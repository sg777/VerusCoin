/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides reserve currency functions, leveraging the multi-precision boost libraries to calculate reserve currency conversions.
 * 
 */

#include "main.h"
#include "pbaas/pbaas.h"
#include "pbaas/reserves.h"

CReserveExchange::CReserveExchange(const CTransaction &tx, bool validate)
{
    bool orderFound = false;
    for (auto out : tx.vout)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(out.scriptPubKey, p))
        {
            if (p.evalCode == EVAL_RESERVE_EXCHANGE)
            {
                if (orderFound)
                {
                    flags &= !VALID;        // invalidate
                }
                else
                {
                    FromVector(p.vData[0], *this);
                    orderFound = true;
                }
            }
        }
    }

    if (validate)
    {
        
    }
}

CCurrencyState::CCurrencyState(const UniValue &obj)
{
    uint32_t flags = uni_get_int(find_value(obj, "flags"));
    int32_t initialRatio = uni_get_int(find_value(obj, "initialratio"));
    if (initialRatio > CReserveExchange::SATOSHIDEN)
    {
        initialRatio = CReserveExchange::SATOSHIDEN;
    }
    else if (initialRatio < MIN_RESERVE_RATIO)
    {
        initialRatio = MIN_RESERVE_RATIO;
    }
    InitialRatio = initialRatio;

    InitialSupply = uni_get_int64(find_value(obj, "initialsupply"));
    Emitted = uni_get_int64(find_value(obj, "emitted"));
    Supply = uni_get_int64(find_value(obj, "supply"));
    Reserve = uni_get_int64(find_value(obj, "reserve"));
}

UniValue CCurrencyState::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("flags", (int32_t)flags));
    ret.push_back(Pair("initialratio", (int32_t)InitialRatio));
    ret.push_back(Pair("initialsupply", (int64_t)InitialSupply));
    ret.push_back(Pair("emitted", (int64_t)Emitted));
    ret.push_back(Pair("supply", (int64_t)Supply));
    ret.push_back(Pair("reserve", (int64_t)Reserve));
    ret.push_back(Pair("currentratio", GetReserveRatio().convert_to<float>()));
    return ret;
}

// This can handle multiple aggregated, bidirectional conversions in one block of transactions. To determine the conversion price, it 
// takes both input amounts of the reserve and the fractional currency to merge the conversion into one calculation
// with the same price for all transactions in the block. It returns the newly calculated conversion price of the fractional 
// reserve in the reserve currency.
CAmount CCurrencyState::ConvertAmounts(CAmount inputReserve, CAmount inputFractional, CCurrencyState &newState) const
{
    newState = *this;

    // if both conversions are zero, nothing to do but return current price
    if ((!inputReserve && !inputFractional) || !(flags & ISRESERVE))
    {
        return 0;
    }

    cpp_dec_float_50 reservein(inputReserve);
    cpp_dec_float_50 fractionalin(inputFractional);
    cpp_dec_float_50 supply(Supply);
    cpp_dec_float_50 reserve(Reserve);
    cpp_dec_float_50 ratio = GetReserveRatio();

    // first buy if anything to buy
    if (inputReserve)
    {
        supply = supply + (supply * (pow((reservein / reserve + 1.0), ratio) - 1));

        int64_t newSupply;
        if (!to_int64(supply, newSupply))
        {
            assert(false);
        }
        newState.Supply = newSupply;
        newState.Reserve += inputReserve;
        reserve = reserve + reservein;
    }

    // now sell if anything to sell
    if (inputFractional)
    {
        cpp_dec_float_50 reserveout;
        int64_t reserveOut;
        reserveout = reserve * (pow((fractionalin / supply + 1.0), (1 / ratio)) - 1);
        if (!to_int64(reserveout, reserveOut))
        {
            assert(false);
        }

        newState.Supply -= inputFractional;
        newState.Reserve -= reserveOut;
    }

    // determine the change in both supply and reserve and return the execution price in reserve by calculating it from
    // the actual conversion numbers
    return (newState.Supply - Supply) / (newState.Reserve - Reserve);
}

/*
 * Checks all structural aspects of the reserve part of a transaction that may have reserve inputs and/or outputs
 */
bool CCurrencyState::CheckReserveExchangeTransaction(const CTransaction *ptx, 
                                                    CReserveExchangeTransactionDescriptor &desc, 
                                                    int32_t nHeight,
                                                    CCoinsViewCache *pview,
                                                    bool checkInputs) const
{
    // market conversions can have any number of both buy and sell conversion outputs, this is used to make efficient, aggregated
    // reserve transfer operations with conversion

    // limit conversion outputs may have multiple outputs with different input amounts and destinations, 
    // but they must not be mixed in a transaction with any dissimilar set of conditions on the output, 
    // including mixing with market orders, parity of buy or sell, limit value and validbefore values, 
    // or the transaction is considered invalid

    // reserve exchange transactions cannot run on the Verus chain and must have a supported chain on which to execute
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) != CConstVerusSolutionVector::activationHeight.SOLUTION_VERUSV3 ||
        IsVerusActive() ||
        !(ConnectedChains.ThisChain().ChainOptions() & ConnectedChains.ThisChain().OPTION_RESERVE))
    {
        return false;
    }

    desc.isInvalid = true;

    std::vector<CReserveExchange> vRex;
    bool isValid = false;
    bool isLimit = false;
    bool isMarket = false;
    bool isFillOrKillFail = false;
    
    int64_t reserveInTotal = 0;
    int64_t reserveOutConverted = 0;
    int64_t nativeInTotal = 0;
    int64_t nativeOutConverted = 0;
    int64_t nativeConversionFees = 0;       // non-zero only if there is a conversion
    int64_t reserveConversionFees = 0;
    int64_t reserveOutChange = 0;           // total of non-converting outputs
    int64_t nativeOutChange = 0;
    int32_t numBuys = 0;                    // each limit conversion that is valid before a certain block should account for FILL_OR_KILL_FEE
    int32_t numSells = 0;

    for (auto txOut : ptx->vout)
    {
        COptCCParams p;
        if (txOut.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
        {
            switch (p.evalCode)
            {
                case EVAL_RESERVE_OUTPUT:
                    {
                        CReserveOutput ro;
                        if (!p.vData.size() && !(ro = CReserveOutput(p.vData[0])).IsValid())
                        {
                            return false;
                        }
                        // on a PBaaS reserve chain, a reserve transfer is always denominated in reserve, as exchange must happen before it is
                        // created. explicit fees in transfer object are for export and import, not initial mining
                        reserveOutChange += ro.nValue;
                    }
                    break;

                case EVAL_RESERVE_TRANSFER:
                    {
                        CReserveTransfer rt;
                        if (!p.vData.size() && !(rt = CReserveTransfer(p.vData[0])).IsValid())
                        {
                            return false;
                        }
                        // on a PBaaS reserve chain, a reserve transfer is always denominated in reserve, as exchange must happen before it is
                        // created. explicit fees in transfer object are for export and import, not initial mining
                        reserveOutChange += rt.nValue;
                    }
                    break;

                case EVAL_RESERVE_EXCHANGE:
                    {
                        CReserveExchange rex;
                        if (!p.vData.size() && !(rex = CReserveExchange(p.vData[0])).IsValid())
                        {
                            return false;
                        }


                        CAmount fee;
                        
                        if (isLimit || rex.flags & CReserveExchange::LIMIT)
                        {
                            if (isMarket || (vRex.size() && (vRex.back().flags != rex.flags || (vRex.back().nValidBefore != rex.nValidBefore))))
                            {
                                return false;
                            }
                            isLimit = true;

                            if (rex.flags & CReserveExchange::FILL_OR_KILL && rex.nValidBefore > nHeight)
                            {
                                // fill or kill fee must be pre-subtracted, but is added back on success, making conversion the only
                                // requred fee on success
                                fee = CalculateConversionFee(rex.nValue + rex.FILL_OR_KILL_FEE);
                                if (rex.flags & CReserveExchange::TO_RESERVE)
                                {
                                    numSells += 1;
                                    nativeConversionFees += fee;
                                    nativeOutConverted += (rex.nValue + rex.FILL_OR_KILL_FEE) - fee;
                                }
                                else
                                {
                                    numBuys += 1;
                                    reserveConversionFees += fee;
                                    reserveOutConverted += rex.nValue + rex.FILL_OR_KILL_FEE;
                                }
                            }
                            else
                            {
                                isFillOrKillFail = true;
                                if (rex.flags & CReserveExchange::TO_RESERVE)
                                {
                                    numSells += 1;
                                    nativeOutChange += rex.nValue;
                                }
                                else
                                {
                                    numBuys += 1;
                                    reserveOutChange += rex.nValue;
                                }
                            }
                        }
                        else
                        {
                            isMarket = true;
                            fee = CalculateConversionFee(rex.nValue);
                            if (rex.flags & CReserveExchange::TO_RESERVE)
                            {
                                numSells += 1;
                                nativeConversionFees += fee;
                                nativeOutConverted += rex.nValue - fee;
                            }
                            else
                            {
                                numBuys += 1;
                                reserveConversionFees += fee;
                                reserveOutConverted += rex.nValue;
                            }
                        }                        
                        vRex.push_back(rex);
                    }
                    break;

                // the following outputs are incompatible with reserve exchange tranactions
                case EVAL_RESERVE_DEPOSIT:
                case EVAL_CROSSCHAIN_EXPORT:
                case EVAL_CROSSCHAIN_IMPORT:
                    {
                        return false;
                    }
                    break;
                
                default:
                    {
                        nativeOutChange += txOut.nValue;
                    }
            }
        }
    }

    // we have all inputs, outputs, and fees, if check inputs, we can check all for consistency
    // inputs may be in the memory pool or on the blockchain
    if (pview && checkInputs)
    {
        // no inputs are valid at height 0
        if (!nHeight)
        {
            return false;
        }

        int64_t interest;
        CAmount nValueIn = 0;
        {
            LOCK2(cs_main, mempool.cs);

            int64_t interest;           // unused for now
            // if it is a conversion to reserve, the amount in is accurate, since it is from the native coin, if converting to
            // the native PBaaS coin, the amount input is a sum of all the reserve token values of all of the inputs
            nativeInTotal = pview->GetValueIn(nHeight, &interest, *ptx);
            reserveInTotal = pview->GetReserveValueIn(nHeight, *ptx);
        }

        CAmount minReserveFee = CReserveExchange::FILL_OR_KILL_FEE * numBuys;
        CAmount minNativeFee = CReserveExchange::FILL_OR_KILL_FEE * numSells;

        // we have total inputs, outputs and fee calculations, ensure that
        // everything balances and fees are covered in all cases
        CAmount reserveFeesAvailable;
        CAmount nativeFeesAvailable;
        if (isFillOrKillFail || !(reserveOutConverted || nativeOutConverted))
        {
            // we have failed conversions, so we must have at least enough fees available between input and output to cover
            // the minimum FILL_OR_KILL_FEES
            reserveFeesAvailable = reserveInTotal - reserveOutChange;
            nativeFeesAvailable = nativeInTotal - nativeOutChange;
        }
        else
        {
            // make sure that we have the rght amount of conversion fee and also that if it didn't convert, we'd still have enough
            reserveFeesAvailable = reserveInTotal - ((reserveOutConverted + reserveOutChange) - minReserveFee);
            nativeFeesAvailable = nativeInTotal - ((nativeOutConverted + nativeOutChange) - minNativeFee);
        }
        if (numBuys && reserveFeesAvailable < minReserveFee)
        {
            // not enough fees
            return false;
        }
        if (numSells && nativeFeesAvailable < minNativeFee)
        {
            // not enough fees
            return false;
        }
    }

    // TODO fill in desc and return true
}

// From a vector of reserve exchange transactions, match all that can be matched and return a new fractional reserve state,
// a vector of transactions that are all executable, and the price that they executed at only qualified transactions 
// based on their limits and the transaction price will be included.
CCurrencyState CCurrencyState::MatchOrders(const std::vector<const CTransaction *> &orders, 
                                            std::vector<CReserveExchangeTransactionDescriptor> &matches, 
                                            std::vector<const CTransaction *> &refunds, 
                                            std::vector<const CTransaction *> &nofill, 
                                            std::vector<const CTransaction *> &rejects, 
                                            CAmount &price, int32_t height, int64_t maxSerializeSize, 
                                            int64_t *pInOutTotalSerializeSize, CAmount *pInOutTotalFees) const
{
    // synthetic order book of limitBuys and limitSells sorted by limit, order of preference beyond limit sorting is random
    std::multimap<CAmount, CReserveExchangeTransactionDescriptor> limitBuys;
    std::multimap<CAmount, CReserveExchangeTransactionDescriptor> limitSells;        // limit orders are prioritized by limit
    std::multimap<CAmount, CReserveExchangeTransactionDescriptor> marketOrders;      // prioritized by fee rate
    CAmount marketBuy = 0;
    CAmount marketSell = 0;

    int64_t totalSerializedSize = pInOutTotalSerializeSize ? *pInOutTotalSerializeSize + CCurrencyState::CONVERSION_TX_SIZE_MIN : CCurrencyState::CONVERSION_TX_SIZE_MIN;
    int64_t totalNativeFees = 0;
    int64_t totalReserveFees = 0;

    if (!(flags & ISRESERVE))
    {
        return CCurrencyState();
    }

    uint32_t tipTime = (chainActive.Height() >= height) ? chainActive[height]->nTime : chainActive.LastTip()->nTime;
    CCoinsViewCache view(pcoinsTip);

    // organize all valid reserve exchange transactions into 3 multimaps, limitBuys, limitSells, and market orders
    // orders that should be treated as normal will go into refunds and invalid transactions into rejects
    for (int i = 0; i < orders.size(); i++)
    {
        CReserveExchangeTransactionDescriptor orderParams;
        orderParams.ptx = orders[i];

        if (CheckReserveExchangeTransaction(orderParams.ptx, orderParams, height, &view, true) && orderParams.IsReserveExchange() && !orderParams.IsFillOrKillFail() && orderParams.IsValid())
        {
            // if this is a market order, put it in, if limit, put it in an order book, sorted by limit
            if (orderParams.IsMarket())
            {
                CAmount fee = ReserveToNative(orderParams.reserveConversionFees) + orderParams.nativeConversionFees;
                CFeeRate feeRate = CFeeRate(fee, GetSerializeSize(CDataStream(SER_NETWORK, PROTOCOL_VERSION), *orderParams.ptx));
                marketOrders.insert(std::make_pair(feeRate.GetFeePerK(), orderParams));
            }
            else
            {
                assert(orderParams.IsLimit());
                // limit order, so put it in buy or sell
                if (orderParams.numBuys)
                {
                    limitBuys.insert(std::make_pair(orderParams.vRex[0].second.nLimit, orderParams));
                }
                else
                {
                    assert(orderParams.numSells);
                    limitSells.insert(std::make_pair(orderParams.vRex[0].second.nLimit, orderParams));
                }
            }
        }
        else if (orderParams.IsValid())
        {
            refunds.push_back(orders[i]);
        }
        else
        {
            rejects.push_back(orders[i]);
        }
    }

    // now we have all market orders in marketOrders multimap, sorted by feeperk, rejects that are expired or invalid in rejects
    // first, prune as many market orders as possible up to the maximum storage space available for market orders, which we calculate
    // as a functoin of the total space available and precentage of total orders that are market orders
    int64_t numLimitOrders = limitBuys.size() + limitSells.size();
    int64_t numMarketOrders = marketOrders.size();

    // if nothing to do, we are done, don't update anything
    if (!(numLimitOrders + numMarketOrders))
    {
        return *this;
    }

    int64_t marketOrdersSizeLimit = ((arith_uint256(numMarketOrders) * arith_uint256(maxSerializeSize)) / arith_uint256(numLimitOrders + numMarketOrders)).GetLow64();
    int64_t limitOrdersSizeLimit = maxSerializeSize - marketOrdersSizeLimit;
    if (limitOrdersSizeLimit < 1024 && maxSerializeSize > 2048)
    {
        marketOrdersSizeLimit = maxSerializeSize - 1024;
        limitOrdersSizeLimit = 1024;
    }

    CDataStream sizeStream(SER_NETWORK, PROTOCOL_VERSION);

    for (auto marketOrder : marketOrders)
    {
        // add as many as we can fit
        int64_t thisSerializeSize = GetSerializeSize(sizeStream, *marketOrder.second.ptx);
        if (totalSerializedSize + thisSerializeSize <= marketOrdersSizeLimit)
        {
            if (marketOrder.second.numSells)
            {
                // total amount of native currency out that must be converted
                marketSell += marketOrder.second.nativeOutConverted;
            }
            if (marketOrder.second.numBuys)
            {
                // convert the total input to fractional, fee is subtracted after
                marketBuy += marketOrder.second.reserveOutConverted;
            }
            matches.push_back(marketOrder.second);
            totalSerializedSize += thisSerializeSize;
            totalNativeFees += marketOrder.second.nativeConversionFees;
            totalReserveFees += marketOrder.second.reserveConversionFees;
        }
        else
        {
            // can't fit, no fill
            nofill.push_back(marketOrder.second.ptx);
        }
    }

    // 1. start from the current state and calculate what the price would be with market orders
    // 2. add orders, first buys, as many as we can from the highest value and number downward, one at a time, until we run out or
    //    cannot add any more due to not meeting the price. then we do the same for sells if there are any available, and alternate until
    //    we either run out or cannot add from either side. within a specific limit, orders are sorted by largest first, which means
    //    there is no point in retracing if an element fails to be added
    // 3. calculate a final order price.5
    // 4. create and return a new, updated CCurrencyState
    CAmount reserveIn = marketBuy;
    CAmount fractionalIn = marketSell;
    CCurrencyState newState;
    CAmount exchangeRate;

    // iteratively add limit orders first buy, then sell, until we no longer have anything to add
    // this must iterate because each time we add a buy, it may put another sell's limit within reach and
    // vice versa
    std::pair<std::multimap<CAmount, CReserveExchangeTransactionDescriptor>::iterator, CAmount> buyPartial = make_pair(limitBuys.end(), 0); // valid in loop for partial fill
    std::pair<std::multimap<CAmount, CReserveExchangeTransactionDescriptor>::iterator, CAmount> sellPartial = make_pair(limitSells.end(), 0);

    limitOrdersSizeLimit = maxSerializeSize - totalSerializedSize;
    int64_t buyLimitSizeLimit = totalSerializedSize + ((arith_uint256(limitBuys.size()) * arith_uint256(limitOrdersSizeLimit)) / arith_uint256(numLimitOrders)).GetLow64();

    for (bool tryagain = true; tryagain; )
    {
        tryagain = false;

        exchangeRate = ConvertAmounts(reserveIn, fractionalIn, newState);

        // starting with that exchange rate, add buys one at a time until we run out of buys to add or reach the limit,
        // possibly in a partial fill, then see if we can add any sells. we go back and forth until we have stopped being able to add
        // new orders. it would be possible to recognize a state where we are able to simultaneously fill a buy and a sell that are
        // the the same or very minimally overlapping limits
        
        for (auto limitBuysIt = limitBuys.rbegin(); limitBuysIt != limitBuys.rend() && exchangeRate > limitBuysIt->second.vRex.front().second.nLimit; limitBuysIt = limitBuys.rend())
        {
            // any time there are entries above the lower bound, we only actually look at the end, since we mutate the
            // search space each iteration and remove anything we've already added, making the end always the most in-the-money
            CCurrencyState rState;

            CReserveExchangeTransactionDescriptor &currentBuy = limitBuysIt->second;

            // it must first fit, space-wise
            int64_t thisSerializeSize = GetSerializeSize(sizeStream, *(currentBuy.ptx));
            if (totalSerializedSize + thisSerializeSize <= buyLimitSizeLimit)
            {
                // calculate fresh with all conversions together to see if we still meet the limit
                CAmount newExchange = ConvertAmounts(reserveIn + currentBuy.reserveOutConverted, fractionalIn, rState);
                if (newExchange <= currentBuy.vRex[0].second.nLimit)
                {
                    // add to the current buys, we will never do something to disqualify this, since all orders left are either
                    // the same limit or lower
                    matches.push_back(currentBuy);
                    totalReserveFees += currentBuy.reserveConversionFees;
                    totalSerializedSize += thisSerializeSize;

                    reserveIn += currentBuy.reserveOutConverted;
                    newState = rState;
                    exchangeRate = newExchange;
                    limitBuys.erase(--limitBuys.end());
                }
                else
                {
                    break;
                    /*
                    // get ratio of how much above the current exchange price we were on the limit and how much over we are
                    // use that ratio as a linear interpolation of the input amount to hit that limit and try again for a partial fill. if we can't fill
                    // the minimum, give up on this order. if we can, record a partial
                    cpp_dec_float_50 distanceTarget(limitBuysIt->second.nLimit - exchangeRate);
                    cpp_dec_float_50 actualDistance(newExchange - exchangeRate);
                    int64_t partialAttempt;
                    for (int j = 0; j < CReserveExchange::INTERPOLATE_ROUNDS; j++)
                    {
                        if (to_int64((distanceTarget / actualDistance) * cpp_dec_float_50(currentBuy.nInputValue), partialAttempt) && 
                            partialAttempt >= CReserveExchange::MIN_PARTIAL)
                        {
                            // TODO: check limit and if still out of bounds, iterate, otherwise, make a partial fill
                            // initially, fail partials
                        }
                    }

                    // we must be done with buys whether we created a partial or not
                    break;
                    */
                }
            }
        }

        // now, iterate from lowest/most qualified sell limit first to highest/least qualified and attempt to put all in
        // if we can only fill an order partially, then do so
        for (auto limitSellsIt = limitSells.begin(); limitSellsIt != limitSells.end() && exchangeRate > limitSellsIt->second.vRex.front().second.nLimit; limitSellsIt = limitSells.begin())
        {
            CCurrencyState rState;
            CReserveExchangeTransactionDescriptor &currentSell = limitSellsIt->second;

            int64_t thisSerializeSize = GetSerializeSize(sizeStream, *currentSell.ptx);
            if (totalSerializedSize + thisSerializeSize <= maxSerializeSize)
            {
                // calculate fresh with all conversions together to see if we still meet the limit
                CAmount newExchange = ConvertAmounts(reserveIn, fractionalIn + currentSell.nativeOutConverted, rState);
                if (newExchange >= currentSell.vRex.front().second.nLimit)
                {
                    // add to the current sells, we will never do something to disqualify this, since all orders left are either
                    // the same limit or higher
                    matches.push_back(currentSell);
                    totalNativeFees += currentSell.nativeConversionFees;
                    totalSerializedSize += thisSerializeSize;

                    fractionalIn += currentSell.nativeOutConverted;
                    newState = rState;
                    limitSells.erase(limitSellsIt);
                    tryagain = true;
                }
                else
                {
                    // we must be done with buys whether we created a partial or not
                    break;
                }
            }
        }
    }

    for (auto entry : limitBuys)
    {
        nofill.push_back(entry.second.ptx);
    }

    for (auto entry : limitSells)
    {
        nofill.push_back(entry.second.ptx);
    }

    // if no matches, no state updates
    if (!matches.size())
    {
        return *this;
    }
    else
    {
        if (pInOutTotalSerializeSize)
        {
            *pInOutTotalSerializeSize = totalSerializedSize;
        }
        if (pInOutTotalFees)
        {
            *pInOutTotalFees = totalNativeFees + ReserveToNative(totalReserveFees, exchangeRate);
        }
        return newState;
    }
}

CAmount CCurrencyState::CalculateConversionFee(CAmount inputAmount, bool convertToNative) const
{
    arith_uint256 bigAmount(inputAmount);
    arith_uint256 bigSatoshi(CReserveExchange::SATOSHIDEN);

    // we need to calculate a fee based either on the amount to convert or the last price
    // times the reserve
    if (convertToNative)
    {
        int64_t price;
        cpp_dec_float_50 priceInReserve = GetPriceInReserve();
        if (!to_int64(priceInReserve, price))
        {
            assert(false);
        }
        bigAmount = price ? (bigAmount * bigSatoshi) / arith_uint256(price) : 0;
    }

    CAmount fee = 0;
    fee = ((bigAmount * arith_uint256(CReserveExchange::SUCCESS_FEE)) / bigSatoshi).GetLow64();
    if (fee < CReserveExchange::MIN_SUCCESS_FEE)
    {
        fee = CReserveExchange::MIN_SUCCESS_FEE;
    }
    return fee;
}

CAmount CCurrencyState::ReserveToNative(CAmount reserveAmount) const
{
    arith_uint256 bigAmount(reserveAmount);

    int64_t price;
    cpp_dec_float_50 priceInReserve = GetPriceInReserve();
    if (!to_int64(priceInReserve, price))
    {
        assert(false);
    }
    bigAmount = price ? (bigAmount * arith_uint256(CReserveExchange::SATOSHIDEN)) / arith_uint256(price) : 0;

    return bigAmount.GetLow64();
}

CAmount CCurrencyState::ReserveToNative(CAmount reserveAmount, CAmount exchangeRate) const
{
    arith_uint256 bigAmount(reserveAmount);

    int64_t price;
    cpp_dec_float_50 priceInReserve(exchangeRate);
    if (!to_int64(priceInReserve, price))
    {
        assert(false);
    }
    bigAmount = price ? (bigAmount * arith_uint256(CReserveExchange::SATOSHIDEN)) / arith_uint256(price) : 0;

    return bigAmount.GetLow64();
}

CAmount CCurrencyState::ReserveFeeToNative(CAmount inputAmount, CAmount outputAmount) const
{
    return ReserveToNative(inputAmount - outputAmount);
}
