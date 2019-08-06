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
#include "key_io.h"

CReserveOutput::CReserveOutput(const UniValue &obj)
{
    uint32_t flags = uni_get_int(find_value(obj, "flags"));
    int32_t nValue = uni_get_int(find_value(obj, "value"));
}

UniValue CReserveOutput::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("flags", (int32_t)flags));
    ret.push_back(Pair("value", (int64_t)nValue));
    return ret;
}

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

CCoinbaseCurrencyState::CCoinbaseCurrencyState(const CTransaction &tx)
{
    bool currencyStateFound = false;
    for (auto out : tx.vout)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(out.scriptPubKey, p))
        {
            if (p.evalCode == EVAL_CURRENCYSTATE)
            {
                if (currencyStateFound)
                {
                    flags &= !VALID;        // invalidate
                }
                else
                {
                    FromVector(p.vData[0], *this);
                    currencyStateFound = true;
                }
            }
        }
    }
}

CCoinbaseCurrencyState::CCoinbaseCurrencyState(const UniValue &obj) : CCurrencyState(obj)
{
    ReserveIn = uni_get_int64(find_value(obj, "reservein"));
    NativeIn = uni_get_int64(find_value(obj, "nativein"));
    ReserveOut = CReserveOutput(find_value(obj, "reserveout"));
    ConversionPrice = uni_get_int64(find_value(obj, "conversionprice"));
    Fees = uni_get_int64(find_value(obj, "fees"));
}

UniValue CCoinbaseCurrencyState::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret = ((CCurrencyState *)this)->ToUniValue();
    ret.push_back(Pair("reservein", (int64_t)ReserveIn));
    ret.push_back(Pair("nativein", (int64_t)NativeIn));
    ret.push_back(Pair("reserveout", ReserveOut.ToUniValue()));
    ret.push_back(Pair("conversionprice", (int64_t)ConversionPrice));
    ret.push_back(Pair("fees", (int64_t)Fees));
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
        cpp_dec_float_50 price = GetPriceInReserve();
        int64_t intPrice;
        if (!to_int64(price, intPrice))
        {
            return 0;
        }
        else
        {
            return intPrice;
        }
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

void CReserveTransactionDescriptor::AddReserveExchange(const CReserveExchange &rex, int32_t outputIndex, int32_t nHeight)
{
    CAmount fee;

    bool wasMarket = IsMarket();

    flags |= IS_RESERVE + IS_RESERVEEXCHANGE;

    if (IsLimit() || rex.flags & CReserveExchange::LIMIT)
    {
        if (wasMarket || (vRex.size() && (vRex.back().second.flags != rex.flags || (vRex.back().second.nValidBefore != rex.nValidBefore))))
        {
            flags |= IS_REJECT;
            return;
        }

        flags |= IS_LIMIT;

        if (rex.nValidBefore > nHeight)
        {
            flags |= IS_FILLORKILL;
            // fill or kill fee must be pre-subtracted, but is added back on success, making conversion the only
            // requred fee on success
            fee = CalculateConversionFee(rex.nValue + rex.FILL_OR_KILL_FEE);
            if (rex.flags & CReserveExchange::TO_RESERVE)
            {
                numSells += 1;
                nativeConversionFees += fee;
                nativeOutConverted += (rex.nValue + rex.FILL_OR_KILL_FEE) - fee;    // only explicitly converted
                nativeOut += (rex.nValue + rex.FILL_OR_KILL_FEE) - fee;             // output is always less fees
            }
            else
            {
                numBuys += 1;
                reserveConversionFees += fee;
                reserveOutConverted += rex.nValue + rex.FILL_OR_KILL_FEE - fee;
                reserveOut += (rex.nValue + rex.FILL_OR_KILL_FEE) - fee;
            }
        }
        else
        {
            flags &= !IS_RESERVEEXCHANGE;                       // no longer a reserve exchange transaction, falls back to normal reserve tx
            flags |= IS_FILLORKILLFAIL;

            if (rex.flags & CReserveExchange::TO_RESERVE)
            {
                numSells += 1;
                nativeOut += rex.nValue;
            }
            else
            {
                numBuys += 1;
                reserveOut += rex.nValue;
            }
        }
    }
    else
    {
        fee = CalculateConversionFee(rex.nValue);
        if (rex.flags & CReserveExchange::TO_RESERVE)
        {
            numSells += 1;
            nativeConversionFees += fee;
            nativeOutConverted += rex.nValue - fee;     // fee will not be converted from native, so is not included in converted out
            nativeOut += rex.nValue - fee;              // fee is not considered part of the total native out, since it will go to miner
        }
        else
        {
            numBuys += 1;
            reserveConversionFees += fee;
            reserveOutConverted += rex.nValue;
            reserveOut += rex.nValue - fee;
        }
    }                        
    vRex.push_back(std::make_pair(outputIndex, rex));
}

CAmount CReserveTransactionDescriptor::AllFeesAsNative(const CCurrencyState &currencyState) const
{
    return NativeFees() + currencyState.ReserveToNative(ReserveFees());
}

CAmount CReserveTransactionDescriptor::AllFeesAsNative(const CCurrencyState &currencyState, CAmount exchangeRate) const
{
    return NativeFees() + currencyState.ReserveToNative(ReserveFees(), exchangeRate);
}

CAmount CReserveTransactionDescriptor::AllFeesAsReserve(const CCurrencyState &currencyState) const
{
    return currencyState.NativeToReserve(NativeFees()) + ReserveFees();
}

/*
 * Checks all structural aspects of the reserve part of a transaction that may have reserve inputs and/or outputs
 */
CReserveTransactionDescriptor::CReserveTransactionDescriptor(const CTransaction &tx, CCoinsViewCache &view, int32_t nHeight)
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
        return;
    }

    for (int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut &txOut = tx.vout[i];
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
                            flags |= IS_REJECT;
                            return;
                        }
                        AddReserveOutput(ro);
                    }
                    break;

                case EVAL_RESERVE_TRANSFER:
                    {
                        CReserveTransfer rt;
                        if (!p.vData.size() && !(rt = CReserveTransfer(p.vData[0])).IsValid())
                        {
                            flags |= IS_REJECT;
                            return;
                        }
                        // on a PBaaS reserve chain, a reserve transfer is always denominated in reserve, as exchange must happen before it is
                        // created. explicit fees in transfer object are for export and import, not initial mining
                        AddReserveTransfer(rt);
                    }
                    break;

                case EVAL_RESERVE_EXCHANGE:
                    {
                        CReserveExchange rex;
                        if (!p.vData.size() && !(rex = CReserveExchange(p.vData[0])).IsValid())
                        {
                            flags |= IS_REJECT;
                            return;
                        }

                        // if we send the output to the reserve chain, it must be a TO_RESERVE transaction
                        if (!(rex.flags & rex.TO_RESERVE) && rex.flags & rex.SEND_OUTPUT)
                        {
                            flags |= IS_REJECT;
                            return;
                        }

                        AddReserveExchange(rex, i, nHeight);

                        if (IsReject())
                        {
                            return;
                        }
                    }
                    break;

                // this check will need to be made complete by preventing mixing both here and where the others
                // are seen
                case EVAL_RESERVE_DEPOSIT:
                case EVAL_CROSSCHAIN_EXPORT:
                case EVAL_CROSSCHAIN_IMPORT:
                    {
                        // the following outputs are incompatible with reserve exchange tranactions
                        if (IsReserveExchange())
                        {
                            flags |= IS_REJECT;
                            return;
                        }
                        return;
                    }
                    break;
                
                default:
                    {
                        nativeOut += txOut.nValue;
                    }
            }
        }
    }

    // we have all inputs, outputs, and fees, if check inputs, we can check all for consistency
    // inputs may be in the memory pool or on the blockchain

    // no inputs are valid at height 0
    if (!nHeight)
    {
        flags |= IS_REJECT;
        return;
    }

    // if we don't have a reserve transaction, we're done
    // don't try to replace basic transaction validation
    if (IsReserve())
    {
        int64_t interest;
        CAmount nValueIn = 0;
        {
            LOCK2(cs_main, mempool.cs);

            int64_t interest;           // unused for now
            // if it is a conversion to reserve, the amount in is accurate, since it is from the native coin, if converting to
            // the native PBaaS coin, the amount input is a sum of all the reserve token values of all of the inputs
            nativeIn = view.GetValueIn(nHeight, &interest, tx);
            nativeIn += tx.GetShieldedValueIn();

            reserveIn = view.GetReserveValueIn(nHeight, tx);
        }

        CAmount minReserveFee;
        CAmount minNativeFee;

        if (IsReserveExchange())
        {
            minReserveFee = reserveConversionFees;

            minNativeFee = nativeConversionFees;
        }
        else
        {
            minReserveFee = CReserveExchange::FILL_OR_KILL_FEE * numBuys;
            minNativeFee = CReserveExchange::FILL_OR_KILL_FEE * numSells;
        }

        // we have total inputs, outputs and fee calculations, ensure that
        // everything balances and fees are covered in all cases
        CAmount reserveFeesAvailable;
        CAmount nativeFeesAvailable;

        if (ReserveFees() < minReserveFee || NativeFees() < minNativeFee)
        {
            // not enough fees
            flags |= IS_REJECT;
            return;
        }
        flags |= IS_VALID;
        ptx = &tx;
    }
}

CMutableTransaction &CReserveTransactionDescriptor::AddConversionInOuts(CMutableTransaction &conversionTx, CAmount exchangeRate, CCurrencyState *pCurrencyState) const
{
    if (!IsReserveExchange() || IsFillOrKillFail())
    {
        return conversionTx;
    }

    CCurrencyState dummy;
    CCurrencyState &currencyState = pCurrencyState ? *pCurrencyState : dummy;
    // if no exchange rate is specified, first from the currency if present, then it is unity
    if (!exchangeRate)
    {
        int64_t price;
        if (pCurrencyState && currencyState.to_int64(pCurrencyState->GetPriceInReserve(), price) && price != 0)
        {
            exchangeRate = price;
        }
        else
        {
            exchangeRate = CReserveExchange::SATOSHIDEN;
        }
    }

    CAmount feesLeft = nativeConversionFees + currencyState.ReserveToNative(reserveConversionFees, exchangeRate);

    uint256 txHash = ptx->GetHash();

    for (auto &indexRex : vRex)
    {
        COptCCParams p;
        ptx->vout[indexRex.first].scriptPubKey.IsPayToCryptoCondition(p);

        CCcontract_info CC;
        CCcontract_info *cp;

        CAmount fee = CalculateConversionFee(indexRex.second.nValue);
        if (fee > feesLeft)
        {
            fee = feesLeft;
        }
        feesLeft -= fee;

        CAmount amount = indexRex.second.nValue - fee;

        // add input
        conversionTx.vin.push_back(CTxIn(txHash, indexRex.first, CScript()));

        // if we should emit a reserve transfer or normal reserve output
        if (indexRex.second.flags && indexRex.second.SEND_OUTPUT)
        {
            assert(indexRex.second.flags & indexRex.second.TO_RESERVE);
            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);

            // convert amount to reserve from native
            amount = currencyState.NativeToReserve(amount, exchangeRate);

            CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

            // send the entire amount to a reserve transfer output of the specific chain
            std::vector<CTxDestination> dests = std::vector<CTxDestination>({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_RESERVE_TRANSFER)), 
                                                                                CKeyID(ConnectedChains.NotaryChain().GetChainID())});

            // create the transfer output with the converted amount less fees
            CReserveTransfer rt(CReserveTransfer::VALID, amount, CReserveTransfer::DEFAULT_PER_STEP_FEE << 1, GetDestinationID(p.vKeys[0]));

            conversionTx.vout.push_back(MakeCC1of1Vout(EVAL_RESERVE_TRANSFER, 0, pk, dests, rt));
        }
        else if (indexRex.second.flags & indexRex.second.TO_RESERVE)
        {
            // convert amount to reserve from native
            amount = currencyState.NativeToReserve(amount, exchangeRate);

            // send the net amount to the indicated destination
            std::vector<CTxDestination> dests = std::vector<CTxDestination>({p.vKeys[0]});

            // create the output with the unconverted amount less fees
            CReserveOutput ro(CReserveOutput::VALID, amount);

            conversionTx.vout.push_back(MakeCC0of0Vout(EVAL_RESERVE_OUTPUT, 0, dests, ro));
        }
        else
        {
            // convert amount to native from reserve and send as normal output
            amount = currencyState.ReserveToNative(amount, exchangeRate);
            conversionTx.vout.push_back(CTxOut(amount, GetScriptForDestination(p.vKeys[0])));
        }
    }
    return conversionTx;
}

// From a vector of transaction pointers, match all that are valid orders and can be matched,
// put them into a vector of reserve transaction descriptors, and return a new fractional reserve state,
// if pConversionTx is present, this will add one output to it for each transaction included
// and consider its size wen comparing to maxSerializeSize
CCoinbaseCurrencyState CCoinbaseCurrencyState::MatchOrders(const std::vector<const CTransaction *> &orders, 
                                                            std::vector<CReserveTransactionDescriptor> &reserveFills, 
                                                            std::vector<const CTransaction *> &expiredFillOrKills, 
                                                            std::vector<const CTransaction *> &noFills, 
                                                            std::vector<const CTransaction *> &rejects, 
                                                            CAmount &price, int32_t height, int64_t maxSerializeSize, 
                                                            int64_t *pInOutTotalSerializeSize, CMutableTransaction *pConversionTx) const
{
    // synthetic order book of limitBuys and limitSells sorted by limit, order of preference beyond limit sorting is random
    std::multimap<CAmount, CReserveTransactionDescriptor> limitBuys;
    std::multimap<CAmount, CReserveTransactionDescriptor> limitSells;        // limit orders are prioritized by limit
    std::multimap<CAmount, CReserveTransactionDescriptor> marketOrders;      // prioritized by fee rate

    int64_t totalSerializedSize = pInOutTotalSerializeSize ? *pInOutTotalSerializeSize + CCurrencyState::CONVERSION_TX_SIZE_MIN : CCurrencyState::CONVERSION_TX_SIZE_MIN;
    int64_t conversionSizeOverhead = 0;

    if (!(flags & ISRESERVE))
    {
        return CCoinbaseCurrencyState();
    }

    uint32_t tipTime = (chainActive.Height() >= height) ? chainActive[height]->nTime : chainActive.LastTip()->nTime;
    CCoinsViewCache view(pcoinsTip);

    // organize all valid reserve exchange transactions into 3 multimaps, limitBuys, limitSells, and market orders
    // orders that should be treated as normal will go into refunds and invalid transactions into rejects
    for (int i = 0; i < orders.size(); i++)
    {
        CReserveTransactionDescriptor txDesc(*orders[i], view, height);

        if (txDesc.IsValid() && txDesc.IsReserveExchange())
        {
            // if this is a market order, put it in, if limit, put it in an order book, sorted by limit
            if (txDesc.IsMarket())
            {
                CAmount fee = ReserveToNative(txDesc.reserveConversionFees) + txDesc.nativeConversionFees;
                CFeeRate feeRate = CFeeRate(fee, GetSerializeSize(CDataStream(SER_NETWORK, PROTOCOL_VERSION), *txDesc.ptx));
                marketOrders.insert(std::make_pair(feeRate.GetFeePerK(), txDesc));
            }
            else
            {
                assert(txDesc.IsLimit());
                // limit order, so put it in buy or sell
                if (txDesc.numBuys)
                {
                    limitBuys.insert(std::make_pair(txDesc.vRex[0].second.nLimit, txDesc));
                }
                else
                {
                    assert(txDesc.numSells);
                    limitSells.insert(std::make_pair(txDesc.vRex[0].second.nLimit, txDesc));
                }
            }
        }
        else if (txDesc.IsValid())
        {
            expiredFillOrKills.push_back(orders[i]);
        }
        else
        {
            rejects.push_back(orders[i]);
        }
    }

    // now we have all market orders in marketOrders multimap, sorted by feePerK, rejects that are expired or invalid in rejects
    // first, prune as many market orders as possible up to the maximum storage space available for market orders, which we calculate
    // as a functoin of the total space available and precentage of total orders that are market orders
    int64_t numLimitOrders = limitBuys.size() + limitSells.size();
    int64_t numMarketOrders = marketOrders.size();

    // if nothing to do, we are done, don't update anything
    if (!(reserveFills.size() + numLimitOrders + numMarketOrders))
    {
        return *this;
    }

    // 1. start from the current state and calculate what the price would be with market orders
    // 2. add orders, first buys, as many as we can from the highest value and number downward, one at a time, until we run out or
    //    cannot add any more due to not meeting the price. then we do the same for sells if there are any available, and alternate until
    //    we either run out or cannot add from either side. within a specific limit, orders are sorted by largest first, which means
    //    there is no point in retracing if an element fails to be added
    // 3. calculate a final order price.5
    // 4. create and return a new, updated CCoinbaseCurrencyState
    CCoinbaseCurrencyState newState;
    (CCurrencyState)newState = *this;   // leave extended information zeroed for now

    CAmount exchangeRate;

    // the ones that are passed may be any valid reserve related transaction
    // we need to first process those with the assumption that they are included
    for (auto txDesc : reserveFills)
    {
        // add up the starting point for conversions
        if (txDesc.IsReserveExchange())
        {
            // native is only converted as needed, so the amount to convert is already correct irrespective of fees
            newState.ReserveIn += txDesc.reserveOutConverted + txDesc.ReserveFees();
            newState.NativeIn += txDesc.nativeOutConverted;
            if (pConversionTx)
            {
                txDesc.AddConversionInOuts(*pConversionTx);
            }
        }
        else
        {
            // convert all reserve fees to native
            newState.ReserveIn += txDesc.ReserveFees();
        }
    }

    int64_t curSpace = maxSerializeSize - (totalSerializedSize + conversionSizeOverhead);
    int64_t marketOrdersSizeLimit = ((arith_uint256(numMarketOrders) * arith_uint256(curSpace)) / arith_uint256(numLimitOrders + numMarketOrders)).GetLow64();
    int64_t limitOrdersSizeLimit = curSpace - marketOrdersSizeLimit;
    if (limitOrdersSizeLimit < 1024 && maxSerializeSize > 2048)
    {
        marketOrdersSizeLimit = maxSerializeSize - 1024;
        limitOrdersSizeLimit = 1024;
    }

    for (auto marketOrder : marketOrders)
    {
        // add as many as we can fit, if we are able to, consider the output transaction overhead as well
        int64_t thisSerializeSize = GetSerializeSize(*marketOrder.second.ptx, SER_NETWORK, PROTOCOL_VERSION);
        CMutableTransaction mtx;
        if (pConversionTx)
        {
            mtx = *pConversionTx;
            marketOrder.second.AddConversionInOuts(mtx);
            conversionSizeOverhead = GetSerializeSize(mtx, SER_NETWORK, PROTOCOL_VERSION);
        }
        if ((totalSerializedSize + thisSerializeSize + conversionSizeOverhead) <= marketOrdersSizeLimit)
        {
            if (pConversionTx)
            {
                *pConversionTx = mtx;
            }
            newState.NativeIn += marketOrder.second.nativeOutConverted;
            newState.ReserveIn += marketOrder.second.reserveOutConverted + marketOrder.second.ReserveFees();
            reserveFills.push_back(marketOrder.second);
            totalSerializedSize += thisSerializeSize;
        }
        else
        {
            // can't fit, no fill
            noFills.push_back(marketOrder.second.ptx);
        }
    }

    // iteratively add limit orders first buy, then sell, until we no longer have anything to add
    // this must iterate because each time we add a buy, it may put another sell's limit within reach and
    // vice versa
    std::pair<std::multimap<CAmount, CReserveTransactionDescriptor>::iterator, CAmount> buyPartial = make_pair(limitBuys.end(), 0); // valid in loop for partial fill
    std::pair<std::multimap<CAmount, CReserveTransactionDescriptor>::iterator, CAmount> sellPartial = make_pair(limitSells.end(), 0);

    limitOrdersSizeLimit = maxSerializeSize - totalSerializedSize;
    int64_t buyLimitSizeLimit = totalSerializedSize + ((arith_uint256(limitBuys.size()) * arith_uint256(limitOrdersSizeLimit)) / arith_uint256(numLimitOrders)).GetLow64();

    CCurrencyState latestState = newState;

    for (bool tryagain = true; tryagain; )
    {
        tryagain = false;

        exchangeRate = ConvertAmounts(newState.ReserveIn, newState.NativeIn, latestState);

        // starting with that exchange rate, add buys one at a time until we run out of buys to add or reach the limit,
        // possibly in a partial fill, then see if we can add any sells. we go back and forth until we have stopped being able to add
        // new orders. it would be possible to recognize a state where we are able to simultaneously fill a buy and a sell that are
        // the the same or very minimally overlapping limits
        
        for (auto limitBuysIt = limitBuys.rbegin(); limitBuysIt != limitBuys.rend() && exchangeRate > limitBuysIt->second.vRex.front().second.nLimit; limitBuysIt = limitBuys.rend())
        {
            // any time there are entries above the lower bound, we only actually look at the end, since we mutate the
            // search space each iteration and remove anything we've already added, making the end always the most in-the-money
            CReserveTransactionDescriptor &currentBuy = limitBuysIt->second;

            // it must first fit, space-wise
            int64_t thisSerializeSize = GetSerializeSize(*(currentBuy.ptx), SER_NETWORK, PROTOCOL_VERSION);

            CMutableTransaction mtx;
            if (pConversionTx)
            {
                mtx = *pConversionTx;
                currentBuy.AddConversionInOuts(mtx);
                conversionSizeOverhead = GetSerializeSize(mtx, SER_NETWORK, PROTOCOL_VERSION);
            }
            if ((totalSerializedSize + thisSerializeSize + conversionSizeOverhead) <= buyLimitSizeLimit)
            {
                // calculate fresh with all conversions together to see if we still meet the limit
                CAmount newExchange = ConvertAmounts(newState.ReserveIn + currentBuy.reserveOutConverted + currentBuy.ReserveFees(),
                                                     newState.NativeIn, latestState);
                if (newExchange <= currentBuy.vRex[0].second.nLimit)
                {
                    // update conversion transaction if we have one
                    if (pConversionTx)
                    {
                        *pConversionTx = mtx;
                    }

                    // add to the current buys, we will never do something to disqualify this, since all orders left are either
                    // the same limit or lower
                    reserveFills.push_back(currentBuy);
                    totalSerializedSize += thisSerializeSize;

                    newState.ReserveIn += currentBuy.reserveOutConverted + currentBuy.ReserveFees();
                    exchangeRate = newExchange;
                    limitBuys.erase(--limitBuys.end());
                }
                else
                {
                    // TODO: support partial fills
                    break;
                }
            }
        }

        // now, iterate from lowest/most qualified sell limit first to highest/least qualified and attempt to put all in
        // if we can only fill an order partially, then do so
        for (auto limitSellsIt = limitSells.begin(); limitSellsIt != limitSells.end() && exchangeRate > limitSellsIt->second.vRex.front().second.nLimit; limitSellsIt = limitSells.begin())
        {
            CReserveTransactionDescriptor &currentSell = limitSellsIt->second;

            int64_t thisSerializeSize = GetSerializeSize(*currentSell.ptx, SER_NETWORK, PROTOCOL_VERSION);

            CMutableTransaction mtx;
            if (pConversionTx)
            {
                mtx = *pConversionTx;
                currentSell.AddConversionInOuts(mtx);
                conversionSizeOverhead = GetSerializeSize(mtx, SER_NETWORK, PROTOCOL_VERSION);
            }

            if ((totalSerializedSize + thisSerializeSize + conversionSizeOverhead) <= maxSerializeSize)
            {
                // calculate fresh with all conversions together to see if we still meet the limit
                CAmount newExchange = ConvertAmounts(newState.ReserveIn + currentSell.ReserveFees(), newState.NativeIn + currentSell.nativeOutConverted, latestState);
                if (newExchange >= currentSell.vRex.front().second.nLimit)
                {
                    // update conversion transaction if we have one
                    if (pConversionTx)
                    {
                        *pConversionTx = mtx;
                    }

                    // add to the current sells, we will never do something to disqualify this, since all orders left are either
                    // the same limit or higher
                    reserveFills.push_back(currentSell);
                    totalSerializedSize += thisSerializeSize;
                    exchangeRate = newExchange;

                    newState.ReserveIn += currentSell.ReserveFees();
                    newState.NativeIn += currentSell.nativeOutConverted;
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
        buyLimitSizeLimit = maxSerializeSize;
    }

    (CCurrencyState)newState = latestState;
    price = exchangeRate;

    for (auto entry : limitBuys)
    {
        noFills.push_back(entry.second.ptx);
    }

    for (auto entry : limitSells)
    {
        noFills.push_back(entry.second.ptx);
    }

    // if no matches, no state updates
    if (!reserveFills.size())
    {
        return *this;
    }
    else
    {
        if (pInOutTotalSerializeSize)
        {
            *pInOutTotalSerializeSize = totalSerializedSize;
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

CAmount CReserveTransactionDescriptor::CalculateConversionFee(CAmount inputAmount) const
{
    arith_uint256 bigAmount(inputAmount);
    arith_uint256 bigSatoshi(CReserveExchange::SATOSHIDEN);

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

CAmount CCurrencyState::ReserveToNative(CAmount reserveAmount, CAmount exchangeRate)
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
