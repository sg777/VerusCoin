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

struct CReserveExchangeData
{
    const CTransaction *ptx;
    uint32_t flags;
    CAmount nLimit;
    CAmount nInputValue;
};

// From a vector of reserve exchange transactions, match all that can be matched and return a new fractional reserve state,
// a vector of transactions that are all executable, and the price that they executed at only qualified transactions 
// based on their limits and the transaction price will be included.
CCurrencyState CCurrencyState::MatchOrders(const std::vector<const CTransaction *> &orders, 
                                            std::vector<const CTransaction *> &matches, 
                                            std::vector<const CTransaction *> &refunds, 
                                            std::vector<const CTransaction *> &nofill, 
                                            std::vector<const CTransaction *> &rejects, 
                                            CAmount &price, int32_t height) const
{
    // synthetic order book of limitBuys and limitSells sorted by limit, order of preference beyond limit sorting is random
    std::multimap<CAmount, CReserveExchangeData> limitBuys;
    std::multimap<CAmount, CReserveExchangeData> limitSells;
    std::vector<int> ret;
    CAmount marketBuy = 0;
    CAmount marketSell = 0;

    if (!(flags & ISRESERVE))
    {
        return CCurrencyState();
    }

    uint32_t tipTime = (chainActive.Height() >= height) ? chainActive[height]->nTime : chainActive.LastTip()->nTime;

    for (int i = 0; i < orders.size(); i++)
    {
        CReserveExchange orderParams(*(orders[i]));
        if (orderParams.IsValid() && !orderParams.IsExpired(height))
        {
            // if this is a market order, put it in, if limit, put it in an order book, sorted by limit
            // get input value
            CCoinsViewCache coins(pcoinsTip);
            int64_t interest;           // unused for now

            // if it is a conversion to reserve, the amount in is accurate, since it is from the native coin, if converting to
            // the native PBaaS coin, the amount input is a sum of all the reserve token values of all of the inputs
            CReserveExchangeData rxd = {orders[i], orderParams.flags, orderParams.nLimit, 
                                        orderParams.flags & CReserveExchange::TO_RESERVE ? coins.GetValueIn(height, &interest, *(orders[i]), tipTime) :
                                                                                           coins.GetReserveValueIn(height, *(orders[i]))};

            if (!(rxd.flags & CReserveExchange::TO_RESERVE))
            {
                if (rxd.flags & CReserveExchange::LIMIT)
                {
                    // this is a limit buy, and we add orders from highest limit and move downwards
                    limitBuys.insert(std::make_pair(rxd.nLimit, rxd));
                }
                else
                {
                    // convert the total input to fractional, fee is calculated after
                    marketBuy += rxd.nInputValue;
                    matches.push_back(orders[i]);
                }
            }
            else
            {
                if (rxd.flags & CReserveExchange::LIMIT)
                {
                    // limit sell, we add orders from the lowest limit and move upwards
                    limitSells.insert(std::make_pair(rxd.nLimit, rxd));
                }
                else
                {
                    // calculate fee and subtract, it won't be converted
                    CAmount adjustedInput = 
                        rxd.nInputValue - 
                        ((arith_uint256(rxd.nInputValue) * arith_uint256(CReserveExchange::SUCCESS_FEE)) / arith_uint256(CReserveExchange::SATOSHIDEN)).GetLow64();
                    marketSell += adjustedInput;
                    matches.push_back(orders[i]);
                }
            }
        }
        else
        {
            if (orderParams.IsValid())
            {
                refunds.push_back(orders[i]);
            }
            else
            {
                rejects.push_back(orders[i]);
            }
        }
    }

    // now we have all market orders in matches vector, rejects that are expired or invalid in rejects, and market order input totals calculated
    // 1. start from the current state and calculate what the price would be with market orders
    // 2. add orders, first buys, as many as we can from the highest value and number downward, one at a time, until we run out or
    //    cannot add any more due to not meeting the price. then we do the same for sells if there are any available, and alternate until
    //    we either run out or cannot add from either side. within a specific limit, orders are sorted by largest first, which means
    //    there is no point in retracing if an element fails to be added
    // 3. calculate a final order price.5
    // 4. create and return a new, updated CCurrencyState
    CAmount reserveIn = marketBuy;
    CAmount fractionalIn = marketSell;
    CCurrencyState newState(*this);

    // iteratively add limit orders first buy, then sell, until we no longer have anything to add
    // this must iterate because each time we add a buy, it may put another sell's limit within reach and
    // vice versa
    std::pair<std::multimap<CAmount, CReserveExchangeData>::iterator, CAmount> buyPartial = make_pair(limitBuys.end(), 0); // valid in loop for partial fill
    std::pair<std::multimap<CAmount, CReserveExchangeData>::iterator, CAmount> sellPartial = make_pair(limitSells.end(), 0);
    for (bool tryagain = true; tryagain; )
    {
        tryagain = false;

        CAmount exchangeRate = ConvertAmounts(reserveIn, fractionalIn, newState);

        // starting with that exchange rate, add buys one at a time until we run out of buys to add or reach the limit,
        // possibly in a partial fill, then see if we can add any sells. we go back and forth until we have stopped being able to add
        // new orders. it would be possible to recognize a state where we are able to simultaneously fill a buy and a sell that are
        // the the same or very minimally overlapping limits
        
        for (auto limitBuysIt = limitBuys.lower_bound(exchangeRate); limitBuysIt != limitBuys.end(); limitBuysIt = limitBuys.lower_bound(exchangeRate))
        {
            // any time there are entries above the lower bound, we only actually look at the end, since we mutate the
            // multimap and remove anything we've already added
            CCurrencyState rState;

            // the last is most qualified
            auto it = limitBuys.end();
            CReserveExchangeData &currentBuy = (--it)->second;

            // calculate fresh with all conversions together to see if we still meet the limit
            CAmount newExchange = ConvertAmounts(reserveIn + currentBuy.nInputValue, fractionalIn, rState);
            if (newExchange <= currentBuy.nLimit)
            {
                // add to the current buys, we will never do something to disqualify this, since all orders left are either
                // the same limit or lower
                matches.push_back(currentBuy.ptx);
                reserveIn += currentBuy.nInputValue;
                newState = rState;
                exchangeRate = newExchange;
                limitBuys.erase(it);
            }
            else
            {
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
            }
        }

        // now, iterate from lowest/most qualified sell limit first to highest/least qualified and attempt to put all in
        // if we can only fill an order partially, then do so
        for (auto limitSellsIt = limitSells.begin(); limitSellsIt != limitBuys.end() && exchangeRate > limitSellsIt->second.nLimit; limitSellsIt = limitSells.begin())
        {
            CCurrencyState rState;
            CReserveExchangeData &currentSell = limitSellsIt->second;

            // calculate fresh with all conversions together to see if we still meet the limit
            CAmount newExchange = ConvertAmounts(reserveIn, fractionalIn + currentSell.nInputValue, rState);
            if (newExchange >= currentSell.nLimit)
            {
                // add to the current sells, we will never do something to disqualify this, since all orders left are either
                // the same limit or higher
                matches.push_back(currentSell.ptx);
                fractionalIn += currentSell.nInputValue;
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

    for (auto entry : limitBuys)
    {
        nofill.push_back(entry.second.ptx);
    }

    for (auto entry : limitSells)
    {
        nofill.push_back(entry.second.ptx);
    }

    return newState;
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

CAmount CCurrencyState::ReserveFeeToNative(CAmount inputAmount, CAmount outputAmount) const
{
    return ReserveToNative(inputAmount - outputAmount);
}
