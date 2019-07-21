/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides reserve currency functions, leveraging the multi-precision boost libraries to calculate reserve currency conversions
 * in a predictable manner that can achieve consensus.
 * 
 */

#ifndef PBAAS_RESERVES_H
#define PBAAS_RESERVES_H

#include <sstream>
#include "pbaas/crosschainrpc.h"
#include <boost/multiprecision/cpp_dec_float.hpp>
#include "librustzcash.h"
#include "pubkey.h"

using boost::multiprecision::cpp_dec_float_50;

// reserve output is a special kind of token output that does not carry it's identifier, as it
// is always assumed to be the reserve currency of the current chain.
class CReserveOutput
{
public:
    static const uint32_t VALID = 1;

    uint32_t flags;
    CAmount nValue;                 // amount of input reserve coins this UTXO represents before any conversion

    CReserveOutput(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveOutput() : flags(0), nValue(0) { }

    CReserveOutput(uint32_t Flags, CAmount value) : flags(Flags), nValue(value) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(flags);
        READWRITE(VARINT(nValue));
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        // we don't support op returns
        return (flags & VALID) && (nValue != 0);
    }
};

class CReserveTransfer : public CReserveOutput
{
public:
    static const uint32_t CONVERT = 2;
    static const uint32_t PRECONVERT = 4;

    static const CAmount DEFAULT_PER_STEP_FEE = 10000; // default fee for each step of each transfer (initial mining, transfer, mining on new chain)

    CAmount nFees;                  // cross-chain network fees only, separated out to enable market conversions, conversion fees are additional
    CKeyID destination;             // transparent address to send funds to on the target chain

    CReserveTransfer(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveTransfer() : CReserveOutput() { }

    CReserveTransfer(uint32_t Flags, CAmount value, CAmount fees, CKeyID dest) : CReserveOutput(Flags, value), nFees(fees), destination(dest) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        ((CReserveOutput *)this)->SerializationOp(s, ser_action);
        READWRITE(VARINT(nFees));
        READWRITE(destination);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return CReserveOutput::IsValid() && nFees > 0 && !destination.IsNull();
    }
};

// convert from $VRSC to fractional reserve coin or vice versa. coinID determines which
// in either direction, this is burned in the block. if burned, the block must contain less than a
// maximum reasonable number of exchange outputs, which must be sorted, hashed, and used to validate
// the outputs that must match exactly on any transaction spending the output. since fees are not
// included in outputs, it is assumed that a miner will spend the output in the same block to recover
// exchange fees
class CReserveExchange : public CReserveOutput
{
public:
    // flags
    static const int32_t TO_RESERVE = 8;        // from fractional currency to reserve, default is reserve to fractional
    static const int32_t LIMIT = 0x10;           // observe the limit when converting
    static const int32_t FILL_OR_KILL = 0x20;    // if not filled before nValidBefore but before expiry, no execution, mined with fee, output pass through
    static const int32_t ALL_OR_NONE = 0x40;     // will not execute partial order
    static const int32_t SEND_OUTPUT = 0x80;     // send the output of this exchange to the target chain, only valid if output is reserve

    // success fee is calculated by multiplying the amount by this number and dividing by satoshis (100,000,000), not less than 10x the absolute SUCCESS_FEE
    // failure fee, meaning the valid before block is past but it is not expired is the difference between input and output and must follow those rules
    // it is deducted in the success case from the success fee, so there is no fee beyond the success fee paid
    static const CAmount SUCCESS_FEE = 5000;
    static const CAmount MIN_SUCCESS_FEE = 50000;
    static const CAmount MIN_PARTIAL = 10000000;        // making partial fill minimum the number at which minimum fee meets standard percent fee,
    static const int INTERPOLATE_ROUNDS = 4;            // we ensure that there is no peverse motive to partially fill in order to increase fees
    static const CAmount FILLORKILL_FEE = 10000;
    static const CAmount SATOSHIDEN = 100000000;

    CAmount nLimit;                         // lowest or highest price to sell or buy coin output, may fail if including this tx in block makes price out of range
    uint32_t nValidBefore;                  // if not filled before this block and not expired, can mine tx, but refund input

    CReserveExchange(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveExchange() : CReserveOutput(), nLimit(0), nValidBefore(0) { }

    CReserveExchange(uint32_t Flags, CAmount amountIn, CAmount Limit=0, uint32_t ValidBefore=0) : 
        CReserveOutput(Flags, amountIn), nLimit(Limit), nValidBefore(ValidBefore) { }

    CReserveExchange(const CTransaction &tx, bool validate=false);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        ((CReserveOutput *)this)->SerializationOp(s, ser_action);
        READWRITE(VARINT(nLimit));
        READWRITE(nValidBefore);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        // this needs an actual check
        return CReserveOutput::IsValid();
    }

    bool IsExpired(int32_t height)
    {
        return height >= nValidBefore;
    }
};

class CCurrencyState
{
public:
    static const uint32_t VALID = 1;
    static const uint32_t ISRESERVE = 2;
    static const int32_t MIN_RESERVE_RATIO = 1000000;
    uint32_t flags;         // currency flags (valid, reserve currency, etc.)
    int32_t InitialRatio;   // starting point reserve percent for initial currency and emission, over SATOSHIs
    CAmount InitialSupply;  // initial supply as premine + pre-converted coins, this is used to establish the value at the initial ratio as well
    CAmount Emitted;        // unlike other supply variations, emitted coins reduce the reserve ratio and are used to calculate current ratio
    CAmount Supply;         // current supply - total of initial and all emitted coins
    CAmount Reserve;        // current reserve controlled by fractional chain - only non-zero for reserve currencies

    CCurrencyState() : flags(0), InitialSupply(0), Emitted(0), Supply(0), Reserve(0) {}

    CCurrencyState(int32_t initialRatio, CAmount supply, CAmount initialSupply, CAmount emitted, CAmount reserve, uint32_t Flags=VALID) : 
        flags(Flags), InitialSupply(initialSupply), Emitted(emitted), Supply(supply), Reserve(reserve)
    {
        if (initialRatio > CReserveExchange::SATOSHIDEN)
        {
            initialRatio = CReserveExchange::SATOSHIDEN;
        }
        else if (initialRatio < MIN_RESERVE_RATIO)
        {
            initialRatio = MIN_RESERVE_RATIO;
        }
        InitialRatio = initialRatio;
    }

    CCurrencyState(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCurrencyState(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(flags);
        READWRITE(VARINT(InitialRatio));
        READWRITE(VARINT(InitialSupply));
        READWRITE(VARINT(Emitted));
        READWRITE(VARINT(Supply));
        READWRITE(VARINT(Reserve));        
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    cpp_dec_float_50 GetReserveRatio() const
    {
        cpp_dec_float_50 initial(InitialRatio);
        if (!(flags & ISRESERVE))
        {
            return initial;
        }
        cpp_dec_float_50 one(1);
        cpp_dec_float_50 ratio(one / ((one + (cpp_dec_float_50(Emitted) / cpp_dec_float_50(InitialSupply))) * cpp_dec_float_50(InitialRatio)));
    }

    inline static bool to_int64(const cpp_dec_float_50 &input, int64_t &outval)
    {
        std::stringstream ss(input.str(0));
        try
        {
            ss >> outval;
            return true;
        }
        catch(const std::exception& e)
        {
            return false;
        }
    }

    // return the current price of the fractional reserve in the reserve currency.
    cpp_dec_float_50 GetPriceInReserve() const
    {
        cpp_dec_float_50 supply(Supply);
        cpp_dec_float_50 reserve(Reserve);
        cpp_dec_float_50 ratio = GetReserveRatio();

        return ratio == 0 || supply == 0 ? cpp_dec_float_50(0) : reserve / (supply * ratio);
    }

    // This can handle multiple aggregated, bidirectional conversions in one block of transactions. To determine the conversion price, it 
    // takes both input amounts of the reserve and the fractional currency to merge the conversion into one calculation
    // with the same price for all transactions in the block. It returns the newly calculated conversion price of the fractional 
    // reserve in the reserve currency.
    CAmount ConvertAmounts(CAmount inputReserve, CAmount inputFractional, CCurrencyState &newState) const;

    CCurrencyState MatchOrders(const std::vector<const CTransaction *> &orders, 
                                        std::vector<const CTransaction *> &matches, 
                                        std::vector<const CTransaction *> &refunds, 
                                        std::vector<const CTransaction *> &nofill, 
                                        std::vector<const CTransaction *> &rejects, 
                                        CAmount &price, int32_t height) const;

    CAmount CalculateConversionFee(CAmount inputAmount, bool convertToNative = false) const;
    CAmount ReserveFeeToNative(CAmount inputAmount, CAmount outputAmount) const;

    CAmount ReserveToNative(CAmount reserveAmount) const;

    CAmount NativeToReserve(CAmount nativeAmount) const
    {
        arith_uint256 bigAmount(nativeAmount);

        int64_t price;
        cpp_dec_float_50 priceInReserve = GetPriceInReserve();
        if (!to_int64(priceInReserve, price))
        {
            assert(false);
        }
        return ((bigAmount * arith_uint256(price)) / arith_uint256(CReserveExchange::SATOSHIDEN)).GetLow64();
    }

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return flags & CReserveOutput::VALID;
    }
};

class CCoinbaseConversionOut : public CCurrencyState
{
public:
    CAmount ReserveIn;      // reserve currency converted to native
    CAmount NativeIn;       // native currency converted to reserve
    CAmount ConversionPrice;// calculated price in reserve for all conversions * 100000000
    CAmount Fees;           // fee values in native coins for all transaction network fees + conversion fees for the block, output must be reward + this value

    CCoinbaseConversionOut() : ReserveIn(0), NativeIn(0), ConversionPrice(0), Fees(0) {}

    CCoinbaseConversionOut(int32_t initialRatio, CAmount supply, CAmount initialSupply, CAmount emitted, CAmount reserve,
                             CAmount reserveIn, CAmount nativeIn, CAmount conversionPrice, CAmount fees) : 
        CCurrencyState(initialRatio, supply, initialSupply, emitted, reserve), ReserveIn(reserveIn), NativeIn(nativeIn), ConversionPrice(conversionPrice), Fees(fees) { }
    CCoinbaseConversionOut(CCurrencyState &currencyState, CAmount reserveIn, CAmount nativeIn, CAmount conversionPrice, CAmount fees) : 
        CCurrencyState(currencyState), ReserveIn(reserveIn), NativeIn(nativeIn), ConversionPrice(conversionPrice), Fees(fees) { }
    CCoinbaseConversionOut(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        ((CCurrencyState *)this)->SerializationOp(s, ser_action);
        READWRITE(VARINT(ReserveIn));
        READWRITE(VARINT(NativeIn));
        READWRITE(VARINT(ConversionPrice));
        READWRITE(VARINT(Fees));
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }
};

#endif // PBAAS_RESERVES_H
