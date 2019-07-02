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

#include "pbaas/pbaas.h"
#include <boost/multiprecision/cpp_dec_float.hpp>

using boost::multiprecision::cpp_dec_float_50;

class CReserveSend
{
public:
    static const uint32_t VALID = 1;            // convert automatically when sending
    static const uint32_t CONVERT = 2;          // convert automatically when sending
    static const uint32_t PRECONVERT = 4;       // considered converted before sending according to before sending

    static const CAmount DEFAULT_PER_STEP_FEE = 10000; // default fee for each step of each transfer (initial mining, transfer, mining on new chain)

    uint32_t flags;     // conversion, etc.
    CAmount nValue;     // nValue for an auto-conversion must include conversion fee and be (desired nValue + (desired nValue * (50000 / 100000000)))
    CAmount nFees;      // network fees only, must be 2x standard network fees for the tx, pays for aggregation and mining payout into other chain

    CReserveSend(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveSend() : flags(0), nValue(0), nFees(0) { }

    CReserveSend(uint32_t Flags, CAmount value, CAmount fees) : flags(Flags), nValue(value), nFees(fees) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(flags);
        READWRITE(VARINT(nValue));
        READWRITE(VARINT(nFees));
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return (flags & VALID) && nValue > 0 && nFees > 0;
    }
};

// an output that carries a primary value of the native coin's reserve, not the native coin itself
// there is no need to pay gas in the native coin because reserve can be used and converted to pay fees
// this uses the destination controls of crypto conditions
class CReserveOutput
{
public:
    CAmount nValue;                         // lowest or highest price to sell or buy coin output, may fail if including this tx in block makes price out of range

    CReserveOutput(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveOutput() : nValue(0) { }

    CReserveOutput(CAmount value) : nValue(value) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nValue));
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        // we don't support op returns
        return nValue != 0;
    }
};

// convert from $VRSC to fractional reserve coin or vice versa. coinID determines which
// in either direction, this is burned in the block. if burned, the block must contain less than a
// maximum reasonable number of exchange outputs, which must be sorted, hashed, and used to validate
// the outputs that must match exactly on any transaction spending the output. since fees are not
// included in outputs, it is assumed that a miner will spend the output in the same block to recover
// exchange fees
class CReserveExchange
{
public:
    static const int32_t VERSION_INVALID = 0;
    static const int32_t VERSION1 = 1;

    // flags
    static const int32_t TO_RESERVE = 1;    // from fractional currency to reserve
    static const int32_t TO_FRACTIONAL = 2; // to fractional currency from reserve
    static const int32_t LIMIT = 4;         // after conversion, send output to the destination recipient on the other chain
    static const int32_t FILL_OR_KILL = 8;  // if not filled before nValidBefore but before expiry, no execution, mined with maxfee, output pass through
    static const int32_t ALL_OR_NONE = 0x10; // will not execute partial order

    // success fee is calculated by multiplying the amount by this number and dividing by satoshis (100,000,000), not less than 10x the absolute SUCCESS_FEE
    // failure fee, meaning the valid before block is past but it is not expired is the standard fee
    static const CAmount SUCCESS_FEE = 5000;
    static const CAmount MIN_PARTIAL = 10000000;        // making partial fill minimum the number at which minimum fee meets standard percent fee,
    static const int INTERPOLATE_ROUNDS = 4;            // we ensures that there is no peverse motive to partially fill in order to increase fees
    static const CAmount FILLORKILL_FEE = 10000;
    static const CAmount SATOSHIDEN = 100000000;

    int32_t version;                        // version of order
    uint32_t flags;                         // control of direction and constraints
    CAmount nLimit;                         // lowest or highest price to sell or buy coin output, may fail if including this tx in block makes price out of range
    uint32_t nValidBefore;                  // if not filled before this block and not expired, can mine tx, but refund input

    CReserveExchange(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveExchange() : version(VERSION_INVALID), flags(0), nLimit(0), nValidBefore(0) { }

    CReserveExchange(uint32_t Flags, CAmount Limit, uint32_t ValidBefore) : 
        version(VERSION1), flags(Flags), nLimit(Limit), nValidBefore(ValidBefore) { }

    CReserveExchange(const CTransaction &tx, bool validate=false);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(flags);
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
        return version == VERSION1;
    }

    bool IsExpired(int32_t height)
    {
        return height >= nValidBefore;
    }
};

bool to_int64(const cpp_dec_float_50 &input, int64_t &outval);

class CFractionalReserveState
{
public:
    static const int32_t MIN_RESERVE_RATIO = 1000000;
    int32_t InitialRatio;   // starting point reserve percent for initial currency and emission, over SATOSHIs
    CAmount InitialSupply;  // starting point for reserve currency, baseline for 100% reserve and used to calculate current reserve
    CAmount Emitted;        // unlike other supply variations, emitted coins reduce the reserve ratio and are used to calculate current ratio
    CAmount Supply;         // current supply
    CAmount Reserve;        // current reserve controlled by fractional chain

    CFractionalReserveState() : InitialSupply(0), Emitted(0), Supply(0), Reserve(0) {}

    CFractionalReserveState(int32_t initialRatio, CAmount supply, CAmount initialSupply, CAmount emitted, CAmount reserve) : 
        InitialSupply(initialSupply), Emitted(emitted), Supply(supply), Reserve(reserve)
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
    CFractionalReserveState(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
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
        cpp_dec_float_50 one(1);
        if (Emitted == 0)
        {
            return one;
        }
        cpp_dec_float_50 ratio(one / ((one + (cpp_dec_float_50(Emitted) / cpp_dec_float_50(InitialSupply))) * cpp_dec_float_50(InitialRatio)));
    }

    // return the current price of the fractional reserve in the reserve currency.
    cpp_dec_float_50 GetPriceInReserve() const
    {
        cpp_dec_float_50 supply(Supply);
        cpp_dec_float_50 reserve(Reserve);
        cpp_dec_float_50 ratio = GetReserveRatio();
        return reserve / (supply * ratio);
    }

    // This can handle multiple aggregated, bidirectional conversions in one block of transactions. To determine the conversion price, it 
    // takes both input amounts of the reserve and the fractional currency to merge the conversion into one calculation
    // with the same price for all transactions in the block. It returns the newly calculated conversion price of the fractional 
    // reserve in the reserve currency.
    CAmount ConvertAmounts(CAmount inputReserve, CAmount inputFractional, CFractionalReserveState &newState) const;

    CFractionalReserveState MatchOrders(const std::vector<CTransaction *> &orders, 
                                        std::vector<CTransaction *> &matches, 
                                        std::vector<CTransaction *> &refunds, 
                                        std::vector<CTransaction *> &nofill, 
                                        std::vector<CTransaction *> &rejects, 
                                        CAmount &price, int32_t height) const;

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return InitialRatio >= MIN_RESERVE_RATIO && InitialRatio <= CReserveExchange::SATOSHIDEN && 
                Supply >= 0 && 
                ((Reserve > 0 && InitialSupply > 0) || (Reserve == 0 && InitialSupply == 0));
    }
};

#endif // PBAAS_RESERVES_H
