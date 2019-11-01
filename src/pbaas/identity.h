/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS identity definition,
 * 
 * This is a decentralized identity class that provides the minimum
 * basic function needed to enable persistent DID-similar identities, 
 * needed for signatories, that will eventually bridge compatibly to
 * DID identities.
 * 
 * 
 */

#ifndef IDENTITY_H
#define IDENTITY_H

#include <univalue.h>
#include <sstream>
#include <vector>
#include "streams.h"
#include "pubkey.h"
#include "base58.h"
#include "uint256.h"
#include "key_io.h"
#include "crosschainrpc.h"
#include "zcash/Address.hpp"
#include "script/script.h"
#include "script/standard.h"
#include "primitives/transaction.h"
#include "arith_uint256.h"

class CCommitmentHash
{
public:
    static const CAmount DEFAULT_OUTPUT_AMOUNT = 0;
    static const CAmount POSITIVE_OUTPUT_AMOUNT = 10000;
    uint256 hash;

    CCommitmentHash() {}
    CCommitmentHash(const uint256 &Hash) : hash(Hash) {}

    CCommitmentHash(const UniValue &uni)
    {
        hash = uint256S(uni_get_str(uni));
    }

    CCommitmentHash(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCommitmentHash(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
    }

    UniValue ToUniValue() const
    {
        return UniValue(hash.GetHex());
    }
};

class CNameReservation
{
public:
    static const int MAX_NAME_SIZE = (KOMODO_ASSETCHAIN_MAXLEN - 1);
    std::string name;
    uint256 salt;

    CNameReservation() {}
    CNameReservation(const std::string &Name, const uint256 &Salt) : name(Name.size() > MAX_NAME_SIZE ? std::string(Name.begin(), Name.begin() + MAX_NAME_SIZE) : Name), salt(Salt) {}

    CNameReservation(const UniValue &uni)
    {
        name = uni_get_str(find_value(uni, "name"));
        salt = uint256S(uni_get_str(find_value(uni, "salt")));
    }
    CNameReservation(std::vector<unsigned char> asVector)
    {
        ::FromVector(asVector, *this);
        if (name.size() > MAX_NAME_SIZE)
        {
            name = std::string(name.begin(), name.begin() + MAX_NAME_SIZE);
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(name);
        READWRITE(salt);
    }

    UniValue ToUniValue() const;

    CCommitmentHash GetCommitment()
    {
        return CCommitmentHash(GetHash(*this));
    }

    bool IsValid() const
    {
        return (name != "" && name.size() <= MAX_NAME_SIZE) && !salt.IsNull();
    }
};

// this includes the necessary data for a principal to sign, but does not
// include enough information to derive a persistent identity
class CPrincipal
{
public:
    static const uint8_t VERSION_INVALID = 0;
    static const uint8_t VERSION_CURRENT = 1;
    static const uint8_t VERSION_FIRSTVALID = 1;
    static const uint8_t VERSION_LASTVALID = 1;

    uint32_t nVersion;
    uint32_t flags;

    // signing authority
    std::vector<CTxDestination> primaryAddresses;
    int32_t minSigs;

    CPrincipal() : nVersion(VERSION_INVALID) {}

    CPrincipal(uint32_t Version,
               uint32_t Flags,
               const std::vector<CTxDestination> &primary, 
               int32_t minPrimarySigs) :
               nVersion(Version),
               flags(Flags),
               primaryAddresses(primary),
               minSigs(minPrimarySigs)
        {}

    CPrincipal(const UniValue &uni);
    CPrincipal(std::vector<unsigned char> asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(flags);
        std::vector<std::vector<unsigned char>> addressVs;
        if (ser_action.ForRead())
        {
            READWRITE(addressVs);

            for (auto vec : addressVs)
            {
                if (vec.size() == 20)
                {
                    primaryAddresses.push_back(CTxDestination(CKeyID(uint160(vec))));
                }
                else if (vec.size() == 33)
                {
                    primaryAddresses.push_back(CTxDestination(CPubKey(vec)));
                }
                else
                {
                    primaryAddresses.push_back(CTxDestination(CNoDestination()));
                }
            }
        }
        else
        {
            for (auto dest : primaryAddresses)
            {
                addressVs.push_back(GetDestinationBytes(dest));
            }

            READWRITE(addressVs);
        }
        READWRITE(minSigs);
    }

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return (nVersion >= VERSION_FIRSTVALID && nVersion <= VERSION_LASTVALID);
    }
};

class CIdentity : public CPrincipal
{
public:
    static const uint32_t FLAG_REVOKED = 0x8000;
    static const int64_t MIN_REGISTRATION_AMOUNT = 10000000000;

    uint160 parent;

    // real name or pseudonym, must be unique on the blockchain on which it is defined and can be used
    // as a name for blockchains or other purposes on any chain in the Verus ecosystem once exported to
    // the Verus chain. The hash of this name hashed with the parent if present, must equal the principal ID
    //
    // this name is always normalized to lower case. any identity that is registered
    // on a PBaaS chain may be exported to the Verus chain and referenced by appending
    // a dot ".", followed by the chain name on which this identity was registered.
    // that will eventually create a domain name system as follows:
    // root == VRSC (implicit), so a name that is defined on the Verus chain may be referenced as
    //         just its name.
    //
    // name from another chain == name.chainname
    //      the chainID that would derive from such a name will be Hash(ChainID(chainname) + Hash(name));
    // 
    std::string name;

    // content hashes
    std::vector<uint256> contentHashes;

    // revocation authority - can only invalidate identity or update revocation
    uint160 revocationAuthority;

    // recovery authority - can change primary addresses in case of primary key loss or compromise
    uint160 recoveryAuthority;

    // z-address for contact and privately made attestations that can be proven to others
    libzcash::SaplingPaymentAddress privateAddress;

    CIdentity() : CPrincipal() {}

    CIdentity(uint32_t Version,
              uint32_t Flags,
              const std::vector<CTxDestination> &primary,
              int32_t minPrimarySigs,
              const uint160 &Parent,
              const std::string &Name,
              const std::vector<uint256> &hashes,
              const uint160 &Revocation,
              const uint160 &Recovery,
              const libzcash::SaplingPaymentAddress &Inbox) : 
              CPrincipal(Version, Flags, primary, minPrimarySigs),
              parent(Parent),
              name(Name),
              contentHashes(hashes),
              revocationAuthority(Revocation),
              recoveryAuthority(Recovery),
              privateAddress(Inbox)
    {}

    CIdentity(const UniValue &uni);
    CIdentity(const CTransaction &tx);
    CIdentity(const CScript &scriptPubKey);
    CIdentity(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPrincipal *)this);
        READWRITE(parent);
        READWRITE(name);
        READWRITE(contentHashes);
        READWRITE(revocationAuthority);
        READWRITE(recoveryAuthority);
        READWRITE(privateAddress);
    }

    UniValue ToUniValue() const;

    void Revoke()
    {
        flags |= FLAG_REVOKED;
    }

    void Unrevoke()
    {
        flags &= ~FLAG_REVOKED;
    }

    bool IsRevoked() const
    {
        return flags & FLAG_REVOKED;
    }

    bool IsValidUnrevoked() const
    {
        return IsValid() && !IsRevoked();
    }

    static std::string CleanName(const std::string &Name, uint160 &Parent);
    CIdentityID GetNameID() const;
    CIdentityID GetNameID(const std::string &Name) const;
    static CIdentityID GetNameID(const std::string &Name, const uint160 &parent);

    CIdentity LookupIdentity(const std::string &name, uint32_t height=0, uint32_t *pHeightOut=nullptr, CTxIn *pTxIn=nullptr);
    static CIdentity LookupIdentity(const CIdentityID &nameID, uint32_t height=0, uint32_t *pHeightOut=nullptr, CTxIn *pTxIn=nullptr);

    CIdentity RevocationAuthority() const
    {
        return GetNameID() == revocationAuthority ? *this : LookupIdentity(revocationAuthority);
    }

    CIdentity RecoveryAuthority() const
    {
        return GetNameID() == recoveryAuthority ? *this : LookupIdentity(recoveryAuthority);
    }

    template <typename TOBJ>
    CTxOut TransparentOutput(uint8_t evalcode, CAmount nValue, const TOBJ &obj) const
    {
        CTxOut ret;

        if (IsValidUnrevoked())
        {
            CConditionObj<TOBJ> ccObj = CConditionObj<TOBJ>(evalcode, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetNameID()))}), &obj);
            ret = CTxOut(nValue, MakeMofNCCScript(ccObj));
        }
        return ret;
    }

    template <typename TOBJ>
    CTxOut TransparentOutput(CAmount nValue) const
    {
        CTxOut ret;

        if (IsValidUnrevoked())
        {
            CConditionObj<TOBJ> ccObj = CConditionObj<TOBJ>(0, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetNameID()))}), 1);
            ret = CTxOut(nValue, MakeMofNCCScript(ccObj));
        }
        return ret;
    }

    CScript TransparentOutput() const;
    static CScript TransparentOutput(const CIdentityID &destinationID);

    // creates an output script to control updates to this identity
    CScript IdentityUpdateOutputScript() const;

    inline static CAmount MinRegistrationAmount()
    {
        return MIN_REGISTRATION_AMOUNT;
    }
};

class CIdentityMapKey
{
public:
    // the flags
    static const uint16_t VALID = 1;
    static const uint16_t CAN_SPEND = 0x8000;
    static const uint16_t CAN_SIGN = 0x4000;
    static const uint16_t MANUAL_HOLD = 0x2000; // we were CAN_SIGN in the past, so keep a last state updated after we are removed, keep it updated so its useful when signing related txes
    static const uint16_t BLACKLIST = 0x1000;   // do not track identities that are blacklisted

    // these elements are used as a sort key for the identity map
    // with most significant member first. flags have no effect on sort order, since elements will be unique already
    CIdentityID idID;                           // 20 byte ID
    uint32_t blockHeight;                       // four byte blockheight
    uint32_t blockOrder;                        // 1-based numerical order if in the same block based on first to last spend, 1 otherwise, 0 is invalid except for queries
    uint32_t flags;

    CIdentityMapKey() : blockHeight(0), blockOrder(1), flags(0) {}
    CIdentityMapKey(const CIdentityID &id, uint32_t blkHeight=0, uint32_t orderInBlock=1, uint32_t Flags=0) : idID(id), blockHeight(blkHeight), blockOrder(orderInBlock), flags(Flags) {}

    CIdentityMapKey(const arith_uint256 &mapKey)
    {
        flags = mapKey.GetLow64() & 0xffffffff;
        blockOrder = mapKey.GetLow64() >> 32;
        blockHeight = (mapKey >> 64).GetLow64() & 0xffffffff;
        uint256 keyBytes(ArithToUint256(mapKey));
        idID = CIdentityID(uint160(std::vector<unsigned char>(keyBytes.begin() + 12, keyBytes.end())));
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(idID);
        READWRITE(blockHeight);
        READWRITE(blockOrder);
        READWRITE(flags);
    }

    arith_uint256 MapKey() const
    {
        std::vector<unsigned char> vch(idID.begin(), idID.end());
        vch.insert(vch.end(), 12, 0);
        arith_uint256 retVal = UintToArith256(uint256(vch));
        retVal = (retVal << 32) + blockHeight;
        retVal = (retVal << 32) + blockOrder;
        retVal = (retVal << 32) + flags;
        return retVal;
    }

    // if it actually represents a real identity and not just a key for queries. blockOrder is 1-based
    bool IsValid() const
    {
        return !idID.IsNull() && blockHeight != 0 && flags & VALID && blockOrder >= 1;
    }
};

class CIdentityMapValue : public CIdentity
{
public:
    uint256 txid;

    CIdentityMapValue() : CIdentity() {}
    CIdentityMapValue(const CTransaction &tx) : CIdentity(tx), txid(tx.GetHash()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CIdentity *)this);
        READWRITE(txid);
    }
};

struct CCcontract_info;
struct Eval;

bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool ValidateIdentityRevoke(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool ValidateIdentityRecover(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool ValidateIdentityCommitment(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool ValidateIdentityReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsIdentityInput(const CScript &scriptSig);

#endif // IDENTITY_H
