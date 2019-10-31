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
#include "pbaas/identity.h"

#include "boost/algorithm/string.hpp"
#include "script/standard.h"
#include "script/cc.h"
#include "cc/CCinclude.h"
#include "pbaas/pbaas.h"

extern CTxMemPool mempool;

CCommitmentHash::CCommitmentHash(const CTransaction &tx)
{
    for (auto txOut : tx.vout)
    {
        COptCCParams p;
        if (txOut.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
        {
            ::FromVector(p.vData[0], *this);
            break;
        }
    }
}

UniValue CNameReservation::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("name", name));
    ret.push_back(Pair("salt", salt.GetHex()));
    if (IsVerusActive())
    {
        ret.push_back(Pair("parent", ""));
        ret.push_back(Pair("nameid", EncodeDestination(CTxDestination(CIdentity::GetNameID(name, uint160())))));
    }
    else
    {
        ret.push_back(Pair("parent", ConnectedChains.ThisChain().name));
        ret.push_back(Pair("nameid", EncodeDestination(CTxDestination(CIdentity::GetNameID(name + "." + ConnectedChains.ThisChain().name, uint160())))));
    }
    return ret;
}

CPrincipal::CPrincipal(const UniValue &uni)
{
    nVersion = uni_get_int(find_value(uni, "version"));
    if (nVersion == VERSION_INVALID)
    {
        nVersion = VERSION_CURRENT;
    }
    flags = uni_get_int(find_value(uni, "flags"));
    UniValue primaryAddressesUni = find_value(uni, "primaryaddresses");
    if (primaryAddressesUni.isArray())
    {
        for (int i = 0; i < primaryAddressesUni.size(); i++)
        {
            try
            {
                CTxDestination dest = DecodeDestination(uni_get_str(primaryAddressesUni[i]));
                if (dest.which() == COptCCParams::ADDRTYPE_PK || dest.which() == COptCCParams::ADDRTYPE_PKH)
                {
                    primaryAddresses.push_back(dest);
                }
            }
            catch (const std::exception &e)
            {
                printf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                LogPrintf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                nVersion = VERSION_INVALID;
            }
        }
    }

    minSigs = uni_get_int(find_value(uni, "minimumsignatures"));
}

UniValue CPrincipal::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("flags", (int32_t)flags));

    UniValue primaryAddressesUni(UniValue::VARR);
    for (int i = 0; i < primaryAddresses.size(); i++)
    {
        primaryAddressesUni.push_back(EncodeDestination(primaryAddresses[i]));
    }
    obj.push_back(Pair("primaryaddresses", primaryAddressesUni));
    obj.push_back(Pair("minimumsignatures", minSigs));
    return obj;
}

CIdentity::CIdentity(const UniValue &uni) : CPrincipal(uni)
{
    parent = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "parent")))));
    name = CleanName(uni_get_str(find_value(uni, "name")), parent);

    UniValue hashesUni = find_value(uni, "contenthashes");
    if (hashesUni.isArray())
    {
        for (int i = 0; i < hashesUni.size(); i++)
        {
            try
            {
                contentHashes.push_back(uint256S(uni_get_str(hashesUni[i])));
                if (contentHashes.back().IsNull())
                {
                    contentHashes.pop_back();
                }
            }
            catch (const std::exception &e)
            {
                printf("%s: hash is not valid %s\n", __func__, hashesUni[i].write().c_str());
                LogPrintf("%s: hash is not valid %s\n", __func__, hashesUni[i].write().c_str());
                nVersion = VERSION_INVALID;
            }
        }
    }
    std::string revocationStr = uni_get_str(find_value(uni, "revocationauthorityid"));
    std::string recoveryStr = uni_get_str(find_value(uni, "recoveryauthorityid"));
    uint160 nameID = GetNameID();
    revocationAuthority = revocationStr == "" ? nameID : uint160(GetDestinationID(DecodeDestination(revocationStr)));
    recoveryAuthority = recoveryStr == "" ? nameID : uint160(GetDestinationID(DecodeDestination(recoveryStr)));
    libzcash::PaymentAddress pa = DecodePaymentAddress(uni_get_str(find_value(uni, "privateaddress")));

    if (revocationAuthority.IsNull() || recoveryAuthority.IsNull() || boost::get<libzcash::SaplingPaymentAddress>(&pa) == nullptr)
    {
        printf("%s: invalid address\n", __func__);
        LogPrintf("%s: invalid address\n", __func__);
        nVersion = VERSION_INVALID;
    }
    else
    {
        privateAddress = *boost::get<libzcash::SaplingPaymentAddress>(&pa);
    }
}

CIdentity::CIdentity(const CScript &scriptPubKey)
{
    COptCCParams p;
    if (IsPayToCryptoCondition(scriptPubKey, p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size())
    {
        FromVector(p.vData[0], *this);
    }
}

UniValue CIdentity::ToUniValue() const
{
    UniValue obj = ((CPrincipal *)this)->ToUniValue();

    obj.push_back(Pair("identityaddress", EncodeDestination(CIdentityID(GetNameID()))));
    obj.push_back(Pair("parent", parent.GetHex()));
    obj.push_back(Pair("name", name));

    UniValue hashes(UniValue::VARR);
    for (int i = 0; i < contentHashes.size(); i++)
    {
        hashes.push_back(contentHashes[i].GetHex());
    }
    obj.push_back(Pair("contenthashes", hashes));

    obj.push_back(Pair("revocationauthorityid", EncodeDestination(CTxDestination(CIdentityID(revocationAuthority)))));
    obj.push_back(Pair("recoveryauthorityid", EncodeDestination(CTxDestination(CIdentityID(recoveryAuthority)))));
    obj.push_back(Pair("privateaddress", EncodePaymentAddress(privateAddress)));
    return obj;
}

CIdentity::CIdentity(const CTransaction &tx)
{
    std::set<uint160> ids;
    int idCount;

    nVersion = PBAAS_VERSION_INVALID;
    for (auto out : tx.vout)
    {
        *this = CIdentity(out.scriptPubKey);
        if (IsValid())
        {
            break;
        }
    }
}

CIdentity CIdentity::LookupIdentity(const CIdentityID &nameID, uint32_t height, uint32_t *pHeightOut, CTxIn *pIdTxIn)
{
    CIdentity ret;

    uint32_t heightOut = 0;

    if (!pHeightOut)
    {
        pHeightOut = &heightOut;
    }
    else
    {
        *pHeightOut = 0;
    }

    CTxIn _idTxIn;
    if (!pIdTxIn)
    {
        pIdTxIn = &_idTxIn;
    }
    CTxIn &idTxIn = *pIdTxIn;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK(cs_main);

    CKeyID keyID(CCrossChainRPCData::GetConditionID(nameID, EVAL_IDENTITY_PRIMARY));

    if (GetAddressUnspent(keyID, 1, unspentOutputs))
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); !ret.IsValid() && it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    // check the mempool for spent/modified
                    CSpentIndexKey key(it->first.txhash, it->first.index);
                    CSpentIndexValue value;

                    COptCCParams p;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() && 
                        p.evalCode == EVAL_IDENTITY_PRIMARY && 
                        (ret = CIdentity(coins.vout[it->first.index].scriptPubKey)).IsValid())
                    {
                        if (ret.GetNameID() == nameID)
                        {
                            // to be a confirmed identity, this identity either needs to:
                            // 1. have only one identity output
                            // 2. one of:
                            //   a. spend an identity of the same ID
                            //   b. spend an identity commitment and have an output matching both the identity commitment and identity output
                            // ensuring this to be true is the responsibility of contextual transaction check
                            idTxIn = CTxIn(it->first.txhash, it->first.index);
                            *pHeightOut = it->second.blockHeight;
                        }
                        else
                        {
                            // got an identity masquerading as another, clear it
                            ret = CIdentity();
                        }
                    }
                }
            }
        }

        if (height != 0 && *pHeightOut > height)
        {
            *pHeightOut = 0;

            // if we must check up to a specific height that is less than the latest height, do so
            std::vector<CAddressIndexDbEntry> addressIndex;

            if (GetAddressIndex(keyID, 1, addressIndex, 0, height) && addressIndex.size())
            {
                int txIndex = 0;
                // look from last backward to find the first valid ID
                for (int i = addressIndex.size() - 1; i >= 0; i--)
                {
                    if (addressIndex[i].first.blockHeight < *pHeightOut)
                    {
                        break;
                    }
                    CTransaction idTx;
                    uint256 blkHash;
                    COptCCParams p;
                    LOCK(mempool.cs);
                    if (!addressIndex[i].first.spending &&
                        addressIndex[i].first.txindex > txIndex &&    // always select the latest in a block, if there can be more than one
                        myGetTransaction(addressIndex[i].first.txhash, idTx, blkHash) &&
                        idTx.vout[addressIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() && 
                        p.evalCode == EVAL_IDENTITY_PRIMARY && 
                        (ret = CIdentity(idTx.vout[addressIndex[i].first.index].scriptPubKey)).IsValid())
                    {
                        idTxIn = CTxIn(addressIndex[i].first.txhash, addressIndex[i].first.index);
                        *pHeightOut = addressIndex[i].first.blockHeight;
                        txIndex = addressIndex[i].first.txindex;
                    }
                }
            }
            else
            {
                // not found at that height
                ret = CIdentity();
                idTxIn = CTxIn();
            }
        }
    }
    return ret;
}

CIdentity CIdentity::LookupIdentity(const std::string &name, uint32_t height, uint32_t *pHeightOut, CTxIn *idTxIn)
{
    return LookupIdentity(GetNameID(name), height, pHeightOut, idTxIn);
}

CScript CIdentity::IdentityUpdateOutputScript() const
{
    CScript ret;

    if (!IsValid())
    {
        return ret;
    }

    std::vector<CTxDestination> dests1({CTxDestination(CIdentityID(GetNameID()))});
    CConditionObj<CIdentity> primary(EVAL_IDENTITY_PRIMARY, dests1, 1, this);
    std::vector<CTxDestination> dests2({CTxDestination(CIdentityID(revocationAuthority))});
    CConditionObj<CIdentity> revocation(EVAL_IDENTITY_REVOKE, dests2, 1);
    std::vector<CTxDestination> dests3({CTxDestination(CIdentityID(recoveryAuthority))});
    CConditionObj<CIdentity> recovery(EVAL_IDENTITY_RECOVER, dests3, 1);

    std::vector<CTxDestination> indexDests({CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(GetNameID(), EVAL_IDENTITY_PRIMARY))), CTxDestination(CIdentityID(revocationAuthority)), CTxDestination(CIdentityID(recoveryAuthority))});

    ret = MakeMofNCCScript(1, primary, revocation, recovery, &indexDests);
    return ret;
}

bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // TODO:PBAAS right now, any of the three controlling identities can do any modification
    // ensure that each can only do what it is allowed. the best way to do this would be to change
    // evaluation of crypto conditions to create multi-condition branches in the tree at each
    // threshold condition, enabling evals to be naturally connected to their sub-group of signatures
    return true;
}

bool ValidateIdentityRevoke(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // validate that from the input to the output, the only changes are those allowed by the primary identity
    return true;
}

bool ValidateIdentityRecover(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // validate that from the input to the output, the only changes are those allowed by the primary identity
    return true;
}

bool ValidateIdentityCommitment(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    return true;
}

bool ValidateIdentityReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // validate that spender follows the rules of the role they spent in
    return true;
}

bool IsIdentityInput(const CScript &scriptSig)
{
    return false;
}
