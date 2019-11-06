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
#include "pbaas/reserves.h"
#include "main.h"

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
    if (referral.IsNull())
    {
        ret.push_back(Pair("referredby", ""));
    }
    else
    {
        ret.push_back(Pair("referredby", EncodeDestination(referral)));
    }

    if (IsVerusActive())
    {
        ret.push_back(Pair("parent", ""));
        ret.push_back(Pair("nameid", EncodeDestination(CTxDestination(CIdentity::GetID(name, uint160())))));
    }
    else
    {
        ret.push_back(Pair("parent", ConnectedChains.ThisChain().name));
        ret.push_back(Pair("nameid", EncodeDestination(CTxDestination(CIdentity::GetID(name + "." + ConnectedChains.ThisChain().name, uint160())))));
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
    uint160 nameID = GetID();
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

    obj.push_back(Pair("identityaddress", EncodeDestination(CIdentityID(GetID()))));
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

    if (GetAddressUnspent(keyID, CScript::P2PKH, unspentOutputs))
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
                        if (ret.GetID() == nameID)
                        {
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
    return LookupIdentity(GetID(name), height, pHeightOut, idTxIn);
}

CIdentity CIdentity::LookupFirstIdentity(const CIdentityID &idID, uint32_t *pHeightOut, CTxIn *pIdTxIn, CTransaction *pidTx)
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

    std::vector<CAddressUnspentDbEntry> unspentOutputs;

    LOCK(cs_main);

    CKeyID keyID(CCrossChainRPCData::GetConditionID(idID, EVAL_IDENTITY_RESERVATION));

    if (GetAddressUnspent(keyID, CScript::P2PKH, unspentOutputs))
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); !ret.IsValid() && it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    COptCCParams p;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() && 
                        p.evalCode == EVAL_IDENTITY_RESERVATION)
                    {
                        CTransaction idTx;
                        uint256 blkHash;
                        if (myGetTransaction(it->first.txhash, idTx, blkHash) && (ret = CIdentity(idTx)).IsValid() && ret.GetID() == idID)
                        {
                            int i;
                            for (i = 0; i < idTx.vout.size(); i++)
                            {
                                COptCCParams p;
                                if (idTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
                                {
                                    break;
                                }
                            }

                            if (i < idTx.vout.size())
                            {
                                if (pidTx)
                                {
                                    *pidTx = idTx;
                                }
                                idTxIn = CTxIn(it->first.txhash, it->first.index);
                                *pHeightOut = it->second.blockHeight;
                            }
                        }
                    }
                }
            }
        }
    }
    return ret;
}

// this enables earliest rejection of invalid CC transactions
bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, uint32_t height, bool referrals)
{
    // CHECK #1 - there is only one reservation output, and there is also one identity output that matches the reservation.
    //            the identity output must come first and have from 0 to 3 referral outputs between it and the reservation.
    int numReferrers = 0;
    int identityCount = 0;
    int reservationCount = 0;
    CIdentity newIdentity;
    CNameReservation newName;
    int referralsStart = 0;
    std::vector<CTxDestination> referrers;
    bool valid = true;

    AssertLockHeld(cs_main);

    for (auto &txout : tx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                if (identityCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                referralsStart++;
                newIdentity = CIdentity(p.vData[0]);
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                if (identityCount || reservationCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newName = CNameReservation(p.vData[0]);
            }
            else if (identityCount && !reservationCount)
            {
                if (!referrals || p.vKeys.size() < 1 || referrers.size() > 2 || p.evalCode != 0 || p.n > 1 || txout.nValue < newIdentity.ReferralAmount())
                {
                    valid = false;
                    break;
                }
                referrers.push_back(p.vKeys[0]);
            }
            else if (identityCount != reservationCount)
            {
                valid = false;
                break;
            }
        }
        else
        {
            if (!identityCount)
            {
                referralsStart++;
            }
        }
    }
    if (!identityCount || !valid)
    {
        return false;
    }

    // CHECK #2 - the name is not used on the blockchain or in the mempool
    // lookup name on both blockchain and in mempool. if it is already present in either, then this is not valid
    std::list<CTransaction> conflicts;
    if (mempool.checkNameConflicts(tx, conflicts))
    {
        return false;
    }

    CTxIn idTxIn;
    uint32_t priorHeightOut;
    CIdentity dupID = newIdentity.LookupIdentity(newIdentity.GetID(), height, &priorHeightOut, &idTxIn);
    if (dupID.IsValidUnrevoked())
    {
        return false;
    }

    CCoinsViewCache view(pcoinsTip);

    // CHECK #3a - if dupID is valid (and revoked), we need to be spending it to recover, or we are invalid
    if (dupID.IsValid())
    {
        bool valid = false;
        for (auto &oneTxIn : tx.vin)
        {
            if (oneTxIn.prevout.hash == idTxIn.prevout.hash && oneTxIn.prevout.n == idTxIn.prevout.n)
            {
                valid = true;
                break;
            }
        }
        if (!valid)
        {
            return false;
        }
    }
    // CHECK #3b - if dupID is invalid, we need to spend matching name commitment
    else
    {
        CCommitmentHash ch;
        CCoins coins;

        // from here, we must spend a matching name commitment
        for (auto &oneTxIn : tx.vin)
        {
            if (!view.GetCoins(oneTxIn.prevout.hash, coins))
            {
                return false;   // can't get our input
            }

            COptCCParams p;
            if (coins.vout[oneTxIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
            {
                ::FromVector(p.vData[0], ch);
            }
        }

        if (ch.hash.IsNull())
        {
            return false;
        }

        // are we spending a matching name commitment?
        if (ch.hash != newName.GetCommitment().hash)
        {
            return false;
        }
    }

    CReserveTransactionDescriptor rtxd(tx, view, height);

    // CHECK #4 - if blockchain referrals are not enabled or if there is no referring identity, make sure the fees of this transaction are full price for an identity, 
    // all further checks only if referrals are enabled and there is a referrer
    if (!referrals || newName.referral.IsNull())
    {
        // make sure the fees of this transaction are full price for an identity, all further checks only if there is a referrer
        if (rtxd.NativeFees() < newIdentity.FullRegistrationAmount())
        {
            return false;
        }
        return true;
    }

    // CHECK #5 - ensure that the first referring output goes to the referring identity followed by up 
    //            to two identities that come from the original definition transaction of the referring identity. account for all outputs between
    //            identity out and reservation out and ensure that they are correct and pay 20% of the price of an identity
    uint32_t heightOut = 0;
    CTransaction referralTx;

    CIdentity firstReferralIdentity = CIdentity::LookupFirstIdentity(newName.referral, &heightOut, &idTxIn, &referralTx);
    // referrer must be mined in when this transaction is put into the mem pool
    if (heightOut >= height || !firstReferralIdentity.IsValid())
    {
        return false;
    }

    bool isReferral = false;
    std::vector<CTxDestination> checkReferrers = std::vector<CTxDestination>({newName.referral});
    for (auto &txout : referralTx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                isReferral = true;
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                break;
            }
            else if (isReferral)
            {
                if (p.vKeys.size() == 0 || p.vKeys[0].which() != COptCCParams::ADDRTYPE_ID)
                {
                    // invalid referral
                    return false;
                }
                else
                {
                    checkReferrers.push_back(p.vKeys[0]);
                    if (checkReferrers.size() == 3)
                    {
                        break;
                    }
                }
            }
        }
    }
    if (referrers.size() != checkReferrers.size())
    {
        return false;
    }
    // make sure all paid referrers are correct
    for (int i = 0; i < referrers.size(); i++)
    {
        if (referrers[i] != checkReferrers[i])
        {
            return false;
        }
    }

    // CHECK #6 - ensure that the transaction pays a fee of 80% of the full price for an identity, minus the value of each referral output between identity and reservation
    if (rtxd.NativeFees() < newIdentity.ReferredRegistrationAmount())
    {
        return false;
    }

    return true;
}

bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, uint32_t height)
{
    return PrecheckIdentityReservation(tx, outNum, height, true);
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
