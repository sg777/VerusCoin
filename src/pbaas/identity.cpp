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
    ret.push_back(Pair("referral", referral.IsNull() ? "" : EncodeDestination(referral)));

    if (IsVerusActive())
    {
        ret.push_back(Pair("parent", ""));
        ret.push_back(Pair("nameid", EncodeDestination(DecodeDestination(name + "@"))));
    }
    else
    {
        ret.push_back(Pair("parent", ConnectedChains.ThisChain().name));
        ret.push_back(Pair("nameid", EncodeDestination(DecodeDestination(name + "." + ConnectedChains.ThisChain().name + "@"))));
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
    std::string revocationStr = uni_get_str(find_value(uni, "revocationauthority"));
    std::string recoveryStr = uni_get_str(find_value(uni, "recoveryauthority"));

    revocationAuthority = uint160(GetDestinationID(DecodeDestination(revocationStr == "" ? name + "@" : revocationStr)));
    recoveryAuthority = uint160(GetDestinationID(DecodeDestination(recoveryStr == "" ? name + "@" : recoveryStr)));
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
        *this = CIdentity(p.vData[0]);
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

    obj.push_back(Pair("revocationauthority", EncodeDestination(CTxDestination(CIdentityID(revocationAuthority)))));
    obj.push_back(Pair("recoveryauthority", EncodeDestination(CTxDestination(CIdentityID(recoveryAuthority)))));
    obj.push_back(Pair("privateaddress", EncodePaymentAddress(privateAddress)));
    return obj;
}

CIdentity::CIdentity(const CTransaction &tx)
{
    std::set<uint160> ids;
    int idCount;
    bool found = false;

    nVersion = PBAAS_VERSION_INVALID;
    for (auto out : tx.vout)
    {
        CIdentity foundIdentity(out.scriptPubKey);
        if (foundIdentity.IsValid() && !found)
        {
            *this = foundIdentity;
            found = true;
        }
        else if (foundIdentity.IsValid())
        {
            *this = CIdentity();
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
                                if (idTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3 && p.evalCode == EVAL_IDENTITY_PRIMARY)
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
                                idTxIn = CTxIn(it->first.txhash, i);
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
bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height, bool referrals)
{
    // CHECK #1 - there is only one reservation output, and there is also one identity output that matches the reservation.
    //            the identity output must come first and have from 0 to 3 referral outputs between it and the reservation.
    int numReferrers = 0;
    int identityCount = 0;
    int reservationCount = 0;
    CIdentity newIdentity;
    CNameReservation newName;
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
                newIdentity = CIdentity(p.vData[0]);
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newName = CNameReservation(p.vData[0]);
            }
            else if (identityCount && !reservationCount)
            {
                if (!referrals || p.vKeys.size() < 1 || referrers.size() > (CIdentity::REFERRAL_LEVELS - 1) || p.evalCode != 0 || p.n > 1 || txout.nValue < newIdentity.ReferralAmount())
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
    }

    // we can close a commitment UTXO without an identity
    if (valid && !identityCount)
    {
        return state.Error("Transaction may not have an identity reservation without a matching identity");
    }
    else if (!valid)
    {
        return state.Error("Improperly formed identity definition transaction");
    }

    std::vector<CTxDestination> dests;
    int minSigs;
    txnouttype outType;
    if (ExtractDestinations(tx.vout[outNum].scriptPubKey, outType, dests, minSigs))
    {
        uint160 thisID = newIdentity.GetID();
        for (auto &dest : dests)
        {
            uint160 oneDestID;
            if (dest.which() == COptCCParams::ADDRTYPE_ID && (oneDestID = GetDestinationID(dest)) != thisID && !CIdentity::LookupIdentity(CIdentityID(oneDestID)).IsValid())
            {
                return state.Error("Destination includes invalid identity");
            }
        }
    }

    // CHECK #2 - the name is not used on the blockchain or in the mempool
    // lookup name on both blockchain and in mempool. if it is already present in either, then this is not valid
    std::list<CTransaction> conflicts;
    if (mempool.checkNameConflicts(tx, conflicts))
    {
        return state.Error("Invalid identity redefinition");
    }

    // CHECK #3 - must be rooted in this chain
    if (newIdentity.parent != ConnectedChains.ThisChain().GetChainID())
    {
        return state.Error("Identity parent of new identity must be current chain");
    }

    // CHECK #3a - if dupID is valid, we need to be spending it to recover. redefinition is invalid
    CTxIn idTxIn;
    uint32_t priorHeightOut;
    CIdentity dupID = newIdentity.LookupIdentity(newIdentity.GetID(), height, &priorHeightOut, &idTxIn);

    CCoinsViewCache view(pcoinsTip);
    if (dupID.IsValid())
    {
        return state.Error("Identity already exists");
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
                return state.Error("Cannot access input");
            }

            COptCCParams p;
            if (coins.vout[oneTxIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
            {
                ::FromVector(p.vData[0], ch);
                break;
            }
        }

        if (ch.hash.IsNull())
        {
            return state.Error("Invalid identity commitment");
        }

        // are we spending a matching name commitment?
        if (ch.hash != newName.GetCommitment().hash)
        {
            return state.Error("Mismatched identity commitment");
        }

        if (!newName.referral.IsNull() && referrals && !(CIdentity::LookupIdentity(newName.referral, coins.nHeight - 1).IsValid()))
        {
            // invalid referral identity
            return state.Error("Invalid referral identity specified");
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
            return state.Error("Invalid identity registration - insufficient fee");
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
        return state.Error("Invalid identity registration referral");
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
                    return state.Error("Invalid identity registration referral outputs");
                }
                else
                {
                    checkReferrers.push_back(p.vKeys[0]);
                    if (checkReferrers.size() == CIdentity::REFERRAL_LEVELS)
                    {
                        break;
                    }
                }
            }
        }
    }
    if (referrers.size() != checkReferrers.size())
    {
        return state.Error("Invalid identity registration - incorrect referral payments");
    }

    // make sure all paid referrers are correct
    for (int i = 0; i < referrers.size(); i++)
    {
        if (referrers[i] != checkReferrers[i])
        {
            return state.Error("Invalid identity registration - incorrect referral payments");
        }
    }

    // CHECK #6 - ensure that the transaction pays a fee of 80% of the full price for an identity, minus the value of each referral output between identity and reservation
    if (rtxd.NativeFees() < (newIdentity.ReferredRegistrationAmount() - (referrers.size() * newIdentity.ReferralAmount())))
    {
        return state.Error("Invalid identity registration - insufficient fee");
    }

    return true;
}

bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    return PrecheckIdentityReservation(tx, outNum, state, height, ConnectedChains.ThisChain().IDReferrals());
}

// with the thorough check for an identity reservation, the only thing we need to check is that either 1) this transaction includes an identity reservation output or 2)
// this transaction spends a prior identity transaction that does not create a clearly invalid mutation between the two
bool PrecheckIdentityPrimary(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    AssertLockHeld(cs_main);

    bool validReservation = false;
    bool validIdentity = false;

    CNameReservation nameRes;
    CIdentity identity;

    for (auto &output : tx.vout)
    {
        COptCCParams p;
        if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= COptCCParams::VERSION_V3 && p.evalCode == EVAL_IDENTITY_RESERVATION && p.vData.size() > 1 && (nameRes = CNameReservation(p.vData[0])).IsValid())
        {
            // twice through makes it invalid
            if (validReservation)
            {
                return state.Error("Invalid multiple identity reservations on one transaction");
            }
            validReservation = true;
        }
        else if (p.IsValid() && p.version >= COptCCParams::VERSION_V3 && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() > 1 && (identity = CIdentity(p.vData[0])).IsValid())
        {
            // twice through makes it invalid
            if (validIdentity)
            {
                return state.Error("Invalid multiple identity definitions on one transaction");
            }
            validIdentity = true;
        }
    }

    if (!validIdentity)
    {
        return state.Error("Invalid identity definition");
    }

    std::vector<CTxDestination> dests;
    int minSigs;
    txnouttype outType;
    if (ExtractDestinations(tx.vout[outNum].scriptPubKey, outType, dests, minSigs))
    {
        uint160 thisID = identity.GetID();
        for (auto &dest : dests)
        {
            uint160 oneDestID;
            if (dest.which() == COptCCParams::ADDRTYPE_ID && (oneDestID = GetDestinationID(dest)) != thisID && !CIdentity::LookupIdentity(CIdentityID(oneDestID)).IsValid())
            {
                return state.Error("Destination includes invalid identity");
            }
        }
    }

    if (validReservation && nameRes.name == identity.name)
    {
        return true;
    }

    // if we made it to here without an early, positive exit, we must determine that we are spending a matching identity, and if so, all is fine so far
    CTransaction inTx;
    uint256 blkHash;
    COptCCParams p;
    LOCK(mempool.cs);
    for (auto &input : tx.vin)
    {
        if (input.prevout.hash == inTx.GetHash() || myGetTransaction(input.prevout.hash, inTx, blkHash))
        {
            if (inTx.vout[input.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() > 1 && (identity = CIdentity(p.vData[0])).IsValid())
            {
                return true;
            }
        }
    }

    return state.Error("Invalid primary identity - does not include identity reservation or spend matching identity");
}

CIdentity GetOldIdentity(const CTransaction &spendingTx, uint32_t nIn)
{
    // if not fulfilled, ensure that no part of the primary identity is modified
    CIdentity oldIdentity;
    CTransaction sourceTx;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_IDENTITY_PRIMARY && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldIdentity = CIdentity(p.vData[0]);
        }
    }
    return oldIdentity;
}

bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn);
    if (!oldIdentity.IsValid())
    {
        return eval->Error("Spending invalid identity");
    }

    CIdentity newIdentity(spendingTx);
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to define invalid identity");
    }

    if (oldIdentity.IsInvalidMutation(newIdentity))
    {
        return eval->Error("Invalid identity modification");
    }

    if (!fulfilled && !oldIdentity.IsRevoked() && oldIdentity.IsPrimaryMutation(newIdentity))
    {
        return eval->Error("Unauthorized identity modification");
    }
    return true;
}

bool ValidateIdentityRevoke(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn);
    if (!oldIdentity.IsValid())
    {
        return eval->Error("Invalid source identity");
    }

    if (oldIdentity.recoveryAuthority == oldIdentity.GetID())
    {
        return eval->Error("Cannot revoke an identity with self as the recovery authority");
    }

    CIdentity newIdentity(spendingTx);
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to replace identity with one that is invalid");
    }

    if (oldIdentity.IsInvalidMutation(newIdentity))
    {
        return eval->Error("Invalid identity modification");
    }

    if (!fulfilled && (oldIdentity.IsRevocation(newIdentity) || oldIdentity.IsRevocationMutation(newIdentity)))
    {
        return eval->Error("Unauthorized modification of revocation information");
    }

    return true;
}

bool ValidateIdentityRecover(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn);
    if (!oldIdentity.IsValid())
    {
        return eval->Error("Invalid source identity");
    }

    CIdentity newIdentity(spendingTx);
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to replace identity with one that is invalid");
    }

    if (oldIdentity.IsInvalidMutation(newIdentity))
    {
        return eval->Error("Invalid identity modification");
    }

    if (!fulfilled && oldIdentity.IsRevoked() && (oldIdentity.IsPrimaryMutation(newIdentity) || oldIdentity.IsRecovery(newIdentity) || oldIdentity.IsRecoveryMutation(newIdentity)))
    {
        return eval->Error("Unauthorized modification of recovery information");
    }

    return true;
}

bool ValidateIdentityCommitment(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // if not fulfilled, return true so as to allow it to fail if fulfillment matters, but not to veto
    if (!fulfilled)
    {
        return true;
    }

    CCommitmentHash ch;
    CNameReservation reservation;
    CTransaction sourceTx;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_IDENTITY_COMMITMENT && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            ch = CCommitmentHash(p.vData[0]);
        }
        else
        {
            return eval->Error("Invalid source commitment output");
        }

        for (auto output : spendingTx.vout)
        {
            if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_RESERVATION && p.vData.size() > 1)
            {
                if (reservation.IsValid())
                {
                    return eval->Error("Invalid identity reservation output spend");
                }
                else
                {
                    reservation = CNameReservation(p.vData[0]);
                    if (!reservation.IsValid() || reservation.GetCommitment().hash != ch.hash)
                    {
                        return eval->Error("Identity reservation output spend does not match commitment");
                    }
                }
            }
        }
    }
    return true;
}

bool ValidateIdentityReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // identity reservations are unspendable
    return eval->Error("Identity reservations are unspendable");
}

bool IsIdentityInput(const CScript &scriptSig)
{
    return false;
}
