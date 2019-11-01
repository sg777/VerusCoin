// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "keystore.h"

#include "key.h"
#include "util.h"
#include "pbaas/identity.h"
#include "cc/CCinclude.h"
#include "boost/algorithm/string.hpp"

#include <boost/foreach.hpp>

uint160 CCrossChainRPCData::GetConditionID(uint160 cid, int32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(std::string name, int32_t condition)
{
    uint160 cid = GetChainID(name);

    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}
std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut)
{
    std::string nameCopy = Name;
    std::string invalidChars = "\\/:*?\"<>|";
    for (int i = 0; i < nameCopy.size(); i++)
    {
        if (invalidChars.find(nameCopy[i]) != std::string::npos)
        {
            nameCopy[i] = '_';
        }
    }
    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2)
    {
        return std::vector<std::string>();
    }

    bool explicitChain = false;
    if (retNames.size() == 2)
    {
        ChainOut = retNames[1];
        explicitChain = true;
    }    

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    for (int i = 0; i < retNames.size(); i++)
    {
        if (retNames[i].size() > KOMODO_ASSETCHAIN_MAXLEN - 1)
        {
            retNames[i] = std::string(retNames[i], 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));
        }
    }

    // if no chain is specified, default to chain of the ID
    if (!explicitChain && retNames.size())
    {
        if (retNames.size() == 1)
        {
            // by default, we assume the Verus chain for no suffix
            ChainOut = "";
        }
        else
        {
            for (int i = 1; i < retNames.size(); i++)
            {
                if (ChainOut.size())
                {
                    ChainOut = ChainOut + ".";
                }
                ChainOut = ChainOut + retNames[i];
            }
        }
    }

    return retNames;
}

// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CIdentity::CleanName(const std::string &Name, uint160 &Parent)
{
    std::string chainName;
    std::vector<std::string> subNames = ParseSubNames(Name, chainName);

    if (!subNames.size())
    {
        return "";
    }

    for (int i = subNames.size() - 1; i > 0; i--)
    {
        const char *idName = boost::algorithm::to_lower_copy(subNames[i]).c_str();
        uint256 idHash;

        if (Parent.IsNull())
        {
            idHash = Hash(idName, idName + strlen(idName));
        }
        else
        {
            idHash = Hash(idName, idName + strlen(idName));
            idHash = Hash(Parent.begin(), Parent.end(), idHash.begin(), idHash.end());

        }
        Parent = Hash160(idHash.begin(), idHash.end());
    }
    return subNames[0];
}

CIdentityID CIdentity::GetNameID(const std::string &Name, const uint160 &parent)
{
    uint160 newParent = parent;
    std::string cleanName = CleanName(Name, newParent);

    const char *idName = boost::algorithm::to_lower_copy(cleanName).c_str();
    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());

    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetNameID(const std::string &Name) const
{
    uint160 newLevel = parent;
    std::string cleanName = CleanName(Name, newLevel);

    const char *idName = boost::algorithm::to_lower_copy(cleanName).c_str();
    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());

    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetNameID() const
{
    return GetNameID(name);
}

CScript CIdentity::TransparentOutput() const
{
    CConditionObj<CIdentity> ccObj = CConditionObj<CIdentity>(0, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetNameID()))}), 1);
    return MakeMofNCCScript(ccObj);
}

CScript CIdentity::TransparentOutput(const CIdentityID &destinationID)
{
    CConditionObj<CIdentity> ccObj = CConditionObj<CIdentity>(0, std::vector<CTxDestination>({destinationID}), 1);
    return MakeMofNCCScript(ccObj);
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

bool CKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::SetHDSeed(const HDSeed& seed)
{
    LOCK(cs_SpendingKeyStore);
    if (!hdSeed.IsNull()) {
        // Don't allow an existing seed to be changed. We can maybe relax this
        // restriction later once we have worked out the UX implications.
        return false;
    }
    hdSeed = seed;
    return true;
}

bool CBasicKeyStore::HaveHDSeed() const
{
    LOCK(cs_SpendingKeyStore);
    return !hdSeed.IsNull();
}

bool CBasicKeyStore::GetHDSeed(HDSeed& seedOut) const
{
    LOCK(cs_SpendingKeyStore);
    if (hdSeed.IsNull()) {
        return false;
    } else {
        seedOut = hdSeed;
        return true;
    }
}

CScriptID ScriptOrIdentityID(const CScript& scr)
{
    COptCCParams p;
    CIdentity identity;
    if (scr.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() && (identity = CIdentity(p.vData[0])).IsValid())
    {
        return CScriptID(identity.GetNameID());
    }
    else
    {
        return CScriptID(scr);
    }
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[ScriptOrIdentityID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::HaveIdentity(const CIdentityID &idID) const
{
    return mapIdentities.count(CIdentityMapKey(idID).MapKey()) != 0;
}

bool CBasicKeyStore::AddIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    if (mapIdentities.count(mapKey.MapKey()) || !mapKey.IsValid())
    {
        return false;
    }
    mapIdentities.insert(make_pair(mapKey.MapKey(), identity));
    return true;
}

bool CBasicKeyStore::UpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    if (!mapIdentities.count(mapKey.MapKey()) || !mapKey.IsValid())
    {
        return false;
    }
    // erase and insert to replace
    mapIdentities.erase(mapKey.MapKey());
    mapIdentities.insert(make_pair(mapKey.MapKey(), identity));
    return true;
}

bool CBasicKeyStore::AddUpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    arith_uint256 arithKey = mapKey.MapKey();
    return CBasicKeyStore::AddIdentity(mapKey, identity) || CBasicKeyStore::UpdateIdentity(mapKey, identity);
}

bool CBasicKeyStore::RemoveIdentity(const CIdentityMapKey &mapKey, const uint256 &txid)
{
    auto localKey = mapKey;
    if (localKey.idID.IsNull())
    {
        return false;
    }
    auto startIt = mapIdentities.lower_bound(localKey.MapKey());
    if (localKey.blockHeight == 0)
    {
        localKey.blockHeight = 0x7fffffff;
    }

    if (startIt != mapIdentities.end())
    {
        if (txid.IsNull())
        {
            mapIdentities.erase(startIt, mapIdentities.upper_bound(localKey.MapKey()));
        }
        else
        {
            auto endIt = mapIdentities.upper_bound(localKey.MapKey());
            for (; startIt != endIt; startIt++)
            {
                if (startIt->second.txid == txid)
                {
                    mapIdentities.erase(startIt);
                    break;
                }
            }
        }
        
        return true;
    }
    return false;
}

// return the first identity not less than a specific key
bool CBasicKeyStore::GetIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t lteHeight) const
{
    auto itStart = mapIdentities.lower_bound(CIdentityMapKey(idID).MapKey());
    if (itStart == mapIdentities.end())
    {
        return false;
    }
    // point to the last
    CIdentityMapKey endKey(idID, lteHeight);
    auto itEnd = mapIdentities.upper_bound(CIdentityMapKey(idID).MapKey());
    itEnd--;
    keyAndIdentity = make_pair(CIdentityMapKey(itEnd->first), itEnd->second);
    return true;
}

// return all identities matching a specific key and between two block heights
bool CBasicKeyStore::GetIdentity(const CIdentityMapKey &keyStart, const CIdentityMapKey &keyEnd, std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> &keysAndIdentityUpdates) const
{
    auto itStart = mapIdentities.lower_bound(keyStart.MapKey());
    if (itStart == mapIdentities.end())
    {
        return false;
    }
    auto itEnd = mapIdentities.upper_bound(keyEnd.MapKey());
    for (; itStart != mapIdentities.end() && itStart != itEnd; itStart++)
    {
        keysAndIdentityUpdates.push_back(make_pair(CIdentityMapKey(itStart->first), itStart->second));
    }
    return true;
}

bool CBasicKeyStore::GetIdentity(const CIdentityMapKey &mapKey, const uint256 &txid, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity)
{
    CIdentityMapKey localKey = mapKey;
    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> toCheck;
    bool found = false;

    if (localKey.blockHeight == 0)
    {
        localKey.blockHeight = 0x7fffffff;
    }
    if (!GetIdentity(mapKey, localKey, toCheck))
    {
        return found;
    }

    for (auto id : toCheck)
    {
        if (id.second.txid == txid)
        {
            keyAndIdentity = id;
            found = true;
        }
    }
    return found;
}

// return the first identity not less than a specific key
bool CBasicKeyStore::GetFirstIdentity(const CIdentityID &idID, std::pair<CIdentityMapKey, CIdentityMapValue> &keyAndIdentity, uint32_t gteHeight) const
{
    auto it = mapIdentities.lower_bound(CIdentityMapKey(idID).MapKey());
    if (it == mapIdentities.end())
    {
        return false;
    }
    keyAndIdentity = make_pair(CIdentityMapKey(it->first), it->second);
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CBasicKeyStore::AddSproutSpendingKey(const libzcash::SproutSpendingKey &sk)
{
    LOCK(cs_SpendingKeyStore);
    auto address = sk.address();
    mapSproutSpendingKeys[address] = sk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(sk.receiving_key())));
    return true;
}

//! Sapling 
bool CBasicKeyStore::AddSaplingSpendingKey(
    const libzcash::SaplingExtendedSpendingKey &sk,
    const libzcash::SaplingPaymentAddress &defaultAddr)
{
    LOCK(cs_SpendingKeyStore);
    auto fvk = sk.expsk.full_viewing_key();

    // if SaplingFullViewingKey is not in SaplingFullViewingKeyMap, add it
    if (!AddSaplingFullViewingKey(fvk, defaultAddr)) {
        return false;
    }

    mapSaplingSpendingKeys[fvk] = sk;

    return true;
}

bool CBasicKeyStore::AddSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_SpendingKeyStore);
    auto address = vk.address();
    mapSproutViewingKeys[address] = vk;
    mapNoteDecryptors.insert(std::make_pair(address, ZCNoteDecryption(vk.sk_enc)));
    return true;
}

bool CBasicKeyStore::AddSaplingFullViewingKey(
    const libzcash::SaplingFullViewingKey &fvk,
    const libzcash::SaplingPaymentAddress &defaultAddr)
{
    LOCK(cs_SpendingKeyStore);
    auto ivk = fvk.in_viewing_key();
    mapSaplingFullViewingKeys[ivk] = fvk;

    return CBasicKeyStore::AddSaplingIncomingViewingKey(ivk, defaultAddr);
}

// This function updates the wallet's internal address->ivk map. 
// If we add an address that is already in the map, the map will
// remain unchanged as each address only has one ivk.
bool CBasicKeyStore::AddSaplingIncomingViewingKey(
    const libzcash::SaplingIncomingViewingKey &ivk,
    const libzcash::SaplingPaymentAddress &addr)
{
    LOCK(cs_SpendingKeyStore);

    // Add addr -> SaplingIncomingViewing to SaplingIncomingViewingKeyMap
    mapSaplingIncomingViewingKeys[addr] = ivk;

    return true;
}

bool CBasicKeyStore::RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    LOCK(cs_SpendingKeyStore);
    mapSproutViewingKeys.erase(vk.address());
    return true;
}

bool CBasicKeyStore::HaveSproutViewingKey(const libzcash::SproutPaymentAddress &address) const
{
    LOCK(cs_SpendingKeyStore);
    return mapSproutViewingKeys.count(address) > 0;
}

bool CBasicKeyStore::HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk) const
{
    LOCK(cs_SpendingKeyStore);
    return mapSaplingFullViewingKeys.count(ivk) > 0;
}

bool CBasicKeyStore::HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr) const
{
    LOCK(cs_SpendingKeyStore);
    return mapSaplingIncomingViewingKeys.count(addr) > 0;
}

bool CBasicKeyStore::GetSproutViewingKey(
    const libzcash::SproutPaymentAddress &address,
    libzcash::SproutViewingKey &vkOut) const
{
    LOCK(cs_SpendingKeyStore);
    SproutViewingKeyMap::const_iterator mi = mapSproutViewingKeys.find(address);
    if (mi != mapSproutViewingKeys.end()) {
        vkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey &ivk,
                                   libzcash::SaplingFullViewingKey &fvkOut) const
{
    LOCK(cs_SpendingKeyStore);
    SaplingFullViewingKeyMap::const_iterator mi = mapSaplingFullViewingKeys.find(ivk);
    if (mi != mapSaplingFullViewingKeys.end()) {
        fvkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress &addr,
                                   libzcash::SaplingIncomingViewingKey &ivkOut) const
{
    LOCK(cs_SpendingKeyStore);
    SaplingIncomingViewingKeyMap::const_iterator mi = mapSaplingIncomingViewingKeys.find(addr);
    if (mi != mapSaplingIncomingViewingKeys.end()) {
        ivkOut = mi->second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::GetSaplingExtendedSpendingKey(const libzcash::SaplingPaymentAddress &addr, 
                                    libzcash::SaplingExtendedSpendingKey &extskOut) const {
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingFullViewingKey fvk;

    return GetSaplingIncomingViewingKey(addr, ivk) &&
            GetSaplingFullViewingKey(ivk, fvk) &&
            GetSaplingSpendingKey(fvk, extskOut);
}
