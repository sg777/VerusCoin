// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "wallet_ismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "cc/eval.h"
#include "pbaas/identity.h"

#include <boost/foreach.hpp>

using namespace std;

typedef vector<unsigned char> valtype;

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}

isminetype IsMine(const CKeyStore &keystore, const CScript& _scriptPubKey)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKey = _scriptPubKey;

    if (scriptPubKey.IsCheckLockTimeVerify())
    {
        uint8_t pushOp = scriptPubKey[0];
        uint32_t scriptStart = pushOp + 3;

        // continue with post CLTV script
        scriptPubKey = CScript(scriptPubKey.size() > scriptStart ? scriptPubKey.begin() + scriptStart : scriptPubKey.end(), scriptPubKey.end());
    }

    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version == p.VERSION_V3)
    {
        // if version 3 Verus CC, we have everything we need to determine if this is ours
        whichType = TX_CRYPTOCONDITION;
        CIdentity identity;
        if (p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() && (identity = CIdentity(p.vData[0])).IsValid())
        {
            // if this is an identity definition, we may need to add a new
            // script to the wallet or update an existing script
            CScript oldIDScript;
            bool wasMine = false;
            bool wasWatched = false;
            std::set<CKeyID> keySet;

            if (keystore.GetCScript(identity.GetNameID(), oldIDScript)) {
                wasMine = true;
            }
            else
            {
                wasWatched = keystore.HaveWatchOnly(scriptPubKey);
            }

            for (auto key : identity.primaryAddresses)
            {
                CKeyID keyID = CKeyID(GetDestinationID(key));
                if (keystore.HaveKey(keyID))
                {
                    keySet.insert(keyID);
                }
            }

            // if we have enough keys to fully authorize, it is ours
            if (keySet.size() >= p.m)
            {
                return ISMINE_SPENDABLE;
            }
            else if (keySet.size())
            {
                return ISMINE_WATCH_ONLY;
            }
            else
            {
                return wasMine || wasWatched ? ISMINE_WATCH_ONLY : ISMINE_NO;
            }
        }
        else
        {
            CCcontract_info C;
            CKeyID pkID;

            if (CCinit(&C, p.evalCode))
            {
                pkID = CPubKey(ParseHex(C.CChexstr)).GetID();
            }

            // check all destinations, including IDs
            std::set<CTxDestination> keySet;
            bool watchOnly = false;
            for (auto key : p.vKeys)
            {
                if (key.which() == COptCCParams::ADDRTYPE_SH)
                {
                    CScript idScript;
                    CIdentity idp;
                    std::set<CKeyID> ownKeySet;
                    if (keystore.GetCScript(CScriptID(GetDestinationID(key)), idScript) && (idp = CIdentity(idScript)).IsValid() && (idp.GetNameID() == GetDestinationID(key)))
                    {
                        for (auto oneKey : idp.primaryAddresses)
                        {
                            ownKeySet.insert(GetDestinationID(oneKey));
                        }
                        if (ownKeySet.size())
                        {
                            watchOnly = true;
                        }
                        if (ownKeySet.size() >= idp.minSigs)
                        {
                            keySet.insert(key);
                        }
                    }
                }
                else
                {
                    CKeyID keyID = CKeyID(GetDestinationID(key));
                    if (keystore.HaveKey(keyID))
                    {
                        keySet.insert(key);
                    }
                }
            }
            if (keySet.size() >= p.m)
            {
                return ISMINE_SPENDABLE;
            }
            else
            {
                return watchOnly ? ISMINE_WATCH_ONLY : ISMINE_NO;
            }
        }
    }
    else if (!Solver(scriptPubKey, whichType, vSolutions))
    {
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_ONLY;
        return ISMINE_NO;
    }

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_CRYPTOCONDITION:
        {
            // for now, default is that the first value returned will be the target address, subsequent values will be
            // pubkeys. if we have the first in our wallet, we consider it spendable for now
            if (vSolutions[0].size() == 33)
            {
                keyID = CPubKey(vSolutions[0]).GetID();
            }
            else if (vSolutions[0].size() == 20)
            {
                keyID = CKeyID(uint160(vSolutions[0]));
            }
            if (!keyID.IsNull() && keystore.HaveKey(keyID))
            {
                return ISMINE_SPENDABLE;
            }
        }
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;
    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript);
            if (ret == ISMINE_SPENDABLE)
                return ret;
        }
        break;
    }
    case TX_MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (HaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }
    }

    if (keystore.HaveWatchOnly(scriptPubKey))
        return ISMINE_WATCH_ONLY;
    return ISMINE_NO;
}
