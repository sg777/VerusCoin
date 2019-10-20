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
#include "boost/algorithm/string.hpp"
#include "script/standard.h"
#include "pbaas/identity.h"
#include "script/cc.h"
#include "cc/CCinclude.h"
#include "pbaas/pbaas.h"

extern CTxMemPool mempool;

CPrincipal::CPrincipal(const UniValue &uni)
{
    nVersion = uni_get_int(find_value(uni, "version"));
    flags = uni_get_int(find_value(uni, "flags"));
    UniValue primaryAddressesUni = find_value(uni, "primaryAddresses");
    if (primaryAddressesUni.isArray())
    {
        for (int i = 0; i < primaryAddressesUni.size(); i++)
        {
            try
            {
                primaryAddresses.push_back(DecodeDestination(uni_get_str(primaryAddressesUni[i])));
            }
            catch (const std::exception &e)
            {
                printf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                LogPrintf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                nVersion = VERSION_INVALID;
            }
        }
    }

    minSigs = uni_get_int(find_value(uni, "minimumtransparent"));
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
    obj.push_back(Pair("primaryAddresses", primaryAddressesUni));
    obj.push_back(Pair("minimumtransparent", minSigs));
    return obj;
}

CIdentity::CIdentity(const UniValue &uni) : CPrincipal(uni)
{
    parent = uint160(GetDestinationID(DecodeDestination(uni_get_str(uni, "parent"))));
    name = CleanName(uni_get_str(find_value(uni, "name")), parent);

    nTime = uni_get_int64(find_value(uni, "time"));

    UniValue hashesUni = find_value(uni, "contenthashes");
    if (hashesUni.isArray())
    {
        for (int i = 0; i < hashesUni.size(); i++)
        {
            try
            {
                contentHashes.push_back(uint256S(uni_get_str(hashesUni[i])));
            }
            catch (const std::exception &e)
            {
                printf("%s: hash is not valid %s\n", __func__, hashesUni[i].write().c_str());
                LogPrintf("%s: hash is not valid %s\n", __func__, hashesUni[i].write().c_str());
                nVersion = VERSION_INVALID;
            }
        }
    }
    revocationAuthority = uint160(GetDestinationID(DecodeDestination(uni_get_str(uni, "revocationauthorityid"))));
    recoveryAuthority = uint160(GetDestinationID(DecodeDestination(uni_get_str(uni, "recoveryauthorityid"))));
    libzcash::PaymentAddress pa = DecodePaymentAddress(uni_get_str(uni, "privateaddress"));

    if (revocationAuthority.IsNull() || recoveryAuthority.IsNull() || boost::get<libzcash::SaplingPaymentAddress>(&pa) == nullptr)
    {
        printf("%s: invalid Sapling address %s\n", __func__, uni_get_str(uni, "privateaddress").c_str());
        LogPrintf("%s: invalid Sapling address %s\n", __func__, uni_get_str(uni, "privateaddress").c_str());
        nVersion = VERSION_INVALID;
    }
    else
    {
        privateAddress = *boost::get<libzcash::SaplingPaymentAddress>(&pa);
    }
}

UniValue CIdentity::ToUniValue() const
{
    UniValue obj = ((CPrincipal *)this)->ToUniValue();

    obj.push_back(Pair("parent", EncodeDestination(CTxDestination(CScriptID(parent)))));
    obj.push_back(Pair("name", name));
    obj.push_back(Pair("time", (int64_t)nTime));

    UniValue hashes(UniValue::VARR);
    for (int i = 0; i < contentHashes.size(); i++)
    {
        hashes.push_back(contentHashes[i].GetHex());
    }
    obj.push_back(Pair("contenthashes", hashes));

    obj.push_back(Pair("revocationauthorityid", EncodeDestination(CTxDestination(CKeyID(revocationAuthority)))));
    obj.push_back(Pair("recoveryauthorityid", EncodeDestination(CTxDestination(CKeyID(recoveryAuthority)))));
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

CIdentity CIdentity::LookupIdentity(const uint160 &nameID, CTxIn *idTxIn)
{
    CIdentity ret;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK2(cs_main, mempool.cs);

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
                    if (mempool.getSpentIndex(key, value))
                    {
                        do
                        {
                            CTransaction tx;
                            if (mempool.lookup(it->first.txhash, tx))
                            {
                                for (int i = 0; !ret.IsValid() && i < tx.vout.size(); i++)
                                {
                                    ret = CIdentity(tx.vout[i].scriptPubKey);
                                    key = CSpentIndexKey(tx.GetHash(), i);
                                }
                            }
                            else
                            {
                                key = CSpentIndexKey(uint256(), -1);
                            }
                        } while (mempool.getSpentIndex(key, value));
                    }
                    else
                    {
                        ret = CIdentity(coins.vout[it->first.index].scriptPubKey);
                        if (idTxIn)
                        {
                            *idTxIn = CTxIn(it->first.txhash, it->first.index);
                        }
                    }
                }
            }
            else
            {
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
            }
        }
    }
    return ret;
}

CIdentity CIdentity::LookupIdentity(const std::string &name, CTxIn *idTxIn)
{
    return LookupIdentity(GetNameID(name), idTxIn);
}

CScript CIdentity::IdentityUpdateOutputScript() const
{
    CScript ret;

    if (!IsValid())
    {
        return ret;
    }

    std::vector<CTxDestination> dests1({CTxDestination(CScriptID(GetNameID()))});
    CConditionObj<CIdentity> primary(EVAL_IDENTITY_PRIMARY, dests1, 1, this);
    std::vector<CTxDestination> dests2({CTxDestination(CScriptID(revocationAuthority))});
    CConditionObj<CIdentity> revocation(EVAL_IDENTITY_REVOKE, dests2, 1);
    std::vector<CTxDestination> dests3({CTxDestination(CScriptID(recoveryAuthority))});
    CConditionObj<CIdentity> recovery(EVAL_IDENTITY_RECOVER, dests3, 1);

    CTxDestination indexDest(CKeyID(CCrossChainRPCData::GetConditionID(GetNameID(), EVAL_IDENTITY_PRIMARY)));
    ret = MakeMofNCCScript(1, primary, revocation, recovery, &indexDest);
    return ret;
}

bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // validate that from the input to the output, the only changes are those allowed by the primary identity
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

bool IsIdentityInput(const CScript &scriptSig)
{
    return false;
}
