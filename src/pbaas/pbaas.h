/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS initialization, notarization, and cross-chain token
 * transactions and enabling liquid or non-liquid tokens across the
 * Verus ecosystem.
 * 
 * 
 */

#ifndef PBAAS_H
#define PBAAS_H

#include <vector>

#include "cc/CCinclude.h"
#include "streams.h"
#include "script/script.h"
#include "amount.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/reserves.h"
#include "mmr.h"

#include <boost/algorithm/string.hpp>

class CPBaaSNotarization;

// these are output cryptoconditions for the Verus reserve liquidity system
// VRSC can be proxied to other PBaaS chains and sent back for use with this system
// The assumption that Verus is either the proxy on the PBaaS chain or the native
// coin on Verus enables us to reduce data requirements systemwide

// this is for transaction outputs with a Verus proxy on a PBaaS chain cryptoconditions with these outputs
// must also be funded with the native chain for fees, unless the chain is a Verus reserve chain, in which
// case the fee will be autoconverted from the Verus proxy through the conversion rules of this chain

// bits for currency controls
// if CURRENCY_FUNGIBLE is set, it can be bought and sold automatically through its reserves, and any issuance
// must be backed by some amount of Verus. issuance can include inflation of supply relative to reserves, but
// a reserve over 100% can be used to ensure that inflation never causes the reserve to drop below 100% if that
// is desired.
// If CURRENCY_RESERVE is set, then it can at least be converted from the currency to Verus in order to
// pay rewards in Verus. If the currency is reserve, but not fractional and not fungible, all rewards will
// be automatically converted to Verus for payout, and if reserves are emptied, the chain will stop running unless
// miners and stakers decide to mine and stake it for free.
// If CURRENCY_FRACTIONAL is set, then at 100% or less, the Bancor math formulas will determine conversion
// rates at each mined block, dependent on how many exchanges in either direction are processed in that
// block. All transactions processed get exactly the same price for both exchange to and echange from in any
// given block.
// if CURRENCY_CONVERTSTAKES is set, even stake rewards are required to be automatically converted to reserves.
//  

static const uint32_t PBAAS_VERSION = 1;
static const uint32_t PBAAS_VERSION_INVALID = 0;
static const uint32_t PBAAS_NODESPERNOTARIZATION = 2;       // number of nodes to reference in each notarization
static const int64_t PBAAS_MINNOTARIZATIONOUTPUT = 10000;   // enough for one fee worth to finalization and notarization thread
static const int32_t PBAAS_MINSTARTBLOCKDELTA = 100;        // minimum number of blocks to wait for starting a chain after definition
static const int32_t PBAAS_MAXPRIORBLOCKS = 16;             // maximum prior block commitments to include in prior blocks chain object

enum CURRENCY_OPTIONS {
    CURRENCY_FUNGIBLE = 1,
    CURRENCY_FRACTIONAL = 2
};

// we wil uncomment service types as they are implemented
// commented service types are here as guidance and reminders
enum PBAAS_SERVICE_TYPES {
    SERVICE_INVALID = 0,
    SERVICE_NOTARIZATION = 1,
    //SERVICE_NODE = 2,
    //SERVICE_ELECTRUM = 3,
    SERVICE_LAST = 1
};

// these are object types that can be stored and recognized in an opret array
enum CHAIN_OBJECT_TYPES
{
    CHAINOBJ_INVALID = 0,
    CHAINOBJ_HEADER = 1,            // serialized full block header
    CHAINOBJ_TRANSACTION = 2,       // serialized transaction, sometimes without an opret, which will be reconstructed
    CHAINOBJ_PROOF = 3,             // merkle proof of preceding block or transaction
    CHAINOBJ_HEADER_REF = 4,        // equivalent to header, but only includes non-canonical data, assuming merge mine reconstruction
    CHAINOBJ_PRIORBLOCKS = 5,       // prior block commitments to ensure recognition of overlapping notarizations
    CHAINOBJ_RESERVETRANSFER = 6,   // serialized transaction, sometimes without an opret, which will be reconstructed
    CHAINOBJ_CROSSCHAINPROOF = 7    // proof that references a notarization
};

// the proof of an opret transaction, which is simply the types of objects and hashes of each
class COpRetProof
{
public:
    uint32_t orIndex;                   // index into the opret objects to begin with
    std::vector<uint8_t>    types;
    std::vector<uint256>    hashes;

    COpRetProof() : orIndex(0), types(0), hashes(0) {}
    COpRetProof(std::vector<uint8_t> &rTypes, std::vector<uint256> &rHashes, uint32_t opretIndex = 0) : types(rTypes), hashes(rHashes), orIndex(opretIndex) {}

    void AddObject(CHAIN_OBJECT_TYPES typeCode, uint256 objHash)
    {
        types.push_back(typeCode);
        hashes.push_back(objHash);
    }

    template <typename CHAINOBJTYPE>
    void AddObject(CHAINOBJTYPE &co, uint256 objHash)
    {
        types.push_back(ObjTypeCode(co));
        hashes.push_back(objHash);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(orIndex);
        READWRITE(types);
        READWRITE(hashes);
    }
};

class CHeaderRef
{
public:
    uint256 hash;               // block hash
    CPBaaSPreHeader preHeader;  // non-canonical pre-header data of source chain

    CHeaderRef() : hash() {}
    CHeaderRef(uint256 &rHash, CPBaaSPreHeader ph) : hash(rHash), preHeader(ph) {}
    CHeaderRef(const CBlockHeader &bh) : hash(bh.GetHash()), preHeader(bh) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(hash);
        READWRITE(preHeader);
    }

    uint256 GetHash() { return hash; }
};

class CPriorBlocksCommitment
{
public:
    std::vector<uint256> priorBlocks;       // prior block commitments, which are node hashes that include merkle root, block hash, and compact power

    CPriorBlocksCommitment() : priorBlocks() {}
    CPriorBlocksCommitment(std::vector<uint256> priors) : priorBlocks(priors) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(priorBlocks);
    }
};

class CCrossChainProof
{
public:
    uint256 notarizationRoot;               // notarization txid used as the root of proof
    CMerkleBranch branch;                   // proof of the transaction on the other chain and import, transaction is stored separately

    CCrossChainProof() {}
    CCrossChainProof(const uint256 &rootTxId, const CMerkleBranch &b) : notarizationRoot(rootTxId), branch(b) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(notarizationRoot);
        READWRITE(branch);
    }

    bool IsValid()
    {
        return !notarizationRoot.IsNull();
    }
};

class CBaseChainObject
{
public:
    uint16_t objectType;                    // type of object, such as blockheader, transaction, proof, tokentx, etc.

    CBaseChainObject() : objectType(CHAINOBJ_INVALID) {}
    CBaseChainObject(uint16_t objType) : objectType(objType) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(objectType);
    }
};

template <typename SERIALIZABLE>
class CChainObject : public CBaseChainObject
{
public:
    SERIALIZABLE object;                    // the actual object

    CChainObject() : CBaseChainObject() {}

    CChainObject(uint16_t objType, const SERIALIZABLE &rObject) : CBaseChainObject(objType)
    {
        object = rObject;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(objectType);
        READWRITE(object);
    }

    uint256 GetHash() const
    {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);

        hw << object;
        return GetHash();
    }
};

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo);

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
template <typename OStream>
CBaseChainObject *RehydrateChainObject(OStream &s)
{
    uint16_t objType;

    s >> objType;

    union {
        CChainObject<CBlockHeader> *pNewHeader;
        CChainObject<CTransaction> *pNewTx;
        CChainObject<CMerkleBranch> *pNewProof;
        CChainObject<CHeaderRef> *pNewHeaderRef;
        CChainObject<CPriorBlocksCommitment> *pPriors;
        CChainObject<CReserveTransfer> *pExport;
        CChainObject<CCrossChainProof> *pCrossChainProof;
        CBaseChainObject *retPtr;
    };

    retPtr = NULL;

    switch(objType)
    {
        case CHAINOBJ_HEADER:
            pNewHeader = new CChainObject<CBlockHeader>();
            if (pNewHeader)
            {
                s >> pNewHeader->object;
                pNewHeader->objectType = objType;
            }
            break;
        case CHAINOBJ_TRANSACTION:
            pNewTx = new CChainObject<CTransaction>();
            if (pNewTx)
            {
                s >> pNewTx->object;
                pNewTx->objectType = objType;
            }
            break;
        case CHAINOBJ_PROOF:
            pNewProof = new CChainObject<CMerkleBranch>();
            if (pNewProof)
            {
                s >> pNewProof->object;
                pNewProof->objectType = objType;
            }
            break;
        case CHAINOBJ_HEADER_REF:
            pNewHeaderRef = new CChainObject<CHeaderRef>();
            if (pNewHeaderRef)
            {
                s >> pNewHeaderRef->object;
                pNewHeaderRef->objectType = objType;
            }
            break;
        case CHAINOBJ_PRIORBLOCKS:
            pPriors = new CChainObject<CPriorBlocksCommitment>();
            if (pPriors)
            {
                s >> pPriors->object;
                pPriors->objectType = objType;
            }
            break;
        case CHAINOBJ_RESERVETRANSFER:
            pExport = new CChainObject<CReserveTransfer>();
            if (pExport)
            {
                s >> pExport->object;
                pExport->objectType = objType;
            }
            break;
        case CHAINOBJ_CROSSCHAINPROOF:
            pCrossChainProof = new CChainObject<CCrossChainProof>();
            if (pCrossChainProof)
            {
                s >> pCrossChainProof->object;
                pCrossChainProof->objectType = objType;
            }
            break;
    }
    return retPtr;
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
template <typename OStream>
bool DehydrateChainObject(OStream &s, const CBaseChainObject *pobj)
{
    switch(pobj->objectType)
    {
        case CHAINOBJ_HEADER:
        {
            s << *(CChainObject<CBlockHeader> *)pobj;
            return true;
        }

        case CHAINOBJ_TRANSACTION:
        {
            s << *(CChainObject<CTransaction> *)pobj;
            return true;
        }

        case CHAINOBJ_PROOF:
        {
            s << *(CChainObject<CMerkleBranch> *)pobj;
            return true;
        }

        case CHAINOBJ_HEADER_REF:
        {
            s << *(CChainObject<CHeaderRef> *)pobj;
            return true;
        }

        case CHAINOBJ_PRIORBLOCKS:
        {
            s << *(CChainObject<CPriorBlocksCommitment> *)pobj;
            return true;
        }

        case CHAINOBJ_RESERVETRANSFER:
        {
            s << *(CChainObject<CReserveTransfer> *)pobj;
            return true;
        }
        case CHAINOBJ_CROSSCHAINPROOF:
        {
            s << *(CChainObject<CCrossChainProof> *)pobj;
            return true;
        }
    }
    return false;
}

int8_t ObjTypeCode(const CBlockHeader &obj);

int8_t ObjTypeCode(const CMerkleBranch &obj);

int8_t ObjTypeCode(const CTransaction &obj);

int8_t ObjTypeCode(const CHeaderRef &obj);

int8_t ObjTypeCode(const CPriorBlocksCommitment &obj);

int8_t ObjTypeCode(const CReserveTransfer &obj);

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(std::vector<CBaseChainObject *> &objPtrs);

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora);

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript);

class CNodeData
{
public:
    std::string networkAddress;
    CKeyID paymentAddress;

    CNodeData() {}
    CNodeData(UniValue &);
    CNodeData(std::string netAddr, uint160 paymentKeyID) : networkAddress(netAddr), paymentAddress(paymentKeyID) {}
    CNodeData(std::string netAddr, std::string paymentAddr) :
        networkAddress(netAddr)
    {
        CBitcoinAddress ba(paymentAddr);
        ba.GetKeyID(paymentAddress);
    }
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(networkAddress);
        READWRITE(paymentAddress);        
    }

    UniValue ToUniValue() const;
};

// This defines the currency characteristics of a PBaaS currency that will be the native coins of a PBaaS chain
class CPBaaSChainDefinition
{
public:
    static const int64_t MIN_PER_BLOCK_NOTARIZATION = 1000000;  // 0.01 VRSC per block notarization minimum
    static const int64_t MIN_BILLING_PERIOD = 480;  // 8 hour minimum billing period for notarization, typically expect days/weeks/months
    static const int64_t DEFAULT_OUTPUT_VALUE = 100000;  // 0.001 VRSC default output value

    static const int32_t OPTION_RESERVE = 1; // allows reserve conversion using base calculations when set

    uint32_t nVersion;                      // version of this chain definition data structure to allow for extensions (not daemon version)
    std::string name;                       // chain name, maximum 64 characters
    CKeyID address;                         // non-purchased/converted premine and fee recipient address
    int64_t premine;                        // initial supply that is distributed to the premine output address, but not purchased
    int64_t initialcontribution;            // optional initial contribution by this transaction. this serves to ensure the option to participate by whoever defines the chain
    int64_t minpreconvert;                  // zero for now, later can be used for Kickstarter-like launch and return all non-network fees upon failure to meet minimum
    int64_t maxpreconvert;                  // maximum amount of reserve that can be pre-converted
    int64_t preconverted;                   // actual converted amount if known
    int64_t conversion;                     // initial reserve ratio, also value in Verus if premine is 0, otherwise value is conversion * maxpreconvert/(maxpreconvert + premine)
    int64_t launchFee;                      // fee deducted from reserve purchase before conversion. always 100000000 (100%) for non-reserve currencies
    int32_t startBlock;                     // parent chain block # that must kickoff the notarization of block 0, cannot be before this block
    int32_t endBlock;                       // block after which this is considered end-of-lifed
    int32_t eras;                           // number of eras, each vector below should have an entry for each
    std::vector<int64_t> rewards;           // initial reward in each ERA in native coin
    std::vector<int64_t> rewardsDecay;      // decay of rewards during the era - only applies to non-converted values
    std::vector<int32_t> halving;           // number of blocks between halvings
    std::vector<int32_t> eraEnd;            // block number that ends each ERA
    std::vector<int32_t> eraOptions;        // flags to determine fungibility and conversion for each ERA

    int32_t billingPeriod;                  // number of blocks in one billing period
    int64_t notarizationReward;             // default amount per block for notarizations

    std::vector<CNodeData> nodes;           // network nodes

    CPBaaSChainDefinition() : nVersion(PBAAS_VERSION_INVALID) {}

    CPBaaSChainDefinition(const UniValue &obj);

    CPBaaSChainDefinition(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CPBaaSChainDefinition(const CTransaction &tx, bool validate = false);

    CPBaaSChainDefinition(std::string Name, std::string Address, int64_t Premine, int64_t Conversion, int64_t minPreConvert, int64_t maxPreConvert, int64_t preConverted, int64_t LaunchFee,
                          int32_t StartBlock, int32_t EndBlock, int32_t chainEras,
                          const std::vector<int64_t> &chainRewards, const std::vector<int64_t> &chainRewardsDecay,
                          const std::vector<int32_t> &chainHalving, const std::vector<int32_t> &chainEraEnd, std::vector<int32_t> &chainCurrencyOptions,
                          int32_t BillingPeriod, int64_t NotaryReward, std::vector<CNodeData> &Nodes) :
                            nVersion(PBAAS_VERSION),
                            name(Name),
                            premine(Premine),
                            conversion(Conversion),
                            minpreconvert(minPreConvert),
                            maxpreconvert(maxPreConvert),
                            preconverted(preConverted),
                            launchFee(LaunchFee),
                            startBlock(StartBlock),
                            endBlock(EndBlock),
                            eras(chainEras),
                            rewards(chainRewards),
                            rewardsDecay(chainRewardsDecay),
                            halving(chainHalving),
                            eraEnd(chainEraEnd),
                            eraOptions(chainCurrencyOptions),
                            billingPeriod(BillingPeriod),
                            notarizationReward(NotaryReward),
                            nodes(Nodes)
    {
        if (Name.size() > (KOMODO_ASSETCHAIN_MAXLEN - 1))
        {
            Name.resize(KOMODO_ASSETCHAIN_MAXLEN - 1);
        }
        name = Name;
        CBitcoinAddress ba(Address);
        ba.GetKeyID(address);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(name);        
        READWRITE(address);        
        READWRITE(VARINT(premine));
        READWRITE(VARINT(conversion));
        READWRITE(VARINT(minpreconvert));
        READWRITE(VARINT(maxpreconvert));
        READWRITE(VARINT(preconverted));
        READWRITE(VARINT(launchFee));
        READWRITE(startBlock);
        READWRITE(endBlock);
        READWRITE(eras);
        READWRITE(rewards);
        READWRITE(rewardsDecay);
        READWRITE(halving);
        READWRITE(eraEnd);
        READWRITE(eraOptions);
        READWRITE(billingPeriod);
        READWRITE(VARINT(notarizationReward));
        READWRITE(nodes);
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    static uint160 GetChainID(std::string name);

    uint160 GetChainID() const
    {
        return GetChainID(name);
    }

    uint160 GetConditionID(int32_t condition) const;

    bool IsValid() const
    {
        return (nVersion != PBAAS_VERSION_INVALID) && (name.size() && eras > 0) && (eras <= ASSETCHAINS_MAX_ERAS);
    }

    int32_t ChainOptions() const
    {
        return eraOptions.size() ? eraOptions[0] : 0;
    }

    UniValue ToUniValue() const;

    int GetDefinedPort() const;
};

// This data structure is used on an output that provides proof of stake validation for other crypto conditions
// with rate limited spends based on a PoS contest
class CPoSSelector
{
public:
    uint32_t nBits;                         // PoS difficulty target
    uint32_t nTargetSpacing;                // number of 1/1000ths of a block between selections (e.g. 1 == 1000 selections per block)

    CPoSSelector(uint32_t bits, uint32_t TargetSpacing)
    {
        nBits = bits; 
        nTargetSpacing = TargetSpacing;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBits);
        READWRITE(nTargetSpacing);
    }

    CPoSSelector(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return nBits != 0;
    }
};

// Additional data for an output pool used for a PBaaS chain's reward for service, such as mining, staking, node or electrum service
class CServiceReward
{
public:
    uint32_t nVersion;                      // version of this chain definition data structure to allow for extensions (not daemon version)
    uint16_t serviceType;                   // type of service
    int32_t billingPeriod;                  // this is used to identify to which billing period of a chain, this reward applies

    CServiceReward() : nVersion(PBAAS_VERSION_INVALID), serviceType(SERVICE_INVALID) {}

    CServiceReward(PBAAS_SERVICE_TYPES ServiceType, int32_t period) : nVersion(PBAAS_VERSION), serviceType(ServiceType), billingPeriod(period) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(serviceType);
        READWRITE(billingPeriod);
    }

    CServiceReward(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CServiceReward(const UniValue &obj) : nVersion(PBAAS_VERSION)
    {
        serviceType = uni_get_str(find_value(obj, "servicetype")) == "notarization" ? SERVICE_NOTARIZATION : SERVICE_INVALID;
        billingPeriod = uni_get_int(find_value(obj, "billingperiod"));
        if (!billingPeriod)
        {
            serviceType = SERVICE_INVALID;
        }
    }

    CServiceReward(const CTransaction &tx, bool validate = false);

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("servicetype", serviceType == SERVICE_NOTARIZATION ? "notarization" : "unknown"));
        obj.push_back(Pair("billingperiod", billingPeriod));
        return obj;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return serviceType != SERVICE_INVALID;
    }
};

class CInputDescriptor
{
public:
    CScript scriptPubKey;
    CAmount nValue;
    CTxIn txIn;
    CInputDescriptor() : nValue(0) {}
    CInputDescriptor(CScript script, CAmount value, CTxIn input) : scriptPubKey(script), nValue(value), txIn(input) {}
};

// import transactions from another chain
// an import transaction on a fractional reserve chain will have an instant spend input of EVAL_CHAIN_IMPORT from the coinbase, 
// which provides for import of a reserve currency or cross-chain token, or auto-conversion to the native currency.
class CCrossChainImport
{
public:
    uint160 chainID;                                            // usually the reserve currency, but here for generality
    CAmount nValue;                                             // total amount of foreign coins imported from chain without conversion

    CCrossChainImport() : nValue(0) { }
    CCrossChainImport(const uint160 &cID, const CAmount value) : chainID(cID), nValue(value) { }

    CCrossChainImport(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCrossChainImport(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nValue));
        READWRITE(chainID);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return !chainID.IsNull();
    }

    UniValue ToUniValue() const;
};

// describes an entire output that will be realized on a target chain. target is specified as part of an aggregated transaction.
class CCrossChainExport
{
public:
    static const int MIN_BLOCKS = 10;
    static const int MIN_INPUTS = 10;
    static const int MAX_EXPORT_INPUTS = 50;
    uint160 chainID;                                // target chain ID
    int32_t numInputs;                              // number of inputs aggregated to calculate the fee percentage
    CAmount totalAmount;                            // total amount of inputs, including fees
    CAmount totalFees;                              // total amount of fees to split between miner on exporting chain and importing chain

    CCrossChainExport() {}

    CCrossChainExport(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCrossChainExport(uint160 cID, int32_t numin, CAmount value, CAmount fees) : chainID(cID), numInputs(numin),totalAmount(value), totalFees(fees) {}

    CCrossChainExport(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainID);
        READWRITE(numInputs);
        READWRITE(VARINT(totalAmount));
        READWRITE(VARINT(totalFees));
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return chainID.IsNull();
    }

    CAmount CalculateExportFee() const;

    CAmount CalculateImportFee() const
    {
        return totalFees - CalculateExportFee();
    }
    
    UniValue ToUniValue() const;
};

// Export some number of cross chain transaction sends to another chain by creating an aggregated transaction with all
// relevant transfer transactions as inputs and an aggregated set of output descriptions to match all inputs.
// Cross chain transfer transactions aggregate a number of cross chain outputs into one bundle and packages them up
// for a transfer to the other chain. This allows the one transaction to be proven on the other chain, which also
// proves all inputs as valid transactions. In addition, the rules of the reserve chain require that the transaction outputs
// match the send destination, which allows the one proof and transitive trust of the other chain's rules to save
// the space required to prove many cross-chain sends.
class CCrossChainTransfer
{
public:
    uint160 chainID;            // destination chain
    CAmount nValue;             // total amount of reserve input that was pre-converted or will be added to the reserves of the chain
    CAmount feesTransfered;     // fees on this chain, which are available to miner on destination chain

    CCrossChainTransfer() {}

    CCrossChainTransfer(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCrossChainTransfer(uint160 chainDest, CAmount valueIn, CAmount fees) : chainID(chainDest), nValue(valueIn), feesTransfered(fees) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainID);
        READWRITE(VARINT(nValue));
        READWRITE(VARINT(feesTransfered));
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return !chainID.IsNull();
    }
};

class CRPCChainData
{
public:
    CPBaaSChainDefinition chainDefinition;  // chain information for the specific chain
    std::string     rpcHost;                // host of the chain's daemon
    int32_t         rpcPort;                // port of the chain's daemon
    std::string     rpcUserPass;            // user and password for this daemon

    CRPCChainData() {}
    CRPCChainData(CPBaaSChainDefinition &chainDef, std::string host, int32_t port, std::string userPass) :
        chainDefinition(chainDef), rpcHost{host}, rpcPort(port), rpcUserPass(userPass) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid()
    {
        return chainDefinition.IsValid();
    }

    uint160 GetChainID()
    {
        return chainDefinition.GetChainID();
    }
};

// Each merge mined chain gets an entry that includes information required to connect to a live daemon
// for that block, cross notarize, and validate notarizations.
class CPBaaSMergeMinedChainData : public CRPCChainData
{
public:
    static const uint32_t MAX_MERGE_CHAINS = 15;
    CBlock          block;                  // full block to submit upon winning header

    CPBaaSMergeMinedChainData() {}
    CPBaaSMergeMinedChainData(CPBaaSChainDefinition &chainDef, std::string host, int32_t port, std::string userPass, CBlock &blk) :
        CRPCChainData(chainDef, host, port, userPass), block(blk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
        READWRITE(block);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }
};

class CConnectedChains
{
protected:
    CPBaaSMergeMinedChainData *GetChainInfo(uint160 chainID);

public:
    std::map<uint160, CPBaaSMergeMinedChainData> mergeMinedChains;
    std::map<arith_uint256, CPBaaSMergeMinedChainData *> mergeMinedTargets;

    std::string notaryChainVersion;             // is Verus or VRSCTEST running and PBaaS compatible?
    int32_t notaryChainHeight;                  // is Verus or VRSCTEST running and PBaaS compatible?
    CRPCChainData notaryChain;                  // notary chain information

    CPBaaSChainDefinition thisChain;
    std::vector<std::pair<int, CScript>> latestMiningOutputs; // accessible from all merge miners - can be invalid
    CTxDestination  latestDestination;          // latest destination from miner output 0 - can be invalid
    int64_t lastAggregation = 0;                // adjusted time of last aggregation

    int32_t earnedNotarizationHeight;           // zero or the height of one or more potential submissions
    CBlock earnedNotarizationBlock;
    int32_t earnedNotarizationIndex;            // index of earned notarization in block

    bool dirty;
    bool lastSubmissionFailed;                  // if we submit a failed block, make another
    std::map<arith_uint256, CBlockHeader> qualifiedHeaders;

    CCriticalSection cs_mergemining;
    CSemaphore sem_submitthread;

    CConnectedChains() : sem_submitthread(0), earnedNotarizationHeight(0), dirty(0), lastSubmissionFailed(0) {}

    arith_uint256 LowestTarget()
    {
        if (mergeMinedTargets.size())
        {
            return mergeMinedTargets.begin()->first;
        }
        else
        {
            return arith_uint256(0);
        }
    }

    void SubmissionThread();
    static void SubmissionThreadStub();
    std::vector<std::pair<std::string, UniValue>> SubmitQualifiedBlocks();

    bool QueueNewBlockHeader(CBlockHeader &bh);
    void QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height);

    bool AddMergedBlock(CPBaaSMergeMinedChainData &blkData);
    bool RemoveMergedBlock(uint160 chainID);
    bool GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData);
    uint32_t PruneOldChains(uint32_t pruneBefore);
    uint32_t CombineBlocks(CBlockHeader &bh);

    // returns false if destinations are empty or first is not either pubkey or pubkeyhash
    bool SetLatestMiningOutputs(const std::vector<std::pair<int, CScript>> minerOutputs, CTxDestination &firstDestinationOut);
    void AggregateChainTransfers(const CTxDestination &feeOutput, uint32_t nHeight);

    // send new imports from this chain to the specified chain, which generally will be the notary chain
    void SendNewImports(const uint160 &chainID, 
                        const CPBaaSNotarization &notarization, 
                        const uint256 &lastExportTx, 
                        const CTransaction &lastCrossImport, 
                        const CTransaction &lastExport);

    bool GetLastImport(const uint160 &chainID, 
                       CTransaction &lastImport, 
                       CTransaction &crossChainExport, 
                       CCrossChainImport &ccImport, 
                       CCrossChainExport &ccCrossExport);

    // returns newly created import transactions to the specified chain from exports on this chain specified chain
    bool CreateLatestImports(const CPBaaSChainDefinition &chainDef, 
                             const CTransaction &lastCrossChainImport, 
                             const CTransaction &importTxTemplate,
                             const CTransaction &lastConfirmedNotarization,
                             std::vector<CTransaction> &newImports);

    CRPCChainData &NotaryChain()
    {
        return notaryChain;
    }

    CPBaaSChainDefinition &ThisChain()
    {
        return thisChain;
    }

    CCoinbaseCurrencyState GetCurrencyState(int32_t height);

    bool CheckVerusPBaaSAvailable(UniValue &chainInfo, UniValue &chainDef);
    bool CheckVerusPBaaSAvailable();      // may use RPC to call Verus
    bool IsVerusPBaaSAvailable();
    std::vector<CPBaaSChainDefinition> GetMergeMinedChains()
    {
        std::vector<CPBaaSChainDefinition> ret;
        LOCK(cs_mergemining);
        for (auto &chain : mergeMinedChains)
        {
            ret.push_back(chain.second.chainDefinition);
        }
        return ret;
    }
};

template <typename TOBJ>
CTxOut MakeCC1of1Vout(uint8_t evalcode, CAmount nValue, CPubKey pk, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1(evalcode, pk);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector(obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 1, vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC0of0Vout(uint8_t evalcode, CAmount nValue, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond0(evalcode);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector(obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 1, vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector(obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 2, vpk, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector(obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 2, vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

bool IsVerusActive();

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsCrossChainExportInput(const CScript &scriptSig);

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsCrossChainImportInput(const CScript &scriptSig);

// used to validate a specific service reward based on the spending transaction
bool ValidateServiceReward(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsServiceRewardInput(const CScript &scriptSig);

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsReserveOutputInput(const CScript &scriptSig);

// used to transfer a reserve currency between chains
bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsReserveTransferInput(const CScript &scriptSig);

// used as exchange tokens between reserves and fractional reserves
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsReserveExchangeInput(const CScript &scriptSig);

// used to deposit reserves into a reserve UTXO set
bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsReserveDepositInput(const CScript &scriptSig);

bool ValidateChainDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsChainDefinitionInput(const CScript &scriptSig);

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn);
bool IsCurrencyStateInput(const CScript &scriptSig);

bool GetCCParams(const CScript &scr, COptCCParams &ccParams);

bool SetThisChain(UniValue &chainDefinition);

extern CConnectedChains ConnectedChains;
extern uint160 ASSETCHAINS_CHAINID;

#endif
