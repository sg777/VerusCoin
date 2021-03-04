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
 */

#include "base58.h"
#include "main.h"
#include "rpc/pbaasrpc.h"
#include "timedata.h"
#include "transaction_builder.h"

CConnectedChains ConnectedChains;

bool IsVerusActive()
{
    return (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0 || strcmp(ASSETCHAINS_SYMBOL, "VRSCTEST") == 0);
}

bool IsVerusMainnetActive()
{
    return (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0);
}

// this adds an opret to a mutable transaction and returns the voutnum if it could be added
int32_t AddOpRetOutput(CMutableTransaction &mtx, const CScript &opRetScript)
{
    if (opRetScript.IsOpReturn() && opRetScript.size() <= MAX_OP_RETURN_RELAY)
    {
        CTxOut vOut = CTxOut();
        vOut.scriptPubKey = opRetScript;
        vOut.nValue = 0;
        mtx.vout.push_back(vOut);
        return mtx.vout.size() - 1;
    }
    else
    {
        return -1;
    }
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo)
{
    union {
        const CBaseChainObject *retPtr;
        const CChainObject<CBlockHeaderAndProof> *pNewHeader;
        const CChainObject<CPartialTransactionProof> *pNewTx;
        const CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        const CChainObject<CPriorBlocksCommitment> *pPriors;
        const CChainObject<uint256> *pNewProofRoot;
        const CChainObject<CReserveTransfer> *pExport;
        const CChainObject<CCrossChainProof> *pCrossChainProof;
        const CChainObject<CCompositeChainObject> *pCompositeChainObject;
    };

    retPtr = &bo;

    switch(bo.objectType)
    {
        case CHAINOBJ_HEADER:
            return pNewHeader->GetHash();

        case CHAINOBJ_TRANSACTION_PROOF:
            return pNewTx->GetHash();

        case CHAINOBJ_HEADER_REF:
            return pNewHeaderRef->GetHash();

        case CHAINOBJ_PRIORBLOCKS:
            return pPriors->GetHash();

        case CHAINOBJ_PROOF_ROOT:
            return pNewProofRoot->object;

        case CHAINOBJ_RESERVETRANSFER:
            return pExport->GetHash();

        case CHAINOBJ_CROSSCHAINPROOF:
            return pCrossChainProof->GetHash();

        case CHAINOBJ_COMPOSITEOBJECT:
            return pCrossChainProof->GetHash();

    }
    return uint256();
}

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsCrossChainExportInput(const CScript &scriptSig)
{
    return true;
}

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsCrossChainImportInput(const CScript &scriptSig)
{
    return true;
}

// Validate notary evidence
bool ValidateNotaryEvidence(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsNotaryEvidenceInput(const CScript &scriptSig)
{
    return true;
}

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveOutputInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveTransferInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveDepositInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsCurrencyStateInput(const CScript &scriptSig)
{
    return true;
}

// used to convert a fractional reserve currency into its reserve and back 
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveExchangeInput(const CScript &scriptSig)
{
    return true;
}


/*
 * Verifies that the input objects match the hashes and returns the transaction.
 * 
 * If the opRetTx has the op ret, this calculates based on the actual transaction and
 * validates the hashes. If the opRetTx does not have the opRet itself, this validates
 * by ensuring that all objects are present on this chain, composing the opRet, and
 * ensuring that the transaction then hashes to the correct txid.
 * 
 */
bool ValidateOpretProof(CScript &opRet, COpRetProof &orProof)
{
    // enumerate through the objects and validate that they are objects of the expected type that hash
    // to the value expected. return true if so
    return true;
}

int8_t ObjTypeCode(const CBlockHeaderProof &obj)
{
    return CHAINOBJ_HEADER;
}

int8_t ObjTypeCode(const uint256 &obj)
{
    return CHAINOBJ_PROOF_ROOT;
}

int8_t ObjTypeCode(const CPartialTransactionProof &obj)
{
    return CHAINOBJ_TRANSACTION_PROOF;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj)
{
    return CHAINOBJ_HEADER_REF;
}

int8_t ObjTypeCode(const CPriorBlocksCommitment &obj)
{
    return CHAINOBJ_PRIORBLOCKS;
}

int8_t ObjTypeCode(const CReserveTransfer &obj)
{
    return CHAINOBJ_RESERVETRANSFER;
}

int8_t ObjTypeCode(const CCrossChainProof &obj)
{
    return CHAINOBJ_CROSSCHAINPROOF;
}

int8_t ObjTypeCode(const CCompositeChainObject &obj)
{
    return CHAINOBJ_COMPOSITEOBJECT;
}

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs)
{
    CScript vData;
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    s << (int32_t)OPRETTYPE_OBJECTARR;
    bool error = false;

    for (auto pobj : objPtrs)
    {
        try
        {
            if (!DehydrateChainObject(s, pobj))
            {
                error = true;
                break;
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            error = true;
            break;
        }
    }

    //std::vector<unsigned char> schars(s.begin(), s.begin() + 200);
    //printf("stream vector chars: %s\n", HexBytes(&schars[0], schars.size()).c_str());

    std::vector<unsigned char> vch(s.begin(), s.end());
    return error ? CScript() : CScript() << OP_RETURN << vch;
}

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora)
{
    for (auto pobj : ora)
    {
        switch(pobj->objectType)
        {
            case CHAINOBJ_HEADER:
            {
                delete (CChainObject<CBlockHeaderAndProof> *)pobj;
                break;
            }

            case CHAINOBJ_TRANSACTION_PROOF:
            {
                delete (CChainObject<CPartialTransactionProof> *)pobj;
                break;
            }

            case CHAINOBJ_PROOF_ROOT:
            {
                delete (CChainObject<uint256> *)pobj;
                break;
            }

            case CHAINOBJ_HEADER_REF:
            {
                delete (CChainObject<CBlockHeaderProof> *)pobj;
                break;
            }

            case CHAINOBJ_PRIORBLOCKS:
            {
                delete (CChainObject<CPriorBlocksCommitment> *)pobj;
                break;
            }

            case CHAINOBJ_RESERVETRANSFER:
            {
                delete (CChainObject<CReserveTransfer> *)pobj;
                break;
            }

            case CHAINOBJ_CROSSCHAINPROOF:
            {
                delete (CChainObject<CCrossChainProof> *)pobj;
                break;
            }

            case CHAINOBJ_COMPOSITEOBJECT:
            {
                delete (CChainObject<CCompositeChainObject> *)pobj;
                break;
            }

            case CHAINOBJ_NOTARYSIGNATURE:
            {
                delete (CChainObject<CNotaryEvidence> *)pobj;
                break;
            }

            default:
            {
                printf("ERROR: invalid object type (%u), likely corrupt pointer %p\n", pobj->objectType, pobj);
                printf("generate code that won't be optimized away %s\n", CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<CAmount>({200000000})).ToUniValue().write(1,2).c_str());
                printf("This is here to generate enough code for a good break point system chain name: %s\n", ConnectedChains.ThisChain().name.c_str());
                
                delete pobj;
            }
        }
    }
    ora.clear();
}

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript)
{
    std::vector<unsigned char> vch;
    std::vector<CBaseChainObject *> vRet;
    if (opRetScript.IsOpReturn() && GetOpReturnData(opRetScript, vch) && vch.size() > 0)
    {
        CDataStream s = CDataStream(vch, SER_NETWORK, PROTOCOL_VERSION);

        int32_t opRetType;

        try
        {
            s >> opRetType;
            if (opRetType == OPRETTYPE_OBJECTARR)
            {
                CBaseChainObject *pobj;
                while (!s.empty() && (pobj = RehydrateChainObject(s)))
                {
                    vRet.push_back(pobj);
                }
                if (!s.empty())
                {
                    printf("failed to load all objects in opret");
                    DeleteOpRetObjects(vRet);
                    vRet.clear();
                }
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            DeleteOpRetObjects(vRet);
            vRet.clear();
        }
    }
    return vRet;
}

CCrossChainExport::CCrossChainExport(const CScript &script)
{
    COptCCParams p;
    if (script.IsPayToCryptoCondition(p) &&
        p.IsValid() &&
        p.evalCode == EVAL_CROSSCHAIN_EXPORT)
    {
        FromVector(p.vData[0], *this);
    }
}

CCrossChainExport::CCrossChainExport(const CTransaction &tx, int32_t *pCCXOutputNum)
{
    int32_t _ccxOutputNum = 0;
    int32_t &ccxOutputNum = pCCXOutputNum ? *pCCXOutputNum : _ccxOutputNum;
    
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_EXPORT)
        {
            FromVector(p.vData[0], *this);
            ccxOutputNum = i;
            break;
        }
    }
}

CCurrencyDefinition::CCurrencyDefinition(const CScript &scriptPubKey)
{
    nVersion = PBAAS_VERSION_INVALID;
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if (p.evalCode == EVAL_CURRENCY_DEFINITION)
        {
            FromVector(p.vData[0], *this);
        }
    }
}

std::vector<CCurrencyDefinition> CCurrencyDefinition::GetCurrencyDefinitions(const CTransaction &tx)
{
    std::vector<CCurrencyDefinition> retVal;
    for (auto &out : tx.vout)
    {
        CCurrencyDefinition oneCur = CCurrencyDefinition(out.scriptPubKey);
        if (oneCur.IsValid())
        {
            retVal.push_back(oneCur);
        }
    }
    return retVal;
}

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY, ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;
extern uint160 VERUS_CHAINID;

// ensures that the chain definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool ValidateChainDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // the chain definition output can be spent when the chain is at the end of its life and only then
    // TODO
    return false;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee(const CCurrencyValueMap &fees, int numIn)
{
    CCurrencyValueMap retVal;
    int maxFeeCalc = numIn;

    if (maxFeeCalc > MAX_FEE_INPUTS)
    {
        maxFeeCalc = MAX_FEE_INPUTS;
    }
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / maxFeeCalc) * (numIn - 1)));

    for (auto &feePair : fees.valueMap)
    {
        retVal.valueMap[feePair.first] = (((arith_uint256(feePair.second) * ratio)) / satoshis).GetLow64();
    }
    return retVal.CanonicalMap();
}

CAmount CCrossChainExport::CalculateExportFeeRaw(CAmount fee, int numIn)
{
    int maxFeeCalc = std::min((int)MAX_FEE_INPUTS, std::max(1, numIn));
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / MAX_FEE_INPUTS) * (maxFeeCalc - 1)));

    return (((arith_uint256(fee) * ratio)) / satoshis).GetLow64();
}

CAmount CCrossChainExport::ExportReward(int64_t exportFee)
{
    int64_t individualExportFee = ((arith_uint256(exportFee) * 10000000) / SATOSHIDEN).GetLow64();
    if (individualExportFee < MIN_FEES_BEFORE_FEEPOOL)
    {
        individualExportFee = exportFee > MIN_FEES_BEFORE_FEEPOOL ? MIN_FEES_BEFORE_FEEPOOL : exportFee;
    }
    return individualExportFee;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee() const
{
    return CalculateExportFee(totalFees, numInputs);
}

CCurrencyValueMap CCrossChainExport::CalculateImportFee() const
{
    CCurrencyValueMap retVal;

    for (auto &feePair : CalculateExportFee().valueMap)
    {
        CAmount feeAmount = feePair.second;
        auto it = totalFees.valueMap.find(feePair.first);
        retVal.valueMap[feePair.first] = (it != totalFees.valueMap.end() ? it->second : 0) - feeAmount;
    }
    return retVal;
}

bool CEthGateway::ValidateDestination(const std::string &destination) const
{
    // just returns true if it looks like a non-NULL ETH address
    return (destination.substr(0,2) == "0x" && 
            destination.length() == 42 && 
            IsHex(destination.substr(2,40)) && 
            !uint160(ParseHex(destination.substr(2,64))).IsNull());
}

CTransferDestination CEthGateway::ToTransferDestination(const std::string &destination) const
{
    // just returns true if it looks like a non-NULL ETH address
    uint160 retVal;
    if (destination.substr(0,2) == "0x" && 
            destination.length() == 42 && 
            IsHex(destination.substr(2,40)) && 
            !(retVal = uint160(ParseHex(destination.substr(2,64)))).IsNull())
    {
        return CTransferDestination(CTransferDestination::FLAG_DEST_GATEWAY + CTransferDestination::DEST_RAW,
                                    std::vector<unsigned char>(retVal.begin(), retVal.end()));
    }
    return CTransferDestination();
}

// hard coded ETH gateway currency, "veth" for Verus chain. should be updated to work with PBaaS chains
std::set<uint160> CEthGateway::FeeCurrencies() const
{
    std::set<uint160> retVal;
    retVal.insert(CCrossChainRPCData::GetID("veth@"));
    return retVal;
}

const CCurrencyDefinition &CEthGateway::GetConverter() const
{
    // just returns true if it looks like a non-NULL ETH address
    static CCurrencyDefinition ethFeeConverter;
    if (!ethFeeConverter.IsValid())
    {
        GetCurrencyDefinition("vrsc-eth-dai", ethFeeConverter);
    }
    return ethFeeConverter;
}

bool CConnectedChains::RemoveMergedBlock(uint160 chainID)
{
    bool retval = false;
    LOCK(cs_mergemining);

    //printf("RemoveMergedBlock ID: %s\n", chainID.GetHex().c_str());

    auto chainIt = mergeMinedChains.find(chainID);
    if (chainIt != mergeMinedChains.end())
    {
        arith_uint256 target;
        target.SetCompact(chainIt->second.block.nBits);
        for (auto removeRange = mergeMinedTargets.equal_range(target); removeRange.first != removeRange.second; removeRange.first++)
        {
            // make sure we don't just match by target
            if (removeRange.first->second->GetID() == chainID)
            {
                mergeMinedTargets.erase(removeRange.first);
                break;
            }
        }
        mergeMinedChains.erase(chainID);
        dirty = retval = true;

        // if we get to 0, give the thread a kick to stop waiting for mining
        //if (!mergeMinedChains.size())
        //{
        //    sem_submitthread.post();
        //}
    }
    return retval;
}

// remove merge mined chains added and not updated since a specific time
void CConnectedChains::PruneOldChains(uint32_t pruneBefore)
{
    vector<uint160> toRemove;

    LOCK(cs_mergemining);
    for (auto blkData : mergeMinedChains)
    {
        if (blkData.second.block.nTime < pruneBefore)
        {
            toRemove.push_back(blkData.first);
        }
    }

    for (auto id : toRemove)
    {
        //printf("Pruning chainID: %s\n", id.GetHex().c_str());
        RemoveMergedBlock(id);
    }
}

// adds or updates merge mined blocks
// returns false if failed to add
bool CConnectedChains::AddMergedBlock(CPBaaSMergeMinedChainData &blkData)
{
    // determine if we should replace one or add to the merge mine vector
    {
        LOCK(cs_mergemining);

        arith_uint256 target;
        uint160 cID = blkData.GetID();
        auto it = mergeMinedChains.find(cID);
        if (it != mergeMinedChains.end())
        {
            RemoveMergedBlock(cID);             // remove it if already there
        }
        target.SetCompact(blkData.block.nBits);

        //printf("AddMergedBlock name: %s, ID: %s\n", blkData.chainDefinition.name.c_str(), cID.GetHex().c_str());

        mergeMinedTargets.insert(make_pair(target, &(mergeMinedChains.insert(make_pair(cID, blkData)).first->second)));
        dirty = true;
    }
    return true;
}

bool CInputDescriptor::operator<(const CInputDescriptor &op) const
{
    arith_uint256 left = UintToArith256(txIn.prevout.hash);
    arith_uint256 right = UintToArith256(op.txIn.prevout.hash);
    return left < right ? true : left > right ? false : txIn.prevout.n < op.txIn.prevout.n ? true : false;
}


bool CConnectedChains::GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData)
{
    {
        LOCK(cs_mergemining);
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            rpcChainData = (CRPCChainData)chainIt->second;
            return true;
        }
        return false;
    }
}

// this returns a pointer to the data without copy and assumes the lock is held
CPBaaSMergeMinedChainData *CConnectedChains::GetChainInfo(uint160 chainID)
{
    {
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            return &chainIt->second;
        }
        return NULL;
    }
}

void CConnectedChains::QueueNewBlockHeader(CBlockHeader &bh)
{
    //printf("QueueNewBlockHeader %s\n", bh.GetHash().GetHex().c_str());
    {
        LOCK(cs_mergemining);

        qualifiedHeaders[UintToArith256(bh.GetHash())] = bh;
    }
    sem_submitthread.post();
}

void CConnectedChains::CheckImports()
{
    sem_submitthread.post();
}

// get the latest block header and submit one block at a time, returning after there are no more
// matching blocks to be found
vector<pair<string, UniValue>> CConnectedChains::SubmitQualifiedBlocks()
{
    std::set<uint160> inHeader;
    bool submissionFound;
    CPBaaSMergeMinedChainData chainData;
    vector<pair<string, UniValue>>  results;

    CBlockHeader bh;
    arith_uint256 lastHash;
    CPBaaSBlockHeader pbh;

    do
    {
        submissionFound = false;
        {
            LOCK(cs_mergemining);
            // attempt to submit with the lowest hash answers first to increase the likelihood of submitting
            // common, merge mined headers for notarization, drop out on any submission
            for (auto headerIt = qualifiedHeaders.begin(); !submissionFound && headerIt != qualifiedHeaders.end(); headerIt = qualifiedHeaders.begin())
            {
                // add the PBaaS chain ids from this header to a set for search
                for (uint32_t i = 0; headerIt->second.GetPBaaSHeader(pbh, i); i++)
                {
                    inHeader.insert(pbh.chainID);
                }

                uint160 chainID;
                // now look through all targets that are equal to or above the hash of this header
                for (auto chainIt = mergeMinedTargets.lower_bound(headerIt->first); !submissionFound && chainIt != mergeMinedTargets.end(); chainIt++)
                {
                    chainID = chainIt->second->GetID();
                    if (inHeader.count(chainID))
                    {
                        // first, check that the winning header matches the block that is there
                        CPBaaSPreHeader preHeader(chainIt->second->block);
                        preHeader.SetBlockData(headerIt->second);

                        // check if the block header matches the block's specific data, only then can we create a submission from this block
                        if (headerIt->second.CheckNonCanonicalData(chainID))
                        {
                            // save block as is, remove the block from merged headers, replace header, and submit
                            chainData = *chainIt->second;

                            *(CBlockHeader *)&chainData.block = headerIt->second;

                            submissionFound = true;
                        }
                        //else // not an error condition. code is here for debugging
                        //{
                        //    printf("Mismatch in non-canonical data for chain %s\n", chainIt->second->chainDefinition.name.c_str());
                        //}
                    }
                    //else // not an error condition. code is here for debugging
                    //{
                    //    printf("Not found in header %s\n", chainIt->second->chainDefinition.name.c_str());
                    //}
                }

                // if this header matched no block, discard and move to the next, otherwise, we'll drop through
                if (submissionFound)
                {
                    // once it is going to be submitted, remove block from this chain until a new one is added again
                    RemoveMergedBlock(chainID);
                    break;
                }
                else
                {
                    qualifiedHeaders.erase(headerIt);
                }
            }
        }
        if (submissionFound)
        {
            // submit one block and loop again. this approach allows multiple threads
            // to collectively empty the submission queue, mitigating the impact of
            // any one stalled daemon
            UniValue submitParams(UniValue::VARR);
            submitParams.push_back(EncodeHexBlk(chainData.block));
            UniValue result, error;
            try
            {
                result = RPCCall("submitblock", submitParams, chainData.rpcUserPass, chainData.rpcPort, chainData.rpcHost);
                result = find_value(result, "result");
                error = find_value(result, "error");
            }
            catch (exception e)
            {
                result = UniValue(e.what());
            }
            results.push_back(make_pair(chainData.chainDefinition.name, result));
            if (result.isStr() || !error.isNull())
            {
                printf("Error submitting block to %s chain: %s\n", chainData.chainDefinition.name.c_str(), result.isStr() ? result.get_str().c_str() : error.get_str().c_str());
            }
            else
            {
                printf("Successfully submitted block to %s chain\n", chainData.chainDefinition.name.c_str());
            }
        }
    } while (submissionFound);
    return results;
}

// add all merge mined chain PBaaS headers into the blockheader and return the easiest nBits target in the header
uint32_t CConnectedChains::CombineBlocks(CBlockHeader &bh)
{
    vector<uint160> inHeader;
    vector<UniValue> toCombine;
    arith_uint256 blkHash = UintToArith256(bh.GetHash());
    arith_uint256 target(0);
    
    CPBaaSBlockHeader pbh;

    {
        LOCK(cs_mergemining);

        CPBaaSSolutionDescriptor descr = CVerusSolutionVector::solutionTools.GetDescriptor(bh.nSolution);

        for (uint32_t i = 0; i < descr.numPBaaSHeaders; i++)
        {
            if (bh.GetPBaaSHeader(pbh, i))
            {
                inHeader.push_back(pbh.chainID);
            }
        }

        // loop through the existing PBaaS chain ids in the header
        // remove any that are not either this Chain ID or in our local collection and then add all that are present
        for (uint32_t i = 0; i < inHeader.size(); i++)
        {
            auto it = mergeMinedChains.find(inHeader[i]);
            if (inHeader[i] != ASSETCHAINS_CHAINID && (it == mergeMinedChains.end()))
            {
                bh.DeletePBaaSHeader(i);
            }
        }

        for (auto chain : mergeMinedChains)
        {
            // get the native PBaaS header for each chain and put it into the
            // header we are given
            // it must have itself in as a PBaaS header
            uint160 cid = chain.second.GetID();
            if (chain.second.block.GetPBaaSHeader(pbh, cid) != -1)
            {
                if (!bh.AddUpdatePBaaSHeader(pbh))
                {
                    LogPrintf("Failure to add PBaaS block header for %s chain\n", chain.second.chainDefinition.name.c_str());
                    break;
                }
                else
                {
                    arith_uint256 t;
                    t.SetCompact(chain.second.block.nBits);
                    if (t > target)
                    {
                        target = t;
                    }
                }
            }
            else
            {
                LogPrintf("Merge mined block for %s does not contain PBaaS information\n", chain.second.chainDefinition.name.c_str());
            }
        }
        dirty = false;
    }

    return target.GetCompact();
}

bool CConnectedChains::IsVerusPBaaSAvailable()
{
    return IsNotaryAvailable() && FirstNotaryChain().chainDefinition.GetID() == VERUS_CHAINID;
}

bool CConnectedChains::IsNotaryAvailable()
{
    return !(FirstNotaryChain().rpcHost.empty() || FirstNotaryChain().rpcPort == 0 || FirstNotaryChain().rpcUserPass.empty());
}

extern string PBAAS_HOST, PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
bool CConnectedChains::CheckVerusPBaaSAvailable(UniValue &chainInfoUni, UniValue &chainDefUni)
{
    if (chainInfoUni.isObject() && chainDefUni.isObject())
    {
        UniValue uniVer = find_value(chainInfoUni, "VRSCversion");
        if (uniVer.isStr())
        {
            LOCK(cs_mergemining);
            CCurrencyDefinition chainDef(chainDefUni);
            if (chainDef.IsValid())
            {
                if (!notarySystems.count(chainDef.GetID()))
                {
                    notarySystems[chainDef.GetID()] = CNotarySystemInfo(uni_get_int(find_value(chainInfoUni, "blocks")), 
                                                      CRPCChainData(chainDef, PBAAS_HOST, PBAAS_PORT, PBAAS_USERPASS),
                                                      CCurrencyDefinition());
                }
            }
        }
    }
    return IsVerusPBaaSAvailable();
}

uint32_t CConnectedChains::NotaryChainHeight()
{
    LOCK(cs_mergemining);
    return notarySystems.size() ? notarySystems.begin()->second.height : 0;
}

bool CConnectedChains::CheckVerusPBaaSAvailable()
{
    if (!IsVerusActive())
    {
        // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
        // tolerate only 15 second timeout
        UniValue chainInfo, chainDef;
        try
        {
            UniValue params(UniValue::VARR);
            chainInfo = find_value(RPCCallRoot("getinfo", params), "result");
            if (!chainInfo.isNull())
            {
                params.push_back(VERUS_CHAINNAME);
                chainDef = find_value(RPCCallRoot("getcurrency", params), "result");

                if (!chainDef.isNull() && CheckVerusPBaaSAvailable(chainInfo, chainDef))
                {
                    // if we have not past block 1 yet, store the best known update of our current state
                    if ((!chainActive.LastTip() || !chainActive.LastTip()->GetHeight()))
                    {
                        bool success = false;
                        params.clear();
                        params.push_back(EncodeDestination(CIdentityID(thisChain.GetID())));
                        chainDef = find_value(RPCCallRoot("getcurrency", params), "result");
                        if (!chainDef.isNull())
                        {
                            CCurrencyDefinition currencyDef(chainDef);
                            if (currencyDef.IsValid())
                            {
                                thisChain = currencyDef;
                                if (NotaryChainHeight() >= thisChain.startBlock)
                                {
                                    readyToStart = true;    // this only gates mining of block one, to be sure we have the latest definition
                                }
                                success = true;
                            }
                        }
                        return success;
                    }
                    return true;
                }
            }
        } catch (exception e)
        {
            LogPrintf("%s: Error communicating with %s chain\n", __func__, VERUS_CHAINNAME);
        }
    }
    return false;
}

int CConnectedChains::GetThisChainPort() const
{
    int port;
    string host;
    for (auto node : defaultPeerNodes)
    {
        SplitHostPort(node.networkAddress, port, host);
        if (port)
        {
            return port;
        }
    }
    return 0;
}

CCoinbaseCurrencyState CConnectedChains::AddPrelaunchConversions(CCurrencyDefinition &curDef,
                                                                 const CCoinbaseCurrencyState &_currencyState,
                                                                 int32_t fromHeight,
                                                                 int32_t height,
                                                                 int32_t curDefHeight)
{
    CCoinbaseCurrencyState currencyState = _currencyState;
    bool firstUpdate = fromHeight <= curDefHeight;
    if (firstUpdate)
    {
        if (curDef.IsFractional())
        {
            currencyState.supply = curDef.initialFractionalSupply;
            currencyState.reserves = std::vector<int64_t>(currencyState.reserves.size(), 0);
            currencyState.weights = curDef.weights;
        }
        else
        {
            // supply is determined by purchases * current conversion rate
            currencyState.supply = currencyState.initialSupply;
        }
    }

    // get chain transfers that should apply before the start block
    // until there is a post-start block notarization, we always consider the
    // currency state to be up to just before the start block
    std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> unspentTransfers;
    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();
    int32_t nativeIdx = currencyIndexes.count(curDef.systemID) ? currencyIndexes[curDef.systemID] : -1;

    if (GetChainTransfers(unspentTransfers, curDef.GetID(), fromHeight, height < curDef.startBlock ? height : curDef.startBlock - 1))
    {
        currencyState.ClearForNextBlock();

        for (auto &transfer : unspentTransfers)
        {
            if (transfer.second.second.IsPreConversion())
            {
                CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.FirstValue());
                CAmount valueIn = transfer.second.second.FirstValue() - conversionFee;
                int32_t curIdx = currencyIndexes[transfer.second.second.FirstCurrency()];

                currencyState.reserveIn[curIdx] += valueIn;
                curDef.preconverted[curIdx] += valueIn;
                if (curDef.IsFractional())
                {
                    currencyState.reserves[curIdx] += valueIn;
                }
                else
                {
                    currencyState.supply += CCurrencyState::ReserveToNativeRaw(valueIn, currencyState.PriceInReserve(curIdx));
                }

                if (transfer.second.second.FirstCurrency() == curDef.systemID)
                {
                    currencyState.nativeConversionFees += conversionFee;
                    currencyState.nativeFees += conversionFee;
                }
                currencyState.fees[curIdx] += conversionFee;
                currencyState.nativeFees +=  transfer.second.second.CalculateTransferFee(transfer.second.second.destination);
                currencyState.fees[nativeIdx] +=  transfer.second.second.CalculateTransferFee(transfer.second.second.destination);
                currencyState.conversionFees[curIdx] += conversionFee;
            }
        }
    }

    if (curDef.IsFractional())
    {
        // convert all non-native fees to native and update the price as a result
        bool isFeeConversion = false;
        int numCurrencies = curDef.currencies.size();
        std::vector<int64_t> reservesToConvert(numCurrencies, 0);
        std::vector<int64_t> fractionalToConvert(numCurrencies, 0);
        std::vector<int64_t> reserveAdjustments(numCurrencies, 0);

        for (int i = 0; i < numCurrencies; i++)
        {
            curDef.conversions[i] = currencyState.conversionPrice[i] = currencyState.PriceInReserve(i, true);

            // all currencies except the native currency of the system will be converted to the native currency
            if (currencyState.fees[i] && curDef.currencies[i] != curDef.systemID)
            {
                fractionalToConvert[nativeIdx] += currencyState.ReserveToNativeRaw(currencyState.fees[i], currencyState.conversionPrice[i]);
                reserveAdjustments[i] += currencyState.fees[i];
                isFeeConversion = true;
            }
        }

        // convert all non-native fee currencies to native and adjust prices
        if (isFeeConversion)
        {
            for (int i = 0; i < numCurrencies; i++)
            {
                if (reserveAdjustments[i])
                {
                    currencyState.reserveIn[i] += reserveAdjustments[i];
                    currencyState.reserves[i] += reserveAdjustments[i];
                }
            }
            currencyState.supply += fractionalToConvert[nativeIdx];

            CCurrencyState converterState = static_cast<CCurrencyState>(currencyState);
            currencyState.viaConversionPrice = converterState.ConvertAmounts(reservesToConvert, fractionalToConvert, currencyState);

            for (int j = 0; j < numCurrencies; j++)
            {
                currencyState.reserves[j] = converterState.reserves[j];
            }
            currencyState.supply = converterState.supply - fractionalToConvert[nativeIdx];

            // to ensure no rounding errors, use the resulting native price to convert the fee fractional to native,
            // subtract from supply, and subtract from native reserves
            CAmount nativeFeeOutput = currencyState.NativeToReserveRaw(fractionalToConvert[nativeIdx], currencyState.viaConversionPrice[nativeIdx]);
            currencyState.nativeConversionFees += nativeFeeOutput;
            currencyState.nativeFees += nativeFeeOutput;
            currencyState.reserves[nativeIdx] -= nativeFeeOutput;
            currencyState.reserveOut[nativeIdx] += nativeFeeOutput;
        }
    }

    // set initial supply from actual conversions if this is first update
    if (firstUpdate && curDef.IsFractional())
    {
        CAmount calculatedSupply = 0;
        for (auto &transfer : unspentTransfers)
        {
            if (transfer.second.second.IsPreConversion())
            {
                CAmount toConvert = transfer.second.second.FirstValue() - CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.FirstValue());
                calculatedSupply += CCurrencyState::ReserveToNativeRaw(toConvert, currencyState.conversionPrice[currencyIndexes[transfer.second.second.FirstCurrency()]]);
            }
        }

        if (calculatedSupply > curDef.initialFractionalSupply)
        {            
            // get a ratio and reduce all prices by that ratio
            static arith_uint256 bigSatoshi(SATOSHIDEN);
            arith_uint256 bigMultipliedSupply(calculatedSupply * bigSatoshi);
            arith_uint256 newRatio(bigMultipliedSupply / curDef.initialFractionalSupply);
            // truncate up, not down, to prevent any overflow at all
            if (newRatio * curDef.initialFractionalSupply < bigMultipliedSupply)
            {
                newRatio++;
            }
            for (auto &rate : currencyState.conversionPrice)
            {
                arith_uint256 numerator = rate * newRatio;
                rate = (numerator / bigSatoshi).GetLow64();
                if ((numerator - (bigSatoshi * rate)) > 0)
                {
                    rate++;
                }
            }
        }

        /* calculatedSupply = 0;
        for (auto &transfer : unspentTransfers)
        {
            if (transfer.second.second.IsPreConversion())
            {
                CAmount toConvert = transfer.second.second.nValue - CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.nValue);
                calculatedSupply += CCurrencyState::ReserveToNativeRaw(toConvert, currencyState.conversionPrice[currencyIndexes[transfer.second.second.currencyID]]);
            }
        }
        printf("Calculated supply %s\n", ValueFromAmount(calculatedSupply).write().c_str()); */

        // now, remove carveout percentage from each weight & reserve
        // for currency state
        int32_t preLaunchCarveOutTotal = 0;
        for (auto &carveout : curDef.preLaunchCarveOuts)
        {
            preLaunchCarveOutTotal += carveout.second;
            
        }
        static arith_uint256 bigSatoshi(SATOSHIDEN);
        for (auto &oneReserve : currencyState.reserves)
        {
            oneReserve =  ((arith_uint256(oneReserve) * arith_uint256(SATOSHIDEN - preLaunchCarveOutTotal)) / bigSatoshi).GetLow64();
        }
        for (auto &oneWeight : currencyState.weights)
        {
            oneWeight = ((arith_uint256(oneWeight) * arith_uint256(CCurrencyDefinition::CalculateRatioOfValue((SATOSHIDEN - preLaunchCarveOutTotal), SATOSHIDEN - curDef.preLaunchDiscount))) / bigSatoshi).GetLow64();
        }
    }

    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(CCurrencyDefinition &curDef, int32_t height, int32_t curDefHeight)
{
    uint160 chainID = curDef.GetID();
    CCoinbaseCurrencyState currencyState;
    std::vector<CAddressIndexDbEntry> notarizationIndex;

    if (chainID == ASSETCHAINS_CHAINID)
    {
        currencyState = GetInitialCurrencyState(thisChain);
    }
    // if this is a token on this chain, it will be simply notarized
    else if (curDef.systemID == ASSETCHAINS_CHAINID || (curDef.launchSystemID == ASSETCHAINS_CHAINID && curDef.startBlock > height))
    {
        // get the last notarization in the height range for this currency, which is valid by definition for a token
        CPBaaSNotarization notarization;
        notarization.GetLastNotarization(chainID, EVAL_ACCEPTEDNOTARIZATION, curDefHeight, height);
        currencyState = notarization.currencyState;
        if (!currencyState.IsValid())
        {
            if (notarization.IsValid() && notarization.currencyStates.count(chainID))
            {
                currencyState = notarization.currencyStates[chainID];
            }
            else
            {
                currencyState = GetInitialCurrencyState(curDef);
                currencyState.SetPrelaunch();
            }
        }
        if (currencyState.IsValid() && notarization.notarizationHeight < (curDef.startBlock - 1))
        {
            // pre-launch
            currencyState.SetPrelaunch(true);
            currencyState = AddPrelaunchConversions(curDef, 
                                                    currencyState, 
                                                    notarization.IsValid() ? notarization.notarizationHeight : curDefHeight, 
                                                    height, 
                                                    curDefHeight);
        }
    }
    else
    {
        // we need to get the currency state of a currency not on this chain, so we look for the latest confirmed notarization
        // of that currency, and get it there
        CChainNotarizationData cnd;
        if (GetNotarizationData(chainID, cnd))
        {
            int32_t transfersFrom = curDefHeight;
            if (cnd.lastConfirmed != -1)
            {
                transfersFrom = cnd.vtx[cnd.lastConfirmed].second.notarizationHeight;
            }
            int32_t transfersUntil = cnd.lastConfirmed == -1 ? curDef.startBlock - 1 :
                                       (cnd.vtx[cnd.lastConfirmed].second.notarizationHeight < curDef.startBlock ?
                                        (height < curDef.startBlock ? height : curDef.startBlock - 1) :
                                        cnd.vtx[cnd.lastConfirmed].second.notarizationHeight);
            if (transfersUntil < curDef.startBlock)
            {
                // get chain transfers that should apply before the start block
                // until there is a post-start block notarization, we always consider the
                // currency state to be up to just before the start block
                std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> unspentTransfers;
                if (GetChainTransfers(unspentTransfers, chainID, transfersFrom, transfersUntil))
                {
                    // at this point, all pre-allocation, minted, and pre-converted currency are included
                    // in the currency state before final notarization
                    std::map<uint160, int32_t> currencyIndexes = currencyState.GetReserveMap();
                    if (curDef.IsFractional())
                    {
                        currencyState.supply = curDef.initialFractionalSupply;
                    }
                    else
                    {
                        // supply is determined by purchases * current conversion rate
                        currencyState.supply = currencyState.initialSupply;
                    }

                    for (auto &transfer : unspentTransfers)
                    {
                        if (transfer.second.second.IsPreConversion())
                        {
                            CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.FirstValue());

                            currencyState.reserveIn[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue();
                            curDef.preconverted[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue();
                            if (curDef.IsFractional())
                            {
                                currencyState.reserves[currencyIndexes[transfer.second.second.FirstCurrency()]] += transfer.second.second.FirstValue() - conversionFee;
                            }
                            else
                            {
                                currencyState.supply += CCurrencyState::ReserveToNativeRaw(transfer.second.second.FirstValue() - conversionFee, currencyState.PriceInReserve(currencyIndexes[transfer.second.second.FirstCurrency()]));
                            }

                            if (transfer.second.second.FirstCurrency() == curDef.systemID)
                            {
                                currencyState.nativeConversionFees += conversionFee;
                                currencyState.nativeFees += conversionFee + transfer.second.second.CalculateTransferFee(transfer.second.second.destination);
                            }
                            else
                            {
                                currencyState.fees[currencyIndexes[transfer.second.second.FirstCurrency()]] += 
                                            conversionFee + transfer.second.second.CalculateTransferFee(transfer.second.second.destination);
                                currencyState.conversionFees[currencyIndexes[transfer.second.second.FirstCurrency()]] += conversionFee;
                            }
                        }
                        else if (transfer.second.second.flags & CReserveTransfer::PREALLOCATE)
                        {
                            currencyState.emitted += transfer.second.second.FirstValue();
                        }
                    }
                    currencyState.supply += currencyState.emitted;
                    if (curDef.conversions.size() != curDef.currencies.size())
                    {
                        curDef.conversions = std::vector<int64_t>(curDef.currencies.size());
                    }
                    for (int i = 0; i < curDef.conversions.size(); i++)
                    {
                        currencyState.conversionPrice[i] = curDef.conversions[i] = currencyState.PriceInReserve(i);
                    }
                }
            }
            else
            {
                std::pair<CUTXORef, CPBaaSNotarization> notPair = cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed] : cnd.vtx[cnd.forks[cnd.bestChain][0]];
                currencyState = notPair.second.currencyState;
            }
        }
    }
    return currencyState;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(const uint160 &currencyID, int32_t height)
{
    int32_t curDefHeight;
    CCurrencyDefinition curDef;
    if (GetCurrencyDefinition(currencyID, curDef, &curDefHeight, true))
    {
        return GetCurrencyState(curDef, height, curDefHeight);
    }
    else
    {
        LogPrintf("%s: currency %s:%s not found\n", __func__, currencyID.GetHex().c_str(), EncodeDestination(CIdentityID(currencyID)).c_str());
        printf("%s: currency %s:%s not found\n", __func__, currencyID.GetHex().c_str(), EncodeDestination(CIdentityID(currencyID)).c_str());
    }
    return CCoinbaseCurrencyState();
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(int32_t height)
{
    return GetCurrencyState(thisChain.GetID(), height);
}

bool CConnectedChains::SetLatestMiningOutputs(const std::vector<CTxOut> &minerOutputs)
{
    LOCK(cs_mergemining);
    latestMiningOutputs = minerOutputs;
    return true;
}

CCurrencyDefinition CConnectedChains::GetCachedCurrency(const uint160 &currencyID)
{
    CCurrencyDefinition currencyDef;
    int32_t defHeight;
    auto it = currencyDefCache.find(currencyID);
    if ((it != currencyDefCache.end() && !(currencyDef = it->second).IsValid()) ||
        (it == currencyDefCache.end() && !GetCurrencyDefinition(currencyID, currencyDef, &defHeight, true)))
    {
        printf("%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
        LogPrintf("%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
        return currencyDef;
    }
    if (it == currencyDefCache.end())
    {
        currencyDefCache[currencyID] = currencyDef;
    }
    return currencyDefCache[currencyID];
}

CCurrencyDefinition CConnectedChains::UpdateCachedCurrency(const uint160 &currencyID, uint32_t height)
{
    // due to the main lock being taken on the thread that waits for transaction checks,
    // low level functions like this must be called either from a thread that holds LOCK(cs_main),
    // or script validation, where it is held either by this thread or one waiting for it.
    // in the long run, the daemon synchonrization model should be improved
    CCurrencyDefinition currencyDef = GetCachedCurrency(currencyID);
    CCoinbaseCurrencyState curState = GetCurrencyState(currencyDef, height);
    currencyDefCache[currencyID] = currencyDef;
    return currencyDef;
}


// returns all unspent chain exports for a specific chain/system, indexed by the actuall currency destination
bool CConnectedChains::GetUnspentSystemExports(const uint160 systemID, multimap<uint160, pair<int, CInputDescriptor>> &exportOutputs)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressUnspent(CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey()), CScript::P2IDX, unspentOutputs))
    {
        return false;
    }
    else
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                int i = it->first.index;
                if (coins.IsAvailable(i))
                {
                    // if this is an export output, optionally to this chain, add it to the input vector
                    COptCCParams p;
                    CCrossChainExport cx;
                    if (coins.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                        p.vData.size() && (cx = CCrossChainExport(p.vData[0])).IsValid())
                    {
                        exportOutputs.insert(make_pair(cx.destCurrencyID,
                                                    make_pair(coins.nHeight, CInputDescriptor(coins.vout[i].scriptPubKey, coins.vout[i].nValue, CTxIn(COutPoint(it->first.txhash, i))))));
                    }
                }
            }
            else
            {
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        return true;
    }
}


// returns all unspent chain exports for a specific chain/currency
bool CConnectedChains::GetUnspentCurrencyExports(const CCoinsViewCache &view, 
                                                 const uint160 currencyID, 
                                                 std::vector<pair<int, CInputDescriptor>> &exportOutputs)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> exportUTXOs;

    std::vector<pair<int, CInputDescriptor>> exportOuts;

    LOCK2(cs_main, mempool.cs);

    uint160 exportIndexKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey());

    if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{exportIndexKey, CScript::P2IDX}}), exportUTXOs) &&
        exportUTXOs.size())
    {
        // we need to remove those that are spent
        std::map<COutPoint, CInputDescriptor> memPoolOuts;
        for (auto &oneExport : exportUTXOs)
        {
            if (oneExport.first.spending)
            {
                memPoolOuts.erase(COutPoint(oneExport.first.txhash, oneExport.first.index));
            }
            else
            {
                const CTransaction oneTx = mempool.mapTx.find(oneExport.first.txhash)->GetTx();
                memPoolOuts.insert(std::make_pair(COutPoint(oneExport.first.txhash, oneExport.first.index),
                                                CInputDescriptor(oneTx.vout[oneExport.first.index].scriptPubKey, oneExport.second.amount, 
                                                            CTxIn(oneExport.first.txhash, oneExport.first.index))));
            }
        }

        for (auto &oneUTXO : memPoolOuts)
        {
            exportOuts.push_back(std::make_pair(0, oneUTXO.second));
        }
    }
    if (!exportOuts.size() &&
        !GetAddressUnspent(exportIndexKey, CScript::P2IDX, unspentOutputs))
    {
        return false;
    }
    else
    {
        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            exportOuts.push_back(std::make_pair(it->second.blockHeight, CInputDescriptor(it->second.script, it->second.satoshis, 
                                                            CTxIn(it->first.txhash, it->first.index))));
        }
    }
    exportOutputs.insert(exportOutputs.end(), exportOuts.begin(), exportOuts.end());
    return exportOuts.size() != 0;
}


bool CConnectedChains::GetPendingCurrencyExports(const uint160 currencyID,
                                                 uint32_t fromHeight,
                                                 std::vector<pair<int, CInputDescriptor>> &exportOutputs)
{
    CCurrencyDefinition chainDef;
    int32_t defHeight;
    exportOutputs.clear();

    if (GetCurrencyDefinition(currencyID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        CChainNotarizationData cnd;
        if (GetNotarizationData(currencyID, cnd))
        {
            uint160 exportKey = CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey());

            // get all export transactions including and since this one up to the confirmed cross-notarization
            if (GetAddressIndex(exportKey, CScript::P2IDX, addressIndex, fromHeight))
            {
                for (auto &idx : addressIndex)
                {
                    uint256 blkHash;
                    CTransaction exportTx;
                    if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
                    {
                        std::vector<CBaseChainObject *> opretTransfers;
                        CCrossChainExport ccx;
                        if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid())
                        {
                            exportOutputs.push_back(std::make_pair(idx.first.blockHeight, 
                                                                               CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                                exportTx.vout[idx.first.index].nValue,
                                                                                                CTxIn(idx.first.txhash, idx.first.index))));
                        }
                    }
                }
            }
        }
        return true;
    }
    else
    {
        LogPrintf("%s: unrecognized chain name or chain ID\n", __func__);
        return false;
    }
}


CPartialTransactionProof::CPartialTransactionProof(const CTransaction tx, const std::vector<int32_t> outputNums, const CBlockIndex *pIndex, uint32_t proofAtHeight)
{
    // get map and MMR for transaction
    CTransactionMap txMap(tx);
    TransactionMMView txView(txMap.transactionMMR);
    uint256 txRoot = txView.GetRoot();

    std::vector<CTransactionComponentProof> txProofVec;
    txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_HEADER, 0));
    for (auto oneOutNum : outputNums)
    {
        txProofVec.push_back(CTransactionComponentProof(txView, txMap, tx, CTransactionHeader::TX_OUTPUT, oneOutNum));
    }

    // now, both the header and stake output are dependent on the transaction MMR root being provable up
    // through the block MMR, and since we don't cache the new MMR proof for transactions yet, we need the block to create the proof.
    // when we switch to the new MMR in place of a merkle tree, we can keep that in the wallet as well
    CBlock block;
    if (!ReadBlockFromDisk(block, pIndex, Params().GetConsensus(), false))
    {
        LogPrintf("%s: ERROR: could not read block number %u from disk\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    BlockMMRange blockMMR(block.GetBlockMMRTree());
    BlockMMView blockView(blockMMR);

    int txIndexPos;
    for (txIndexPos = 0; txIndexPos < blockMMR.size(); txIndexPos++)
    {
        uint256 txRootHashFromMMR = blockMMR[txIndexPos].hash;
        if (txRootHashFromMMR == txRoot)
        {
            //printf("tx with root %s found in block\n", txRootHashFromMMR.GetHex().c_str());
            break;
        }
    }

    if (txIndexPos == blockMMR.size())
    {
        LogPrintf("%s: ERROR: could not find transaction root in block %u\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    // prove the tx up to the MMR root, which also contains the block hash
    CMMRProof txRootProof;
    if (!blockView.GetProof(txRootProof, txIndexPos))
    {
        LogPrintf("%s: ERROR: could not create proof of source transaction in block %u\n", __func__, pIndex->GetHeight());
        version = VERSION_INVALID;
        return;
    }

    ChainMerkleMountainView mmv = chainActive.GetMMV();
    mmv.resize(proofAtHeight);
    chainActive.GetMerkleProof(mmv, txRootProof, pIndex->GetHeight());
    *this = CPartialTransactionProof(txRootProof, txProofVec);
}


// given exports on this chain, provide the proofs of those export outputs with the MMR root at height "height"
// proofs are added in place
bool CConnectedChains::GetExportProofs(uint32_t height,
                                       std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports)
{
    // fill in proofs of the export outputs for each export at the specified height
    ChainMerkleMountainView mmv = chainActive.GetMMV();
    mmv.resize(height);

    CBlock proofBlock;

    for (auto &oneExport : exports)
    {
        uint256 blockHash;
        CTransaction exportTx;
        if (!myGetTransaction(oneExport.first.first.txIn.prevout.hash, exportTx, blockHash))
        {
            LogPrintf("%s: unable to retrieve export %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        CCrossChainExport ccx(exportTx.vout[oneExport.first.first.txIn.prevout.n].scriptPubKey);
        if (!ccx.IsValid())
        {
            LogPrintf("%s: invalid export on %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        if (blockHash.IsNull())
        {
            LogPrintf("%s: cannot get proof for unconfirmed export %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        auto blockIt = mapBlockIndex.find(blockHash);
        if (blockIt == mapBlockIndex.end() || !chainActive.Contains(blockIt->second))
        {
            LogPrintf("%s: cannot validate block of export tx %s\n", __func__, oneExport.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }
        oneExport.first.second = CPartialTransactionProof(exportTx, 
                                                          std::vector<int32_t>({(int32_t)oneExport.first.first.txIn.prevout.n}), 
                                                          blockIt->second, 
                                                          height);
    }
    return true;
}

bool CConnectedChains::GetReserveDeposits(const uint160 &currencyID, const CCoinsViewCache &view, std::vector<CInputDescriptor> &reserveDeposits)
{
    std::vector<CAddressUnspentDbEntry> confirmedUTXOs;
    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> unconfirmedUTXOs;

    CCoins coin;

    uint160 depositIndexKey = CReserveDeposit::ReserveDepositIndexKey(currencyID);
    if (!GetAddressUnspent(depositIndexKey, CScript::P2IDX, confirmedUTXOs) ||
        !mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{depositIndexKey, CScript::P2IDX}}), unconfirmedUTXOs))
    {
        LogPrintf("%s: Cannot read address indexes\n", __func__);
        return false;
    }
    for (auto &oneConfirmed : confirmedUTXOs)
    {
        if (view.GetCoins(oneConfirmed.first.txhash, coin) && coin.IsAvailable(oneConfirmed.first.index))
        {
            reserveDeposits.push_back(CInputDescriptor(oneConfirmed.second.script, oneConfirmed.second.satoshis, 
                                                        CTxIn(oneConfirmed.first.txhash, oneConfirmed.first.index)));
        }
    }

    // we need to remove those that are spent
    std::map<COutPoint, CInputDescriptor> memPoolOuts;
    for (auto &oneUnconfirmed : unconfirmedUTXOs)
    {
        if (!oneUnconfirmed.first.spending &&
            view.GetCoins(oneUnconfirmed.first.txhash, coin) && 
            coin.IsAvailable(oneUnconfirmed.first.index))
        {
            const CTransaction oneTx = mempool.mapTx.find(oneUnconfirmed.first.txhash)->GetTx();
            reserveDeposits.push_back(CInputDescriptor(oneTx.vout[oneUnconfirmed.first.index].scriptPubKey, oneUnconfirmed.second.amount, 
                                                        CTxIn(oneUnconfirmed.first.txhash, oneUnconfirmed.first.index)));
        }
    }
    return true;
}

// given a set of exports and the reserve deposits for this from another chain, create a set of import transactions
bool CConnectedChains::CreateLatestImports(const CCurrencyDefinition &sourceSystemDef,                      // transactions imported from system
                                           const CUTXORef &confirmedSourceNotarization,                     // last notarization of exporting system
                                           const std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                           std::map<uint160, std::vector<std::pair<int, CTransaction>>> &newImports)
{
    // each export is from the source system, but may be to any currency exposed on this system, so each import
    // made combines the potential currency sources of the source system and the importing currency
    LOCK2(cs_main, mempool.cs);

    CCoinsView dummy;
    CCoinsViewCache view(&dummy);
    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    view.SetBackend(viewMemPool);

    uint32_t nHeight = chainActive.Height();
    uint160 sourceSystemID = sourceSystemDef.GetID();
    bool useProofs = sourceSystemID != thisChain.GetID();

    CPBaaSNotarization proofNotarization;
    if (useProofs)
    {
        CTransaction proofNotarizationTx;
        uint256 blkHash;
        COptCCParams p;
        if (confirmedSourceNotarization.hash.IsNull() ||
            !myGetTransaction(confirmedSourceNotarization.hash, proofNotarizationTx, blkHash) ||
            confirmedSourceNotarization.n >= proofNotarizationTx.vout.size() || 
            !proofNotarizationTx.vout[confirmedSourceNotarization.n].scriptPubKey.IsPayToCryptoCondition(p) ||
            !p.IsValid() ||
            (p.evalCode != EVAL_ACCEPTEDNOTARIZATION && p.evalCode != EVAL_EARNEDNOTARIZATION) ||
            !p.vData.size() ||
            !(proofNotarization = CPBaaSNotarization(p.vData[0])).IsValid() ||
            !proofNotarization.proofRoots.count(sourceSystemID))
        {
            LogPrintf("%s: invalid notarization for export proof\n", __func__);
            return false;
        }
    }

    for (auto &oneIT : exports)
    {
        uint256 blkHash;
        CTransaction exportTx;
        if (useProofs)
        {
            if (!oneIT.first.second.IsValid())
            {
                LogPrintf("%s: invalid proof for export tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
            uint256 exportTxID = oneIT.first.second.GetPartialTransaction(exportTx);

            if (oneIT.first.second.GetBlockHeight() &&
                proofNotarization.proofRoots[sourceSystemID].stateRoot != oneIT.first.second.CheckPartialTransaction(exportTx))
            {
                LogPrintf("%s: export tx %s fails verification\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }

            if (exportTx.vout.size() <= oneIT.first.first.txIn.prevout.n)
            {
                LogPrintf("%s: invalid proof for export tx output %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
        }
        else
        {
            if (!myGetTransaction(oneIT.first.first.txIn.prevout.hash, exportTx, blkHash))
            {
                LogPrintf("%s: unable to retrieve export tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
        }

        const CCrossChainExport ccx(exportTx.vout[oneIT.first.first.txIn.prevout.n].scriptPubKey);
        if (!ccx.IsValid())
        {
            LogPrintf("%s: invalid export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }

        // if we have inputs, break
        if (ccx.numInputs)
        {
            printf("%s:break for debugger on import for export: %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
        }

        // get reserve deposits for destination currency of export. these will be available whether the source is same chain
        // or an external chain/gateway
        std::vector<CInputDescriptor> localDeposits;
        std::vector<CInputDescriptor> crossChainDeposits;
        if (!ConnectedChains.GetReserveDeposits(ccx.destCurrencyID, view, localDeposits))
        {
            LogPrintf("%s: cannot get reserve deposits for export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
            return false;
        }

        // if importing from another system/chain, get reserve deposits of source system to make available to import
        // as well
        if (useProofs)
        {
            if (!ConnectedChains.GetReserveDeposits(sourceSystemID, view, crossChainDeposits))
            {
                LogPrintf("%s: cannot get reserve deposits for cross-system export in tx %s\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str());
                return false;
            }
        }

        // now, we have all reserve deposits for both local destination and importing currency, we can use both, 
        // but must keep track of them separately, first, get last import for the current export
        CTransaction lastImportTx;
        int32_t outputNum;
        CCrossChainImport lastCCI;
        uint256 lastImportTxID;

        auto lastImportIt = newImports.find(ccx.destCurrencyID);
        if (lastImportIt != newImports.end())
        {
            lastImportTx = lastImportIt->second.back().second;
            outputNum = lastImportIt->second.back().first;
            lastCCI = CCrossChainImport(lastImportTx.vout[outputNum].scriptPubKey);
            lastImportTxID = lastImportTx.GetHash();
        }
        else if (nHeight && !GetLastImport(ccx.destCurrencyID, lastImportTx, outputNum))
        {
            LogPrintf("%s: cannot find last import for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            return false;
        }
        else if (nHeight)
        {
            lastCCI = CCrossChainImport(lastImportTx.vout[outputNum].scriptPubKey);
            lastImportTxID = lastImportTx.GetHash();
        }
        
        CCurrencyDefinition destCur = ConnectedChains.GetCachedCurrency(ccx.destCurrencyID);
        if (!lastCCI.IsValid() || !destCur.IsValid())
        {
            LogPrintf("%s: invalid destination currency for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            return false;
        }

        // now, we have:
        // 1. last import output + potentially additional reserve transfer storage outputs to spend from prior import
        // 2. reserve transfers for next import
        // 3. proof notarization if export is from off chain
        // 4. reserve deposits for destination currency on this chain. which will matter if it holds reserves
        // 5. reserve deposits for source system, which will matter if we have sent currencies to it that will be used
        // 6. destination currency definition

        // either:
        // 1) it is a gateway on our current chain, and we are creating imports for the system represented by the gateway from this system
        //    or we are importing into this system from the gateway system
        // 2) we are creating an import for a fractional currency on this chain, or
        // 3) destination is a PBaaS currency, which is either the native currency, if we are the PBaaS chain or a token on our current chain.
        //    We are creating imports for this system, which is the PBaaS chain, to receive exports from our notary chain, which is its parent, 
        //    or we are creating imports to receive exports from the PBaaS chain.
        if (!((destCur.IsGateway() && destCur.systemID == ASSETCHAINS_CHAINID) && 
                (sourceSystemID == ASSETCHAINS_CHAINID || sourceSystemID == ccx.destCurrencyID)) &&
            !(sourceSystemID == destCur.systemID && destCur.systemID == ASSETCHAINS_CHAINID) &&
            !(destCur.IsPBaaSChain() &&
                (sourceSystemID == ccx.destCurrencyID ||
                  (ccx.destCurrencyID == ASSETCHAINS_CHAINID && 
                   sourceSystemID == ConnectedChains.FirstNotaryChain().chainDefinition.GetID()))))
        {
            LogPrintf("%s: invalid currency for export/import %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), outputNum);
            return false;
        }

        // now, if we are creating an import for an external export, spend and output the import thread for that external system to make it
        // easy to find the last import for any external system and confirm that we are also not skipping any exports
        CTransaction lastSourceImportTx;
        int32_t sourceOutputNum;
        CCrossChainImport lastSourceCCI;
        uint256 lastSourceImportTxID;

        // if we are importing from another system, find the last import from that system and consider this another one
        if (useProofs)
        {
            auto lastSourceImportIt = newImports.find(ccx.sourceSystemID);
            if (lastSourceImportIt != newImports.end())
            {
                lastSourceImportTx = lastSourceImportIt->second.back().second;
                sourceOutputNum = lastSourceImportIt->second.back().first;
                lastSourceCCI = CCrossChainImport(lastSourceImportTx.vout[sourceOutputNum].scriptPubKey);
                lastSourceImportTxID = lastSourceImportTx.GetHash();
            }
            else if (nHeight && !GetLastImport(ccx.sourceSystemID, lastSourceImportTx, sourceOutputNum))
            {
                LogPrintf("%s: cannot find last system import for export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), sourceOutputNum);
                return false;
            }
            else if (nHeight)
            {
                lastSourceCCI = CCrossChainImport(lastSourceImportTx.vout[sourceOutputNum].scriptPubKey);
                lastSourceImportTxID = lastSourceImportTx.GetHash();
            }
        }

        CPBaaSNotarization lastNotarization;
        CInputDescriptor lastNotarizationOut;
        std::vector<CReserveTransfer> lastReserveTransfers;
        CCrossChainExport lastCCX;
        CCrossChainImport lastSysCCI;
        int32_t sysCCIOutNum = -1, evidenceOutNumStart = -1, evidenceOutNumEnd = -1;

        int32_t notarizationOutNum;
        CValidationState state;

        uint160 destCurID = destCur.GetID();

        // if not the initial import in the thread, it should have a valid prior notarization as well
        // the notarization of the initial import may be superceded by pre-launch exports
        if (nHeight && lastCCI.IsPostLaunch())
        {
            if (!lastCCI.GetImportInfo(lastImportTx,
                                       outputNum,
                                       lastCCX,
                                       lastSysCCI,
                                       sysCCIOutNum,
                                       lastNotarization,
                                       notarizationOutNum,
                                       evidenceOutNumStart,
                                       evidenceOutNumEnd,
                                       lastReserveTransfers,
                                       state))
            {
                LogPrintf("%s: %u - %s\n", __func__, destCur.name.c_str(), state.GetRejectCode(), state.GetRejectReason().c_str());
                return false;
            }

            lastNotarizationOut = CInputDescriptor(lastImportTx.vout[notarizationOutNum].scriptPubKey,
                                                   lastImportTx.vout[notarizationOutNum].nValue,
                                                   CTxIn(lastImportTxID, notarizationOutNum));

            // verify that the current export from the source system spends the prior export from the source system
            if (useProofs &&
                !(ccx.firstInput > 0 &&
                  exportTx.vin[ccx.firstInput - 1].prevout.hash == lastSysCCI.exportTxId &&
                  exportTx.vin[ccx.firstInput - 1].prevout.n == lastSysCCI.exportTxOutNum))
            {
                LogPrintf("%s: out of order export %s, %d\n", __func__, oneIT.first.first.txIn.prevout.hash.GetHex().c_str(), sourceOutputNum);
                return false;
            }
        }
        else if (nHeight)
        {
            // the first import ever cannot be on a chain that is already running and is not the same chain
            // as the first export processed. it is either launched from the launch chain, which is running
            // or as a new chain, started from a different launch chain.
            if (useProofs)
            {
                LogPrintf("%s: invalid first import for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                return false;
            }

            // first import, but not first block, so not PBaaS launch - last import has no evidence to spend
            CChainNotarizationData cnd;
            std::vector<std::pair<CTransaction, uint256>> notarizationTxes;
            if (!GetNotarizationData(ccx.destCurrencyID, cnd, &notarizationTxes) || !cnd.IsConfirmed())
            {
                LogPrintf("%s: cannot get notarization for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                return false;
            }

            lastNotarization = cnd.vtx[cnd.lastConfirmed].second;
            if (!lastNotarization.IsValid())
            {
                LogPrintf("%s: invalid notarization for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
                return false;
            }
            lastNotarizationOut = CInputDescriptor(notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].scriptPubKey,
                                                   notarizationTxes[cnd.lastConfirmed].first.vout[cnd.vtx[cnd.lastConfirmed].first.n].nValue,
                                                   CTxIn(cnd.vtx[cnd.lastConfirmed].first));
        }
        else // height is 0 - this is first block of PBaaS chain
        {
            if (!(proofNotarization.currencyID == ccx.destCurrencyID || proofNotarization.currencyStates.count(ccx.destCurrencyID)))
            {
                // last notarization is coming from the launch chain at height 0
                lastNotarization = CPBaaSNotarization(ccx.destCurrencyID,
                                                      proofNotarization.currencyID == 
                                                        ccx.destCurrencyID ? proofNotarization.currencyState : 
                                                                             proofNotarization.currencyStates[ccx.destCurrencyID],
                                                      0,
                                                      CUTXORef(),
                                                      0);
                lastNotarizationOut = CInputDescriptor(CScript(), 0, CTxIn());
            }
        }

        CPBaaSNotarization newNotarization;
        uint256 transferHash;
        std::vector<CReserveTransfer> exportTransfers = oneIT.second;
        std::vector<CTxOut> newOutputs;
        CCurrencyValueMap importedCurrency, gatewayDepositsUsed, spentCurrencyOut;
        // if we are transitioning from export to import, allow the function to set launch clear on the currency
        if (lastNotarization.currencyState.IsLaunchClear() && !lastCCI.IsInitialLaunchImport())
        {
            lastNotarization.SetPreLaunch();
            lastNotarization.currencyState.SetLaunchClear(false);
            lastNotarization.currencyState.SetPrelaunch(true);
        }
        else if (lastCCI.IsInitialLaunchImport())
        {
            lastNotarization.SetPreLaunch(false);
            lastNotarization.currencyState.SetPrelaunch(false);
            lastNotarization.currencyState.SetLaunchClear(false);
        }

        uint32_t nextHeight = std::max(ccx.sourceHeightEnd, lastNotarization.notarizationHeight);
        if (ccx.IsPostlaunch())
        {
            lastNotarization.currencyState.SetLaunchCompleteMarker();
        }

        if (!lastNotarization.NextNotarizationInfo(sourceSystemDef,
                                                   destCur,
                                                   ccx.sourceHeightStart,
                                                   std::max(ccx.sourceHeightEnd, lastNotarization.notarizationHeight),
                                                   exportTransfers,
                                                   transferHash,
                                                   newNotarization,
                                                   newOutputs,
                                                   importedCurrency,
                                                   gatewayDepositsUsed,
                                                   spentCurrencyOut))
        {
            LogPrintf("%s: invalid export for currency %s on system %s\n", __func__, destCur.name.c_str(), EncodeDestination(CIdentityID(destCur.systemID)).c_str());
            return false;
        }
        newNotarization.prevNotarization = CUTXORef(lastNotarizationOut.txIn.prevout.hash, lastNotarizationOut.txIn.prevout.n);

        //printf("%s: newNotarization:\n%s\n", __func__, newNotarization.ToUniValue().write(1,2).c_str());

        // create the import
        CCrossChainImport cci = CCrossChainImport(sourceSystemID,
                                                  ccx.sourceHeightEnd,
                                                  destCurID,
                                                  ccx.totalAmounts,
                                                  lastCCI.totalReserveOutMap,
                                                  newOutputs.size(),
                                                  transferHash, 
                                                  oneIT.first.first.txIn.prevout.hash, 
                                                  oneIT.first.first.txIn.prevout.n,
                                                  CCrossChainImport::FLAG_POSTLAUNCH + (lastCCI.IsDefinitionImport() ? CCrossChainImport::FLAG_INITIALLAUNCHIMPORT : 0));
        cci.SetSameChain(!useProofs);

        TransactionBuilder tb = TransactionBuilder(Params().GetConsensus(), nHeight + 1);

        CCcontract_info CC;
        CCcontract_info *cp;

        // now add the import itself
        cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci)), 0);

        // get the source system import as well
        CCrossChainImport sysCCI;
        if (useProofs)
        {
            // we need a new import for the source system
            sysCCI = cci;
            sysCCI.importCurrencyID = sysCCI.sourceSystemID;
            sysCCI.flags |= sysCCI.FLAG_SOURCESYSTEM;
            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &sysCCI)), 0);
        }

        // add notarization first, so it will be just after the import
        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
        tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization)), 0);

        // add the export evidence, null for same chain or reference specific notarization + (proof + reserve transfers) if sourced from external chain
        // add evidence first, then notarization, then import, add reserve deposits after that, if necessary

        if (useProofs)
        {
            // if we need to put the partial transaction proof and follow it with reserve transfers, do it
            CNotaryEvidence evidence = CNotaryEvidence(destCurID,
                                                       CUTXORef(confirmedSourceNotarization.hash, confirmedSourceNotarization.n),
                                                       true,
                                                       std::map<CIdentityID, CIdentitySignature>(),
                                                       std::vector<CPartialTransactionProof>({oneIT.first.second}),
                                                       CNotaryEvidence::TYPE_PARTIAL_TXPROOF);

            // add notarization first, so it will be after the import
            cp = CCinit(&CC, EVAL_NOTARY_EVIDENCE);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CNotaryEvidence>(EVAL_NOTARY_EVIDENCE, dests, 1, &evidence)),
                                    CNotaryEvidence::DEFAULT_OUTPUT_VALUE);

            // supplemental export evidence is posted as a supplemental export
            cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
            dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

            // now add all reserve transfers in supplemental outputs
            auto transferIT = exportTransfers.begin();
            while (transferIT != exportTransfers.end())
            {
                int transferCount = exportTransfers.end() - transferIT;
                if (transferCount > 25)
                {
                    transferCount = 25;
                }

                CCrossChainExport rtSupplement = ccx;
                rtSupplement.flags = ccx.FLAG_EVIDENCEONLY + ccx.FLAG_SUPPLEMENTAL;
                rtSupplement.reserveTransfers.assign(transferIT, transferIT + transferCount);
                CScript supScript = MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &rtSupplement));
                while (supScript.size() > supScript.MAX_SCRIPT_ELEMENT_SIZE)
                {
                    transferCount--;
                    rtSupplement.reserveTransfers.assign(transferIT, transferIT + transferCount);
                    supScript = MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &rtSupplement));
                }
                tb.AddTransparentOutput(supScript, 0);
                transferIT += transferCount;
            }
        }

        // add all importing and conversion outputs
        for (auto oneOut : newOutputs)
        {
            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
        }

        // now, we need to spend previous import, notarization, and evidence or export finalization from export

        // spend evidence or export finalization if necessary
        // if we use proofs, spend the prior, unless we have no prior proofs to spend
        if (lastCCI.IsValid() && !lastImportTxID.IsNull())
        {
            // spend last import
            tb.AddTransparentInput(COutPoint(lastImportTxID, outputNum), lastImportTx.vout[outputNum].scriptPubKey, lastImportTx.vout[outputNum].nValue);

            // if we should add a source import input
            if (useProofs)
            {
                tb.AddTransparentInput(COutPoint(lastSourceImportTxID, sourceOutputNum), 
                                       lastSourceImportTx.vout[sourceOutputNum].scriptPubKey, lastSourceImportTx.vout[sourceOutputNum].nValue);
            }

            if (!lastNotarizationOut.txIn.prevout.hash.IsNull())
            {
                // and its notarization
                tb.AddTransparentInput(lastNotarizationOut.txIn.prevout, lastNotarizationOut.scriptPubKey, lastNotarizationOut.nValue);
            }

            if (useProofs)
            {
                for (int i = evidenceOutNumStart; i <= evidenceOutNumEnd; i++)
                {
                    tb.AddTransparentInput(COutPoint(lastImportTxID, i), lastImportTx.vout[i].scriptPubKey, lastImportTx.vout[i].nValue);
                }
            }
            else
            {
                // if same chain and export has a finalization, spend it on import
                CObjectFinalization of;
                COptCCParams p;
                if (exportTx.vout.size() > (oneIT.first.first.txIn.prevout.n + 1) &&
                    exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_FINALIZE_EXPORT &&
                    p.vData.size() &&
                    (of = CObjectFinalization(p.vData[0])).IsValid())
                {
                    tb.AddTransparentInput(COutPoint(oneIT.first.first.txIn.prevout.hash, oneIT.first.first.txIn.prevout.n + 1), 
                                                        exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].scriptPubKey, 
                                                        exportTx.vout[oneIT.first.first.txIn.prevout.n + 1].nValue);
                }
            }
        }

        // now, get all reserve deposits and change for both gateway reserve deposits and local reserve deposits
        CCurrencyValueMap gatewayChange;

        // add gateway deposit inputs and make a change output for those to the source system's deposits, if necessary
        std::vector<CInputDescriptor> depositsToUse;
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});

        if (gatewayDepositsUsed.valueMap.size())
        {
            CCurrencyValueMap totalDepositsInput;

            // find all deposits intersecting with target currencies
            for (auto &oneDeposit : crossChainDeposits)
            {
                CCurrencyValueMap oneDepositVal = oneDeposit.scriptPubKey.ReserveOutValue();
                if (oneDeposit.nValue)
                {
                    oneDepositVal.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
                }
                if (gatewayDepositsUsed.Intersects(oneDepositVal))
                {
                    totalDepositsInput += oneDepositVal;
                    depositsToUse.push_back(oneDeposit);
                }
            }

            gatewayChange = totalDepositsInput - gatewayDepositsUsed;

            // we should always be able to fulfill
            // gateway despoit requirements, or this is an error
            if (gatewayChange.HasNegative())
            {
                LogPrintf("%s: insufficient funds for gateway reserve deposits from system %s\n", __func__, EncodeDestination(CIdentityID(ccx.sourceSystemID)).c_str());
                return false;
            }
        }

        // the amount being imported is under the control of the exporting system and
        // will either be minted by the import from that system or spent on this chain from its reserve deposits
        // any remaining unmet output requirements must be met by local chain deposits as a result of conversions
        // conversion outputs may only be of the destination currency itself, or in the case of a fractional currency, 
        // the currency or its reserves.
        //
        // if this is a local import, local requirements are any spent currency besides
        //
        // change will all accrue to reserve deposits
        //

        // first determine total deposits required to fulfill currency in requirements
        // this will take fees into account, which do not intersect with other currencies
        CCurrencyValueMap requiredDeposits;

        if (!newNotarization.currencyState.IsLaunchConfirmed() || newNotarization.currencyState.IsLaunchCompleteMarker())
        {
            requiredDeposits = cci.importValue;
        }

        // we must also come up with anything spent that is not satisfied via standard required deposits, 
        // as determined by reserves in. any excess in required deposits beyond what is spent will go to
        // reserve deposits change
        requiredDeposits += spentCurrencyOut.SubtractToZero(requiredDeposits);

        CCurrencyValueMap newCurrencyIn = gatewayDepositsUsed + importedCurrency;
        CCurrencyValueMap localDepositRequirements = requiredDeposits.SubtractToZero(newCurrencyIn);
        CCurrencyValueMap localDepositChange;

        /*
        printf("%s: spentcurrencyout: %s\n", __func__, spentCurrencyOut.ToUniValue().write(1,2).c_str());
        printf("%s: requireddeposits: %s\n", __func__, requiredDeposits.ToUniValue().write(1,2).c_str());
        printf("%s: newcurrencyin: %s\n", __func__, newCurrencyIn.ToUniValue().write(1,2).c_str());
        printf("%s: localdepositrequirements: %s\n", __func__, localDepositRequirements.ToUniValue().write(1,2).c_str());
        */

        // add local reserve deposit inputs and determine change
        if (localDepositRequirements.valueMap.size())
        {
            CCurrencyValueMap totalDepositsInput;

            // find all deposits intersecting with target currencies
            for (auto &oneDeposit : localDeposits)
            {
                CCurrencyValueMap oneDepositVal = oneDeposit.scriptPubKey.ReserveOutValue();
                if (oneDeposit.nValue)
                {
                    oneDepositVal.valueMap[ASSETCHAINS_CHAINID] = oneDeposit.nValue;
                }
                if (localDepositRequirements.Intersects(oneDepositVal))
                {
                    totalDepositsInput += oneDepositVal;
                    depositsToUse.push_back(oneDeposit);
                }
            }

            localDepositChange = totalDepositsInput - localDepositRequirements;

            // we should always be able to fulfill
            // local despoit requirements, or this is an error
            if (localDepositChange.HasNegative())
            {
                LogPrintf("%s: insufficient funds for local reserve deposits for currency %s, have:\n%s, need:\n%s\n", 
                          __func__, 
                          EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(),
                          totalDepositsInput.ToUniValue().write(1,2).c_str(),
                          localDepositRequirements.ToUniValue().write(1,2).c_str());
                return false;
            }
        }

        // add local deposit inputs
        for (auto oneOut : depositsToUse)
        {
            tb.AddTransparentInput(oneOut.txIn.prevout, oneOut.scriptPubKey, oneOut.nValue);
        }

        /*
        for (auto &oneIn : tb.mtx.vin)
        {
            UniValue scriptObj(UniValue::VOBJ);
            printf("%s: oneInput - hash: %s, n: %d\n", __func__, oneIn.prevout.hash.GetHex().c_str(), oneIn.prevout.n);
        }
        */

        // we will keep reserve deposit change to single currency outputs to ensure aggregation of like currencies and
        // prevent fragmentation edge cases
        for (auto &oneChangeVal : gatewayChange.valueMap)
        {
            // dust rules don't apply
            if (oneChangeVal.second)
            {
                CReserveDeposit rd = CReserveDeposit(sourceSystemID, CCurrencyValueMap());;
                CAmount nativeOutput = 0;
                if (oneChangeVal.first == ASSETCHAINS_CHAINID)
                {
                    nativeOutput = oneChangeVal.second;
                }
                else
                {
                    rd.reserveValues.valueMap[oneChangeVal.first] = oneChangeVal.second;
                }
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd)), nativeOutput);
            }
        }

        // we will keep reserve deposit change to single currency outputs to ensure aggregation of like currencies and
        // prevent fragmentation edge cases
        for (auto &oneChangeVal : localDepositChange.valueMap)
        {
            // dust rules don't apply
            if (oneChangeVal.second)
            {
                CReserveDeposit rd = CReserveDeposit(ccx.destCurrencyID, CCurrencyValueMap());;
                CAmount nativeOutput = 0;
                if (oneChangeVal.first == ASSETCHAINS_CHAINID)
                {
                    nativeOutput = oneChangeVal.second;
                }
                else
                {
                    rd.reserveValues.valueMap[oneChangeVal.first] = oneChangeVal.second;
                }
                tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd)), nativeOutput);
            }
        }

        CCurrencyValueMap reserveInMap = CCurrencyValueMap(newNotarization.currencyState.currencies, 
                                                           newNotarization.currencyState.reserveIn).CanonicalMap();

        // ins and outs are correct. now calculate the fee correctly here and set the transaction builder accordingly
        // to prevent an automatic change output. we could just let it go and hae a setting to stop creation of a change output,
        // but this is a nice doublecheck requirement
        /* printf("%s: reserveInMap:\n%s\nspentCurrencyOut:\n%s\nrequiredDeposits:\n%s\nccx.totalAmounts:\n%s\nccx.totalFees:\n%s\n",
                __func__,
                reserveInMap.ToUniValue().write(1,2).c_str(),
                spentCurrencyOut.ToUniValue().write(1,2).c_str(),
                requiredDeposits.ToUniValue().write(1,2).c_str(),
                ccx.totalAmounts.ToUniValue().write(1,2).c_str(),
                ccx.totalFees.ToUniValue().write(1,2).c_str()); */

        // pay the fee out to the miner
        CReserveTransactionDescriptor rtxd(tb.mtx, view, nHeight);
        tb.SetFee(rtxd.nativeIn - rtxd.nativeOut);

        // if we've got launch currency as the fee, it means we are mining block 1
        // send it to our current miner or notary address
        if (!ccx.IsSameChain() && ccx.IsClearLaunch())
        {
            CTxDestination addr;
            extern std::string NOTARY_PUBKEY;
            if (mapArgs.count("-mineraddress"))
            {
                addr = DecodeDestination(mapArgs["-mineraddress"]);
            }
            else if (!VERUS_NOTARYID.IsNull())
            {
                addr = VERUS_NOTARYID;
            }
            else if (!VERUS_DEFAULTID.IsNull())
            {
                addr = VERUS_DEFAULTID;
            }
            else if (!VERUS_NODEID.IsNull())
            {
                addr = CIdentityID(VERUS_NODEID);
            }
            else if (!NOTARY_PUBKEY.empty())
            {
                CPubKey pkey;
                std::vector<unsigned char> hexKey = ParseHex(NOTARY_PUBKEY);
                pkey.Set(hexKey.begin(), hexKey.end());
                addr = pkey.GetID();
            }
            tb.SendChangeTo(addr);
        }

        TransactionBuilderResult result = tb.Build();
        if (result.IsError())
        {
            //UniValue jsonTx(UniValue::VOBJ);
            //uint256 hashBlk;
            //TxToUniv(tb.mtx, hashBlk, jsonTx);
            //printf("%s\n", jsonTx.write(1,2).c_str());
            printf("%s: cannot build import transaction for currency %s: %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(), result.GetError().c_str());
            LogPrintf("%s: cannot build import transaction for currency %s: %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str(), result.GetError().c_str());
            return false;
        }

        CTransaction newImportTx;

        try
        {
            newImportTx = result.GetTxOrThrow();
        }
        catch(const std::exception& e)
        {
            LogPrintf("%s: failure to build transaction for export to %s\n", __func__, EncodeDestination(CIdentityID(ccx.destCurrencyID)).c_str());
            return false;
        }

        {
            for (auto &oneIn : newImportTx.vin)
            {
                if (!view.HaveCoins(oneIn.prevout.hash))
                {
                    printf("%s: cannot find input in view %s\n", __func__, oneIn.prevout.hash.GetHex().c_str());
                }
            }

            // put our transaction in place of any others
            std::list<CTransaction> removed;
            //mempool.removeConflicts(newImportTx, removed);

            // add to mem pool and relay
            if (!myAddtomempool(newImportTx, &state))
            {
                LogPrintf("%s: %s\n", __func__, state.GetRejectReason().c_str());
                if (state.GetRejectReason() == "bad-txns-inputs-missing")
                {
                    for (auto &oneIn : newImportTx.vin)
                    {
                        printf("{\"vin\":{\"%s\":%d}\n", oneIn.prevout.hash.GetHex().c_str(), oneIn.prevout.n);
                    }
                }
                return false;
            }
            else
            {
                //printf("%s: success adding %s to mempool\n", __func__, newImportTx.GetHash().GetHex().c_str());
                RelayTransaction(newImportTx);
            }

            if (!mempool.mapTx.count(newImportTx.GetHash()))
            {
                printf("%s: cannot find tx in mempool %s\n", __func__, newImportTx.GetHash().GetHex().c_str());
            }
            UpdateCoins(newImportTx, view, nHeight);
            if (!view.HaveCoins(newImportTx.GetHash()))
            {
                printf("%s: cannot find tx in view %s\n", __func__, newImportTx.GetHash().GetHex().c_str());
            }
        }

        newImports[ccx.destCurrencyID].push_back(std::make_pair(0, newImportTx));
    }
    return true;
}


// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// export proofs are all returned as null
bool CConnectedChains::GetSystemExports(const uint160 &systemID,
                                        std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                        uint32_t fromHeight,
                                        uint32_t toHeight)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::CurrencyExportKey()), 
                        CScript::P2IDX, 
                        addressIndex, 
                        fromHeight,
                        toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction exportTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
            {
                std::vector<CBaseChainObject *> opretTransfers;
                CCrossChainExport ccx;
                if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    std::vector<CReserveTransfer> exportTransfers;
                    CPartialTransactionProof exportProof;

                    // get the export transfers from the source
                    if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        for (int i = ccx.firstInput; i < ccx.firstInput + ccx.numInputs; i++)
                        {
                            CTransaction oneTxIn;
                            uint256 txInBlockHash;
                            if (!myGetTransaction(exportTx.vin[i].prevout.hash, oneTxIn, txInBlockHash))
                            {
                                LogPrintf("%s: cannot access transaction %s\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str());
                                return false;
                            }
                            COptCCParams oneInP;
                            if (!(oneTxIn.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(oneInP) &&
                                oneInP.IsValid() &&
                                oneInP.evalCode == EVAL_RESERVE_TRANSFER &&
                                oneInP.vData.size()))
                            {
                                LogPrintf("%s: invalid reserve transfer input %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                            exportTransfers.push_back(CReserveTransfer(oneInP.vData[0]));
                            if (!exportTransfers.back().IsValid())
                            {
                                LogPrintf("%s: invalid reserve transfer input 1 %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                        }
                    }
                    else
                    {
                        LogPrintf("%s: invalid export from incorrect system on this chain in tx %s\n", __func__, idx.first.txhash.GetHex().c_str());
                        return false;
                    }

                    exports.push_back(std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                     exportTx.vout[idx.first.index].nValue,
                                                                                     CTxIn(idx.first.txhash, idx.first.index)), 
                                                                    exportProof),
                                                     exportTransfers));
                }
            }
        }
        return true;
    }
    return false;
}

// get the exports to a specific system from this chain, starting from a specific height up to a specific height
// proofs are returned as null
bool CConnectedChains::GetCurrencyExports(const uint160 &currencyID,
                                          std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> &exports,
                                          uint32_t fromHeight,
                                          uint32_t toHeight)
{
    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed cross-notarization
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, CCrossChainExport::CurrencyExportKey()), 
                        CScript::P2IDX, 
                        addressIndex, 
                        fromHeight,
                        toHeight))
    {
        for (auto &idx : addressIndex)
        {
            uint256 blkHash;
            CTransaction exportTx;
            if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
            {
                std::vector<CBaseChainObject *> opretTransfers;
                CCrossChainExport ccx;
                if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid())
                {
                    std::vector<CReserveTransfer> exportTransfers;
                    CPartialTransactionProof exportProof;

                    // get the export transfers from the source
                    if (ccx.sourceSystemID == ASSETCHAINS_CHAINID)
                    {
                        for (int i = ccx.firstInput; i < ccx.firstInput + ccx.numInputs; i++)
                        {
                            CTransaction oneTxIn;
                            uint256 txInBlockHash;
                            if (!myGetTransaction(exportTx.vin[i].prevout.hash, oneTxIn, txInBlockHash))
                            {
                                LogPrintf("%s: cannot access transasction %s\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str());
                                return false;
                            }
                            COptCCParams oneInP;
                            if (!(oneTxIn.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(oneInP) &&
                                oneInP.IsValid() &&
                                oneInP.evalCode == EVAL_RESERVE_TRANSFER &&
                                oneInP.vData.size()))
                            {
                                LogPrintf("%s: invalid reserve transfer input %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                            exportTransfers.push_back(CReserveTransfer(oneInP.vData[0]));
                            if (!exportTransfers.back().IsValid())
                            {
                                LogPrintf("%s: invalid reserve transfer input 1 %s, %lu\n", __func__, exportTx.vin[i].prevout.hash.GetHex().c_str(), exportTx.vin[i].prevout.n);
                                return false;
                            }
                        }
                    }
                    else
                    {
                        LogPrintf("%s: invalid export from incorrect system on this chain in tx %s\n", __func__, idx.first.txhash.GetHex().c_str());
                        return false;
                    }

                    exports.push_back(std::make_pair(std::make_pair(CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                     exportTx.vout[idx.first.index].nValue,
                                                                                     CTxIn(idx.first.txhash, idx.first.index)), 
                                                                    exportProof),
                                                     exportTransfers));
                }
                else
                {
                    LogPrintf("%s: invalid export index for txid: %s, %lu\n", __func__, idx.first.txhash.GetHex().c_str(), idx.first.index);
                    return false;
                }
            }
        }
        return true;
    }
    return false;
}

bool CConnectedChains::GetPendingSystemExports(const uint160 systemID,
                                               uint32_t fromHeight,
                                               multimap<uint160, pair<int, CInputDescriptor>> &exportOutputs)
{
    CCurrencyDefinition chainDef;
    int32_t defHeight;
    exportOutputs.clear();

    if (GetCurrencyDefinition(systemID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        CChainNotarizationData cnd;
        if (GetNotarizationData(systemID, cnd))
        {
            uint160 exportKey;
            if (chainDef.IsGateway())
            {
                exportKey = CCrossChainRPCData::GetConditionID(chainDef.gatewayID, CCrossChainExport::SystemExportKey());
            }
            else
            {
                exportKey = CCrossChainRPCData::GetConditionID(systemID, CCrossChainExport::SystemExportKey());
            }

            // get all export transactions including and since this one up to the confirmed cross-notarization
            if (GetAddressIndex(exportKey, CScript::P2IDX, addressIndex, fromHeight))
            {
                for (auto &idx : addressIndex)
                {
                    uint256 blkHash;
                    CTransaction exportTx;
                    if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
                    {
                        std::vector<CBaseChainObject *> opretTransfers;
                        CCrossChainExport ccx;
                        if ((ccx = CCrossChainExport(exportTx.vout[idx.first.index].scriptPubKey)).IsValid())
                        {
                            exportOutputs.insert(std::make_pair(ccx.destCurrencyID, 
                                                                std::make_pair(idx.first.blockHeight, 
                                                                               CInputDescriptor(exportTx.vout[idx.first.index].scriptPubKey, 
                                                                                                exportTx.vout[idx.first.index].nValue,
                                                                                                CTxIn(idx.first.txhash, idx.first.index)))));
                        }
                    }
                }
            }
        }
        return true;
    }
    else
    {
        LogPrintf("%s: unrecognized chain name or chain ID\n", __func__);
        return false;
    }
}

bool CConnectedChains::CreateNextExport(const CCurrencyDefinition &_curDef,
                                        const std::vector<ChainTransferData> &_txInputs,
                                        const std::vector<CInputDescriptor> &priorExports,
                                        const CTxDestination &feeOutput,
                                        uint32_t sinceHeight,
                                        uint32_t curHeight,
                                        int32_t inputStartNum,
                                        int32_t &inputsConsumed,
                                        std::vector<CTxOut> &exportOutputs,
                                        std::vector<CReserveTransfer> &exportTransfers,
                                        const CPBaaSNotarization &lastNotarization,
                                        const CUTXORef &lastNotarizationUTXO,
                                        CPBaaSNotarization &newNotarization,
                                        int &newNotarizationOutNum,
                                        bool createOnlyIfRequired,
                                        const ChainTransferData *addInputTx)
{
    // Accepts all reserve transfer inputs to a particular currency destination. 
    // Generates a new export transactions and any required notarizations. 
    // Observes anti-front-running rules.

    // This assumes that:
    // 1) _txInputs has all currencies since last export on this system with accurate block numbers
    // 2) _txInputs is sorted
    // 3) the last export transaction is added as input outside of this call

    newNotarization = lastNotarization;
    newNotarization.prevNotarization = lastNotarizationUTXO;
    inputsConsumed = 0;

    uint160 destSystemID = _curDef.IsGateway() ? _curDef.gatewayID : _curDef.systemID;
    uint160 currencyID = _curDef.GetID();
    bool crossSystem = destSystemID != ASSETCHAINS_CHAINID;
    bool isPreLaunch = _curDef.launchSystemID == ASSETCHAINS_CHAINID &&
                       _curDef.startBlock > sinceHeight &&
                       !(_curDef.systemID == ASSETCHAINS_CHAINID && sinceHeight == _curDef.startBlock - 1 && curHeight > _curDef.startBlock);
    bool isClearLaunchExport = isPreLaunch && curHeight == _curDef.startBlock && !lastNotarization.IsLaunchCleared();

    if (!isClearLaunchExport && !_txInputs.size() && !addInputTx)
    {
        // no error, just nothing to do
        return true;
    }

    // The aggregation rules require that:
    // 1. Either there are MIN_INPUTS of reservetransfer or MIN_BLOCKS before an 
    //    aggregation can be made as an export transaction.
    // 2. We will include as many reserveTransfers as we can, block by block until the 
    //    first block that allows us to meet MIN_INPUTS on this export.
    // 3. One additional *conversion* input may be added in the export transaction as
    //    a "what if", for the estimation API.
    //
    // If the addInputTx is included, this function will add it to the export transaction created.

    // determine inputs to include in next export
    // early out if createOnlyIfRequired is true
    std::vector<ChainTransferData> txInputs;
    if (!isClearLaunchExport &&
        sinceHeight - curHeight < CCrossChainExport::MIN_BLOCKS && 
        _txInputs.size() < CCrossChainExport::MIN_INPUTS &&
        createOnlyIfRequired)
    {
        return true;
    }

    uint32_t addHeight = sinceHeight;
    for (int inputNum = 0; inputNum < _txInputs.size(); inputNum++)
    {
        uint32_t nextHeight = std::get<0>(_txInputs[inputNum]);
        if (addHeight != nextHeight)
        {
            // if this is a launch export, we create one at the boundary
            if (isClearLaunchExport && nextHeight >= _curDef.startBlock)
            {
                addHeight = _curDef.startBlock - 1;
                break;
            }
            // if we have skipped to the next block, and we have enough to make an export, we cannot take any more
            // except the optional one to add
            if (inputNum >= CCrossChainExport::MIN_INPUTS)
            {
                break;
            }
            addHeight = nextHeight;
        }
        txInputs.push_back(_txInputs[inputNum]);
    }

    // if we made an export before getting to the end, it doesn't clear launch
    // if we either early outed, due to height or landed right on the correct height, determine launch state
    // a clear launch export may have no inputs yet still be created with a clear launch notarization
    if (isClearLaunchExport)
    {
        addHeight = _curDef.startBlock - 1;
    }

    // all we expect to add are in txInputs now
    inputsConsumed = txInputs.size();

    // check to see if we need to add the optional input, not counted as "consumed"
    if (addInputTx)
    {
        uint32_t rtHeight = std::get<0>(*addInputTx);
        CReserveTransfer reserveTransfer = std::get<2>(*addInputTx);
        // ensure that any pre-conversions or conversions are all valid, based on mined height and
        if (reserveTransfer.IsPreConversion())
        {
            printf("%s: Invalid optional pre-conversion\n", __func__);
            LogPrintf("%s: Invalid optional pre-conversion\n", __func__);
        }
        else if (reserveTransfer.IsConversion() && rtHeight < _curDef.startBlock)
        {
            printf("%s: Invalid optional conversion added before start block\n", __func__);
            LogPrintf("%s: Invalid optional conversion added before start block\n", __func__);
        }
        else
        {
            txInputs.push_back(*addInputTx);
        }
    }

    // if we are not the clear launch export and have no inputs, including the optional one, we are done
    if (!isClearLaunchExport && txInputs.size() == 0)
    {
        return true;
    }

    // currency from reserve transfers will be stored appropriately for export as follows:
    // 1) Currency with this systemID can be exported to another chain, but it will be held on this
    //    chain in a reserve deposit output. The one exception to this rule is when a gateway currency
    //    that is using this systemID is being exported to itself as the other system. In that case, 
    //    it is sent out and assumed burned from this system, just as it is created/minted when sent
    //    in from the gateway as the source system.
    //
    // 2) Currency being sent to the system of its origin is not tracked.
    //
    // 3) Currency from a system that is not this one being sent to a 3rd system is not allowed.
    //
    // get all the new reserve deposits. the only time we will merge old reserve deposit
    // outputs with current reserve deposit outputs is if there is overlap in currencies. the reserve
    // deposits for this new batch will be output together, and the currencies that are not present
    // in the new batch will be left in separate outputs, one per currency. this should enable old 
    // currencies to get aggregated but still left behind and not carried forward when they drop out 
    // of use.
    CCurrencyDefinition destSystem = ConnectedChains.GetCachedCurrency(destSystemID);

    if (!destSystem.IsValid())
    {
        printf("%s: Invalid data for export system or corrupt chain state\n", __func__);
        LogPrintf("%s: Invalid data for export system or corrupt chain state\n", __func__);
        return false;
    }

    for (int i = 0; i < txInputs.size(); i++)
    {
        exportTransfers.push_back(std::get<2>(txInputs[i]));
    }

    uint256 transferHash;
    CCurrencyValueMap importedCurrency;
    CCurrencyValueMap gatewayDepositsUsed;
    CCurrencyValueMap spentCurrencyOut;
    std::vector<CTxOut> checkOutputs;

    CPBaaSNotarization intermediateNotarization = lastNotarization;
    CCrossChainExport lastExport;
    bool isPostLaunch = false;
    if (priorExports.size() &&
        (lastExport = CCrossChainExport(priorExports[0].scriptPubKey)).IsValid() &&
        (lastExport.IsClearLaunch() || intermediateNotarization.currencyState.IsLaunchCompleteMarker()))
    {
        // now, all exports are post launch
        isPostLaunch = true;
        intermediateNotarization.currencyState.SetLaunchCompleteMarker();
    }

    if (!intermediateNotarization.NextNotarizationInfo(ConnectedChains.ThisChain(),
                                                        _curDef,
                                                        sinceHeight,
                                                        addHeight,
                                                        exportTransfers,
                                                        transferHash,
                                                        newNotarization,
                                                        checkOutputs,
                                                        importedCurrency,
                                                        gatewayDepositsUsed,
                                                        spentCurrencyOut))
    {
        printf("%s: cannot create notarization\n", __func__);
        LogPrintf("%s: cannot create notarization\n", __func__);
        return false;
    }

    //printf("%s: num transfers %ld\n", __func__, exportTransfers.size());

    newNotarization.prevNotarization = lastNotarizationUTXO;

    CCurrencyValueMap totalExports;
    CCurrencyValueMap newReserveDeposits;

    for (int i = 0; i < exportTransfers.size(); i++)
    {
        totalExports += exportTransfers[i].TotalCurrencyOut();
    }

    // if we are exporting off of this system to a gateway or PBaaS chain, don't allow 3rd party 
    // or unregistered exports. if same to same chain, all exports are ok.
    if (destSystemID != ASSETCHAINS_CHAINID)
    {
        for (auto &oneCur : totalExports.valueMap)
        {
            if (oneCur.first == ASSETCHAINS_CHAINID)
            {
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                continue;
            }

            CCurrencyDefinition oneCurDef;
            uint160 oneCurID;

            if (oneCur.first != oneCurID)
            {
                oneCurDef = ConnectedChains.GetCachedCurrency(oneCur.first);
                if (!oneCurDef.IsValid())
                {
                    printf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                    LogPrintf("%s: Invalid currency for export or corrupt chain state\n", __func__);
                    return false;
                }
                oneCurID = oneCur.first;
            }

            // if we are exporting a gateway currency back to its gateway, we do not store it in reserve deposits
            if (oneCurDef.IsGateway() && oneCurDef.systemID == ASSETCHAINS_CHAINID && oneCurDef.gatewayID == destSystemID)
            {
                continue;
            }
            else if (oneCurDef.systemID == ASSETCHAINS_CHAINID)
            {
                // exporting from one currency on this system to another currency on this system, store reserve deposits
                newReserveDeposits.valueMap[oneCur.first] += oneCur.second;
                
                // TODO: if we're exporting to a gateway or other chain, ensure that our export currency is registered for import
                //
            }
            else if (destSystemID != oneCurDef.systemID)
            {
                printf("%s: Cannot export from one external currency system or PBaaS chain to another external system\n", __func__);
                LogPrintf("%s: Cannot export from one external currency system or PBaaS chain to another external system\n", __func__);
                return false;
            }
        }
    }
    else
    {
        // we should have no export from this system to this system directly
        assert(currencyID != ASSETCHAINS_CHAINID);

        // when we export from this system to a specific currency on this system,
        // we record the reserve deposits for the destination currency to ensure they are available for imports
        // which take them as inputs.
        newReserveDeposits = totalExports;
        newReserveDeposits.valueMap.erase(currencyID);
    }

    // now, we have:
    // 1) those transactions that we will take
    // 2) new reserve deposits for this export
    // 3) all transfer and expected conversion fees, including those in the second leg
    // 4) total of all currencies exported, whether fee, reserve deposit, or neither
    // 5) hash of all reserve transfers to be exported
    // 6) all reserve transfers are added to our transaction inputs

    // next actions:
    // 1) create the export
    // 2) add reserve deposit output to transaction
    // 3) if destination currency is pre-launch, update notarization based on pre-conversions
    // 4) if fractional currency is target, check fees against minimums or targets based on conversion rates in currency
    // 5) if post launch, call AddReserveTransferImportOutputs to go from the old currency state and notarization to the new one
    // 6) if actual launch closure, make launch initiating export + initial notarization

    // currencies that are going into this export and not being recorded as reserve deposits will
    // have been recorded on the other side and are being unwound. they should be considered
    // burned on this system.

    // inputs can be:
    // 1. transfers of reserve or tokens for fractional reserve chains
    // 2. pre-conversions for pre-launch participation in the premine
    // 3. reserve market conversions
    //

    CCurrencyValueMap estimatedFees = CCurrencyValueMap(newNotarization.currencyState.currencies, newNotarization.currencyState.fees).CanonicalMap();

    //printf("%s: total export amounts:\n%s\n", __func__, totalAmounts.ToUniValue().write().c_str());
    CCrossChainExport ccx(ASSETCHAINS_CHAINID,
                          sinceHeight,
                          addHeight,
                          destSystemID, 
                          currencyID, 
                          exportTransfers.size(), 
                          totalExports.CanonicalMap(), 
                          estimatedFees,
                          transferHash,
                          inputStartNum,
                          DestinationToTransferDestination(feeOutput));

    ccx.SetPreLaunch(isPreLaunch);
    ccx.SetPostLaunch(isPostLaunch);
    ccx.SetClearLaunch(isClearLaunchExport);

    // if we should add a system export, do so
    CCrossChainExport sysCCX;
    if (crossSystem)
    {
        assert(priorExports.size() == 2);
        COptCCParams p;

        if (!(priorExports[1].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
              p.vData.size() &&
              (sysCCX = CCrossChainExport(p.vData[0])).IsValid()))
        {
            printf("%s: Invalid prior system export\n", __func__);
            LogPrintf("%s: Invalid prior system export\n", __func__);
            return false;
        }
        sysCCX = CCrossChainExport(ASSETCHAINS_CHAINID,
                                   sinceHeight,
                                   addHeight,
                                   destSystemID, 
                                   destSystemID, 
                                   txInputs.size(), 
                                   totalExports.CanonicalMap(), 
                                   estimatedFees,
                                   transferHash,
                                   inputStartNum,
                                   DestinationToTransferDestination(feeOutput),
                                   std::vector<CReserveTransfer>(),
                                   sysCCX.flags);
    }

    CAmount nativeReserveDeposit = 0;
    if (newReserveDeposits.valueMap.count(ASSETCHAINS_CHAINID))
    {
        nativeReserveDeposit += newReserveDeposits.valueMap[ASSETCHAINS_CHAINID];
        newReserveDeposits.valueMap.erase(ASSETCHAINS_CHAINID);
    }

    CCcontract_info CC;
    CCcontract_info *cp;

    if (nativeReserveDeposit || newReserveDeposits.valueMap.size())
    {
        // now send transferred currencies to a reserve deposit
        cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);

        // send the entire amount to a reserve deposit output of the specific chain
        // we receive our fee on the other chain, when it comes back, or if a token,
        // when it gets imported back to the chain
        std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});
        // if going off-system, reserve deposits accrue to the destination system, if same system, to the currency
        CReserveDeposit rd = CReserveDeposit(crossSystem ? destSystemID : currencyID, newReserveDeposits);
        exportOutputs.push_back(CTxOut(nativeReserveDeposit, MakeMofNCCScript(CConditionObj<CReserveDeposit>(EVAL_RESERVE_DEPOSIT, dests, 1, &rd))));
    }

    int exportOutNum = exportOutputs.size();

    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
    std::vector<CTxDestination> dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
    exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx))));

    if (crossSystem)
    {
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &sysCCX))));
    }

    // now, if we are clearing launch, determine if we should refund or launch and set notarization appropriately
    if (isClearLaunchExport)
    {
        if (CCurrencyValueMap(_curDef.currencies, newNotarization.currencyState.reserves) < CCurrencyValueMap(_curDef.currencies, _curDef.minPreconvert))
        {
            newNotarization.currencyState.SetRefunding();
        }
        else
        {
            newNotarization.currencyState.SetLaunchClear();

            // set final numbers for notarization

            // if this is a PBaaS fractional gateway launch, the issued reserves for the gateway must be considered
            // when calculating final prices
            std::map<uint160, int32_t> reserveMap;
            if (_curDef.IsFractional() && _curDef.currencies.size() > 1 && 
                (reserveMap = newNotarization.currencyState.GetReserveMap()).count(_curDef.systemID) && 
                _curDef.systemID != ASSETCHAINS_CHAINID)
            {
                CCurrencyDefinition systemDefForGateway = ConnectedChains.GetCachedCurrency(_curDef.systemID);
                if (!systemDefForGateway.IsValid())
                {
                    printf("%s: Invalid launch system currency for fractional gateway converter\n", __func__);
                    LogPrintf("%s: Invalid launch system currency for fractional gateway converter\n", __func__);
                    return false;
                }
                uint160 scratchSysID = _curDef.systemID;
                if (systemDefForGateway.GetID(systemDefForGateway.gatewayConverterName, scratchSysID) == currencyID)
                {
                    newNotarization.currencyState.reserves[reserveMap[_curDef.systemID]] = systemDefForGateway.gatewayConverterIssuance;
                }

                // to get initial prices, do so without the native currency, then add it at launch
                CCoinbaseCurrencyState calcState = newNotarization.currencyState;
                
                int nativeReserveIndex = reserveMap[_curDef.systemID];
                int32_t weightToDistribute = calcState.weights[nativeReserveIndex];
                calcState.currencies.erase(calcState.currencies.begin() + nativeReserveIndex);
                calcState.weights.erase(calcState.weights.begin() + nativeReserveIndex);
                calcState.reserves.erase(calcState.reserves.begin() + nativeReserveIndex);

                // adjust weights for launch pricing
                int32_t divisor = calcState.currencies.size();
                int32_t dividedWeight = weightToDistribute / divisor;
                int32_t excessToDivide = weightToDistribute % divisor;
                for (auto &oneWeight : calcState.weights)
                {
                    oneWeight += excessToDivide ? dividedWeight + excessToDivide-- : dividedWeight;
                }

                std::vector<int64_t> adjustedPrices = newNotarization.currencyState.PricesInReserve();
                adjustedPrices.insert(adjustedPrices.begin() + nativeReserveIndex, newNotarization.currencyState.PriceInReserve(nativeReserveIndex));
                newNotarization.currencyState.conversionPrice = adjustedPrices;
            }
            else
            {
                newNotarization.currencyState.conversionPrice = newNotarization.currencyState.PricesInReserve();
            }
        }
    }
    else if (!isPreLaunch)
    {
        // now, if we are not pre-launch, update the currency via simulated import
        CReserveTransactionDescriptor rtxd;
        std::vector<CTxOut> checkOutputs;
        CCurrencyValueMap importedCurrency;
        CCurrencyValueMap gatewayDepositsUsed;
        if (!rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain(),
                                                  destSystem,
                                                  _curDef, 
                                                  lastNotarization.currencyState, 
                                                  exportTransfers,
                                                  checkOutputs,
                                                  importedCurrency,
                                                  gatewayDepositsUsed,
                                                  spentCurrencyOut,
                                                  &newNotarization.currencyState))
        {
            printf("%s: Viable import check failure\n", __func__);
            LogPrintf("%s: Viable import check failure\n", __func__);
            return false;
        }
    }

    // all exports to a currency on this chain include a finalization that is spent by the import of this export
    // external systems and gateways get one finalization for their clear to launch export
    if (isClearLaunchExport || (destSystemID == ASSETCHAINS_CHAINID && addHeight >= _curDef.startBlock))
    {
        cp = CCinit(&CC, EVAL_FINALIZE_EXPORT);

        // currency ID for finalization determine indexing and query capability
        // since we care about looking for all exports to one system or another, the currency in the finalization
        // is the system destination for this export (i.e. "which system should do the next work?")
        CObjectFinalization finalization(CObjectFinalization::FINALIZE_EXPORT, destSystemID, uint256(), exportOutNum);

        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CObjectFinalization>(EVAL_FINALIZE_EXPORT, dests, 1, &finalization))));
    }

    // if this is a pre-launch export, including clear launch, update notarization and add it to the export outputs
    if (isClearLaunchExport || isPreLaunch)
    {
        // if we are exporting off chain, add a notarization proof root
        if (destSystemID != ASSETCHAINS_CHAINID)
        {
            newNotarization.notarizationHeight = addHeight;
            newNotarization.proofRoots[ASSETCHAINS_CHAINID] = CProofRoot::GetProofRoot(addHeight);
        }

        // TODO: check to see if we are connected to a running PBaaS daemon for this currency waiting for it to start,
        // and if so, share nodes in the notarization

        newNotarizationOutNum = exportOutputs.size();

        cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
        exportOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &newNotarization))));
    }

    return true;
}

void CConnectedChains::AggregateChainTransfers(const CTxDestination &feeOutput, uint32_t nHeight)
{
    // all chains aggregate reserve transfer transactions, so aggregate and add all necessary export transactions to the mem pool
    {
        if (!nHeight)
        {
            return;
        }

        std::multimap<uint160, ChainTransferData> transferOutputs;

        LOCK(cs_main);

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        uint32_t nHeight = chainActive.Height();

        // check for currencies that should launch in the last 20 blocks, haven't yet, and can have their launch export mined
        // if we find any that have no export creation pending, add it to imports
        std::vector<CAddressIndexDbEntry> rawCurrenciesToLaunch;
        std::map<uint160, std::pair<CCurrencyDefinition, CUTXORef>> launchCurrencies;
        if (GetAddressIndex(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CCurrencyDefinition::CurrencyLaunchKey()),
                            CScript::P2IDX, 
                            rawCurrenciesToLaunch,
                            nHeight - 20 < 0 ? 0 : nHeight - 20,
                            nHeight) &&
            rawCurrenciesToLaunch.size())
        {
            // add any unlaunched currencies as an output
            for (auto &oneDefIdx : rawCurrenciesToLaunch)
            {
                CTransaction defTx;
                uint256 hashBlk;
                COptCCParams p;
                CCurrencyDefinition oneDef;
                if (myGetTransaction(oneDefIdx.first.txhash, defTx, hashBlk) &&
                    defTx.vout.size() > oneDefIdx.first.index &&
                    defTx.vout[oneDefIdx.first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_CURRENCY_DEFINITION &&
                    p.vData.size() &&
                    (oneDef = CCurrencyDefinition(p.vData[0])).IsValid() &&
                    oneDef.systemID == ASSETCHAINS_CHAINID)
                {
                    launchCurrencies.insert(std::make_pair(oneDef.GetID(), std::make_pair(oneDef, CUTXORef())));
                }
            }
        }

        // get all available transfer outputs to aggregate into export transactions
        if (GetUnspentChainTransfers(transferOutputs))
        {
            if (!(transferOutputs.size() || launchCurrencies.size()))
            {
                return;
            }

            std::vector<ChainTransferData> txInputs;
            uint160 lastChain = transferOutputs.size() ? transferOutputs.begin()->first : launchCurrencies.begin()->second.first.GetID();

            CCoins coins;
            CCoinsView dummy;
            CCoinsViewCache view(&dummy);

            LOCK(mempool.cs);

            CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
            view.SetBackend(viewMemPool);

            auto outputIt = transferOutputs.begin();
            bool checkLaunchCurrencies = false;
            for (int outputsDone = 0; 
                 outputsDone <= transferOutputs.size() || launchCurrencies.size();
                 outputsDone++)
            {
                if (outputIt != transferOutputs.end())
                {
                    auto &output = *outputIt;
                    if (output.first == lastChain)
                    {
                        txInputs.push_back(output.second);
                        outputIt++;
                        continue;
                    }
                }
                else if (checkLaunchCurrencies || !transferOutputs.size())
                {
                    // we are done with all natural exports and have deleted any launch entries that had natural exports,
                    // since they should also handle launch naturally.
                    // if we have launch currencies that have not been launched and do not have associated
                    // transfer outputs, force launch them
                    std::vector<uint160> toErase;
                    for (auto &oneLaunchCur : launchCurrencies)
                    {
                        CChainNotarizationData cnd;
                        std::vector<std::pair<CTransaction, uint256>> txes;

                        // ensure that a currency is still unlaunched before
                        // marking it for launch
                        if (!(GetNotarizationData(oneLaunchCur.first, cnd, &txes) &&
                              cnd.vtx[cnd.lastConfirmed].second.IsValid() &&
                              !(cnd.vtx[cnd.lastConfirmed].second.currencyState.IsLaunchClear() || 
                                cnd.vtx[cnd.lastConfirmed].second.IsLaunchCleared())))
                        {
                            toErase.push_back(oneLaunchCur.first);
                        }
                    }
                    for (auto &oneToErase : toErase)
                    {
                        launchCurrencies.erase(oneToErase);
                    }
                    if (launchCurrencies.size())
                    {
                        lastChain = launchCurrencies.begin()->first;
                    }
                }
                else
                {
                    // this is when we have to finish one round and then continue with currency launches
                    checkLaunchCurrencies = launchCurrencies.size() != 0;
                }

                CCurrencyDefinition destDef, systemDef;

                destDef = GetCachedCurrency(lastChain);

                if (!destDef.IsValid())
                {
                    printf("%s: cannot find destination currency %s\n", __func__, EncodeDestination(CIdentityID(lastChain)).c_str());
                    LogPrintf("%s: cannot find destination currency %s\n", __func__, EncodeDestination(CIdentityID(lastChain)).c_str());
                    break;
                }

                if (destDef.systemID == thisChainID)
                {
                    if (destDef.IsGateway())
                    {
                        // if the currency is a gateway on this system, any exports go through it to the gateway, not the system ID
                        systemDef = GetCachedCurrency(destDef.gatewayID);
                    }
                    else
                    {
                        systemDef = destDef;
                    }
                }
                else
                {
                    systemDef = GetCachedCurrency(destDef.systemID);
                }

                if (!systemDef.IsValid())
                {
                    printf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    LogPrintf("%s: cannot find destination system definition %s\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                    break;
                }

                bool isSameChain = destDef.systemID == thisChainID;

                // when we get here, we have a consecutive number of transfer outputs to consume in txInputs
                // we need an unspent export output to export, or use the last one of it is an export to the same
                // system
                std::vector<std::pair<int, CInputDescriptor>> exportOutputs;
                std::vector<std::pair<int, CInputDescriptor>> sysExportOutputs;
                std::vector<CInputDescriptor> allExportOutputs;
                CCurrencyDefinition lastChainDef = GetCachedCurrency(lastChain);

                // export outputs must come from the latest, including mempool, to ensure
                // enforcement of sequential exports. get unspent currency export, and if not on the current
                // system, the external system export as well

                if ((ConnectedChains.GetUnspentCurrencyExports(view, lastChain, exportOutputs) && exportOutputs.size()) &&
                    (isSameChain || ConnectedChains.GetUnspentCurrencyExports(view, lastChainDef.systemID, sysExportOutputs) && sysExportOutputs.size()))
                {
                    assert(exportOutputs.size() == 1);
                    std::pair<int, CInputDescriptor> lastExport = exportOutputs[0];
                    allExportOutputs.push_back(lastExport.second);
                    std::pair<int, CInputDescriptor> lastSysExport = std::make_pair(-1, CInputDescriptor());
                    if (!isSameChain)
                    {
                        lastSysExport = sysExportOutputs[0];
                        allExportOutputs.push_back(lastSysExport.second);
                    }

                    COptCCParams p;
                    CCrossChainExport ccx, sysCCX;
                    if (!(lastExport.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                          p.IsValid() &&
                          p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                          p.vData.size() &&
                          (ccx = CCrossChainExport(p.vData[0])).IsValid()) ||
                        !(isSameChain ||
                          (lastSysExport.second.scriptPubKey.IsPayToCryptoCondition(p) &&
                           p.IsValid() &&
                           p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                           p.vData.size() &&
                           (sysCCX = CCrossChainExport(p.vData[0])).IsValid())))
                    {
                        printf("%s: invalid export(s) for %s in index\n", __func__, EncodeDestination(CIdentityID(lastChainDef.GetID())).c_str());
                        LogPrintf("%s: invalid export(s) for %s in index\n", __func__, EncodeDestination(CIdentityID(lastChainDef.GetID())).c_str());
                        break;
                    }

                    // now, we have the previous export to this currency/system, which we should spend to
                    // enable this new export. if we find no export, we're done
                    int32_t numInputsUsed;
                    std::vector<CTxOut> exportTxOuts;
                    std::vector<CReserveTransfer> exportTransfers;
                    CChainNotarizationData cnd;
                    
                    // get notarization for the actual currency we are exporting
                    if (!GetNotarizationData(lastChain, cnd) || cnd.lastConfirmed == -1)
                    {
                        printf("%s: missing or invalid notarization for %s\n", __func__, EncodeDestination(CIdentityID(lastChainDef.GetID())).c_str());
                        LogPrintf("%s: missing or invalid notarization for %s\n", __func__, EncodeDestination(CIdentityID(lastChainDef.GetID())).c_str());
                        break;
                    }

                    CPBaaSNotarization lastNotarization = cnd.vtx[cnd.lastConfirmed].second;
                    CUTXORef lastNotarizationUTXO = cnd.vtx[cnd.lastConfirmed].first;
                    CPBaaSNotarization newNotarization;
                    int newNotarizationOutNum;

                    while (txInputs.size() || launchCurrencies.count(lastChain))
                    {
                        launchCurrencies.erase(lastChain);
                        //printf("%s: launchCurrencies.size(): %ld\n", __func__, launchCurrencies.size());

                        // even if we have no txInputs, currencies that need to will launch
                        newNotarizationOutNum = -1;
                        if (!CConnectedChains::CreateNextExport(lastChainDef,
                                                                txInputs,
                                                                allExportOutputs,
                                                                feeOutput,
                                                                ccx.sourceHeightEnd,
                                                                nHeight,
                                                                isSameChain ? 1 : 2, // reserve transfers start at input 1 on same chain or after sys
                                                                numInputsUsed,
                                                                exportTxOuts,
                                                                exportTransfers,
                                                                lastNotarization,
                                                                lastNotarizationUTXO,
                                                                newNotarization,
                                                                newNotarizationOutNum))
                        {
                            printf("%s: unable to create export for %s\n", __func__, EncodeDestination(CIdentityID(lastChainDef.GetID())).c_str());
                            LogPrintf("%s: unable to create export for  %s\n", __func__, EncodeDestination(CIdentityID(lastChainDef.GetID())).c_str());
                            break;
                        }

                        // now, if we have created any outputs, we have a transaction to make, if not, we are done
                        if (!exportTxOuts.size())
                        {
                            txInputs.clear();
                            break;
                        }

                        TransactionBuilder tb(Params().GetConsensus(), nHeight);
                        tb.SetFee(0);

                        // add input from last export, all consumed txInputs, and all outputs created to make 
                        // the new export tx. since we are exporting from this chain

                        /* UniValue scriptUniOut;
                        ScriptPubKeyToUniv(lastExport.second.scriptPubKey, scriptUniOut, false);
                        printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastExport.second.nValue, scriptUniOut.write(1,2).c_str());
                        */

                        // first add previous export
                        tb.AddTransparentInput(lastExport.second.txIn.prevout, lastExport.second.scriptPubKey, lastExport.second.nValue);

                        // if going to another system, add the system export thread as well
                        if (!isSameChain)
                        {

                            /* scriptUniOut = UniValue(UniValue::VOBJ);
                            ScriptPubKeyToUniv(lastSysExport.second.scriptPubKey, scriptUniOut, false);
                            printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), lastSysExport.second.nValue, scriptUniOut.write(1,2).c_str());
                            */

                            tb.AddTransparentInput(lastSysExport.second.txIn.prevout, lastSysExport.second.scriptPubKey, lastSysExport.second.nValue);
                        }

                        // now, all reserve transfers
                        for (int i = 0; i < numInputsUsed; i++)
                        {
                            CInputDescriptor inputDesc = std::get<1>(txInputs[i]);

                            /* scriptUniOut = UniValue(UniValue::VOBJ);
                            ScriptPubKeyToUniv(inputDesc.scriptPubKey, scriptUniOut, false);
                            printf("adding input %d with %ld nValue and script:\n%s\n", (int)tb.mtx.vin.size(), inputDesc.nValue, scriptUniOut.write(1,2).c_str());
                            */

                            tb.AddTransparentInput(inputDesc.txIn.prevout, inputDesc.scriptPubKey, inputDesc.nValue);
                        }

                        // now, add all outputs to the transaction
                        auto thisExport = lastExport;
                        int outputNum = tb.mtx.vout.size();
                        for (auto &oneOut : exportTxOuts)
                        {
                            COptCCParams xp;
                            if (oneOut.scriptPubKey.IsPayToCryptoCondition(xp) && xp.IsValid() && xp.evalCode == EVAL_CROSSCHAIN_EXPORT)
                            {
                                thisExport.second.scriptPubKey = oneOut.scriptPubKey;
                                thisExport.second.nValue = oneOut.nValue;
                                thisExport.first = nHeight;
                                thisExport.second.txIn.prevout.n = outputNum;
                            }

                            /* scriptUniOut = UniValue(UniValue::VOBJ);
                            ScriptPubKeyToUniv(oneOut.scriptPubKey, scriptUniOut, false);
                            printf("%s: adding output %d with %ld nValue and script:\n%s\n", __func__, (int)tb.mtx.vout.size(), oneOut.nValue, scriptUniOut.write(1,2).c_str());
                            */

                            tb.AddTransparentOutput(oneOut.scriptPubKey, oneOut.nValue);
                            outputNum++;
                        }

                        TransactionBuilderResult buildResult(tb.Build());

                        if (!buildResult.IsError() && buildResult.IsTx())
                        {
                            // replace the last one only if we have a valid new one
                            CTransaction tx = buildResult.GetTxOrThrow();

                            if (newNotarizationOutNum >= 0)
                            {
                                lastNotarization = newNotarization;
                                lastNotarizationUTXO.hash = tx.GetHash();
                                lastNotarizationUTXO.n = newNotarizationOutNum;
                            }

                            /* uni = UniValue(UniValue::VOBJ);
                            TxToUniv(tx, uint256(), uni);
                            printf("%s: successfully built tx:\n%s\n", __func__, uni.write(1,2).c_str()); */

                            LOCK2(cs_main, mempool.cs);
                            static int lastHeight = 0;
                            // remove conflicts, so that we get in
                            std::list<CTransaction> removed;
                            mempool.removeConflicts(tx, removed);

                            // add to mem pool, prioritize according to the fee we will get, and relay
                            //printf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                            //LogPrintf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                            if (myAddtomempool(tx))
                            {
                                uint256 hash = tx.GetHash();
                                thisExport.second.txIn.prevout.hash = hash;
                                lastExport = thisExport;
                                CAmount nativeExportFees = ccx.totalFees.valueMap[ASSETCHAINS_CHAINID] ? ccx.totalFees.valueMap[ASSETCHAINS_CHAINID] : 10000;
                                mempool.PrioritiseTransaction(hash, hash.GetHex(), (double)(nativeExportFees << 1), nativeExportFees);
                            }
                            else
                            {
                                UniValue uni(UniValue::VOBJ);
                                TxToUniv(tx, uint256(), uni);
                                //printf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                LogPrintf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                break;
                            }
                        }
                        else
                        {
                            // we can't do any more useful work for this chain if we failed here
                            printf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                            LogPrintf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                            break;
                        }

                        // erase the inputs we've attempted to spend and loop for another export tx
                        if (numInputsUsed)
                        {
                            txInputs.erase(txInputs.begin(), txInputs.begin() + numInputsUsed);
                        }
                    }
                }
                txInputs.clear();
                launchCurrencies.erase(lastChain);

                if (outputIt != transferOutputs.end())
                {
                    lastChain = outputIt->first;
                    txInputs.push_back(outputIt->second);
                    outputIt++;
                }
            }
            CheckImports();
        }
    }
}

void CConnectedChains::SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions)
{
    int nHeight = chainActive.LastTip()->GetHeight();
    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());
    LOCK2(cs_main, mempool.cs);

    uint256 lastHash, lastSignedHash;
    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto &_tx : transactions)
    {
        CMutableTransaction newTx(_tx);

        if (!lastHash.IsNull())
        {
            //printf("last hash before signing: %s\n", lastHash.GetHex().c_str());
            for (auto &oneIn : newTx.vin)
            {
                //printf("checking input with hash: %s\n", oneIn.prevout.hash.GetHex().c_str());
                if (oneIn.prevout.hash == lastHash)
                {
                    oneIn.prevout.hash = lastSignedHash;
                    //printf("updated hash before signing: %s\n", lastSignedHash.GetHex().c_str());
                }
            }
        }
        lastHash = _tx.GetHash();
        CTransaction tx = newTx;

        // sign the transaction and submit
        bool signSuccess = false;
        for (int i = 0; i < tx.vin.size(); i++)
        {
            SignatureData sigdata;
            CAmount value;
            CScript outputScript;

            if (tx.vin[i].prevout.hash == lastImportTx.GetHash())
            {
                value = lastImportTx.vout[tx.vin[i].prevout.n].nValue;
                outputScript = lastImportTx.vout[tx.vin[i].prevout.n].scriptPubKey;
            }
            else
            {
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(nullptr, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"%s: failure to sign transaction\n", __func__);
                LogPrintf("%s: failure to sign transaction\n", __func__);
                break;
            } else {
                UpdateTransaction(newTx, i, sigdata);
            }
        }

        if (signSuccess)
        {
            // push to local node and sync with wallets
            CValidationState state;
            bool fMissingInputs;
            CTransaction signedTx(newTx);

            //DEBUGGING
            //TxToJSON(tx, uint256(), jsonTX);
            //printf("signed transaction:\n%s\n", jsonTX.write(1, 2).c_str());

            if (!AcceptToMemoryPool(mempool, state, signedTx, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    //UniValue txUni(UniValue::VOBJ);
                    //TxToUniv(signedTx, uint256(), txUni);
                    //fprintf(stderr,"%s: rejected by memory pool for %s\n%s\n", __func__, state.GetRejectReason().c_str(), txUni.write(1,2).c_str());
                    LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"%s: missing inputs\n", __func__);
                        LogPrintf("%s: missing inputs\n", __func__);
                    }
                    else
                    {
                        fprintf(stderr,"%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                        LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                    }
                }
                break;
            }
            else
            {
                UpdateCoins(signedTx, view, nHeight);
                lastSignedHash = signedTx.GetHash();
            }
        }
        else
        {
            break;
        }
    }
}

// process token related, local imports and exports
void CConnectedChains::ProcessLocalImports()
{
    // first determine all exports to the current/same system marked for action
    // next, get the last import of each export thread, package all pending exports,
    // and call CreateLatestImports

    std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> exportsOut;
    uint160 thisChainID = thisChain.GetID();

    LOCK(cs_main);
    uint32_t nHeight = chainActive.Height();

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::set<uint160> currenciesProcessed;
    uint160 finalizeExportKey(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, CObjectFinalization::ObjectFinalizationExportKey()));

    if (GetAddressUnspent(finalizeExportKey, CScript::P2IDX, unspentOutputs))
    {
        // now, we have a list of all currencies with exports that have work to do
        // export finalizations are either on the same transaction as the export, or in the case of a clear launch export,
        // there may be any number of pre-launch exports still to process prior to spending it
        for (auto &oneFinalization : unspentOutputs)
        {
            COptCCParams p;
            CObjectFinalization of;
            CCrossChainExport ccx;
            CCrossChainImport cci;
            CTransaction scratchTx;
            int32_t importOutputNum;
            uint256 hashBlock;
            std::vector<std::pair<std::pair<CInputDescriptor,CPartialTransactionProof>,std::vector<CReserveTransfer>>> exportsFound;
            if (oneFinalization.second.script.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_EXPORT &&
                p.vData.size() &&
                (of = CObjectFinalization(p.vData[0])).IsValid() &&
                myGetTransaction(of.output.hash.IsNull() ? oneFinalization.first.txhash : of.output.hash, scratchTx, hashBlock) &&
                scratchTx.vout.size() > of.output.n &&
                scratchTx.vout[of.output.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                p.vData.size() &&
                (ccx = CCrossChainExport(p.vData[0])).IsValid() &&
                !currenciesProcessed.count(ccx.destCurrencyID) &&
                GetLastImport(ccx.destCurrencyID, scratchTx, importOutputNum) &&
                scratchTx.vout.size() > importOutputNum &&
                scratchTx.vout[importOutputNum].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                GetCurrencyExports(ccx.destCurrencyID, exportsFound, cci.sourceSystemHeight, nHeight))
            {
                uint256 cciExportTxHash = cci.exportTxId.IsNull() ? scratchTx.GetHash() : cci.exportTxId;
                if (exportsFound.size())
                {
                    // make sure we start from the first export not imported and skip the rest
                    auto startingIt = exportsFound.begin();
                    for ( ; startingIt != exportsFound.end(); startingIt++)
                    {
                        // if this is the first. then the first is the one we will always use
                        if (cci.IsDefinitionImport())
                        {
                            break;
                        }
                        if (startingIt->first.first.txIn.prevout.hash == cciExportTxHash && startingIt->first.first.txIn.prevout.n == cci.exportTxOutNum)
                        {
                            startingIt++;
                            break;
                        }
                    }
                    exportsOut.insert(exportsOut.end(), startingIt, exportsFound.end());
                }
                currenciesProcessed.insert(ccx.destCurrencyID);
            }
        }
    }

    std::map<uint160, std::vector<std::pair<int, CTransaction>>> newImports;
    if (exportsOut.size())
    {
        CreateLatestImports(thisChain, CUTXORef(), exportsOut, newImports);
    }
}

void CConnectedChains::SubmissionThread()
{
    try
    {
        arith_uint256 lastHash;
        int64_t lastImportTime = 0;
        uint32_t lastHeight = 0;
        
        // wait for something to check on, then submit blocks that should be submitted
        while (true)
        {
            boost::this_thread::interruption_point();

            if (IsVerusActive())
            {
                // blocks get discarded after no refresh for 5 minutes by default, probably should be more often
                //printf("SubmissionThread: pruning\n");
                PruneOldChains(GetAdjustedTime() - 300);
                bool submit = false;
                {
                    LOCK(cs_mergemining);
                    if (mergeMinedChains.size() == 0 && qualifiedHeaders.size() != 0)
                    {
                        qualifiedHeaders.clear();
                    }
                    submit = qualifiedHeaders.size() != 0 && mergeMinedChains.size() != 0;

                    //printf("SubmissionThread: qualifiedHeaders.size(): %lu, mergeMinedChains.size(): %lu\n", qualifiedHeaders.size(), mergeMinedChains.size());
                }
                if (submit)
                {
                    //printf("SubmissionThread: calling submit qualified blocks\n");
                    SubmitQualifiedBlocks();
                }

                if (!submit)
                {
                    sem_submitthread.wait();
                }
            }

            // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
            if (IsNotaryAvailable())
            {
                // check to see if we have recently earned a block with an earned notarization that qualifies for
                // submitting an accepted notarization
                if (earnedNotarizationHeight)
                {
                    CBlock blk;
                    int32_t txIndex = -1, height;
                    {
                        LOCK(cs_mergemining);
                        if (earnedNotarizationHeight && earnedNotarizationHeight <= chainActive.Height() && earnedNotarizationBlock.GetHash() == chainActive[earnedNotarizationHeight]->GetBlockHash())
                        {
                            blk = earnedNotarizationBlock;
                            earnedNotarizationBlock = CBlock();
                            txIndex = earnedNotarizationIndex;
                            height = earnedNotarizationHeight;
                            earnedNotarizationHeight = 0;
                        }
                    }

                    if (txIndex != -1)
                    {
                        LOCK(cs_main);
                        //printf("SubmissionThread: testing notarization\n");
                        CTransaction lastConfirmed;
                        CPBaaSNotarization notarization; 
                        CNotaryEvidence evidence;
                        CValidationState state;
                        TransactionBuilder txBuilder(Params().GetConsensus(), chainActive.Height());
                        // get latest earned notarization

                        bool success = notarization.CreateAcceptedNotarization(ConnectedChains.FirstNotaryChain().chainDefinition,
                                                                               notarization,
                                                                               evidence,
                                                                               state,
                                                                               txBuilder);

                        if (success)
                        {
                            //printf("Submitted notarization for acceptance: %s\n", txId.GetHex().c_str());
                            //LogPrintf("Submitted notarization for acceptance: %s\n", txId.GetHex().c_str());
                        }
                    }
                }

                // every "n" seconds, look for imports to include in our blocks from the notary chain
                if ((GetAdjustedTime() - lastImportTime) >= 30 || lastHeight < (chainActive.LastTip() ? 0 : chainActive.LastTip()->GetHeight()))
                {
                    lastImportTime = GetAdjustedTime();
                    lastHeight = (chainActive.LastTip() ? 0 : chainActive.LastTip()->GetHeight());

                    // see if our notary has a confirmed notarization for us
                    UniValue params(UniValue::VARR);
                    UniValue result;
                }
            }
            sleep(3);
            boost::this_thread::interruption_point();
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("Verus merge mining thread terminated\n");
    }
}

void CConnectedChains::SubmissionThreadStub()
{
    ConnectedChains.SubmissionThread();
}

void CConnectedChains::QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height)
{
    // called after winning a block that contains an earned notarization
    // the earned notarization and its height are queued for processing by the submission thread
    // when a new notarization is added, older notarizations are removed, but all notarizations in the current height are
    // kept
    LOCK(cs_mergemining);

    // we only care about the last
    earnedNotarizationHeight = height;
    earnedNotarizationBlock = blk;
    earnedNotarizationIndex = txIndex;
}

bool IsChainDefinitionInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_CURRENCY_DEFINITION;
}

