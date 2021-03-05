/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This defines the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 * In all notarization services, there is notarizing chain and a chain paying notarization rewards. They are not the same.
 * The notarizing chain earns the right to submit notarizations onto the paying chain, which uses provable Verus chain power 
 * of each chain combined with a confirmation process to validate the correct version of one chain to another and vice versa.
 * Generally, the paying chain will be Verus, and the notarizing chain will be the PBaaS chain started with a root of Verus 
 * notarization.
 * 
 * On each chain, notarizations spend the output of the prior transaction that spent the notarization output, which has some spending
 * rules that create a thread of one attempted notarization per block, each of them properly representing the current chain, whether 
 * the prior transaction represents a valid representation of the other chain or not. In order to move the notarization forward,
 * it must also be accepted onto the paying chain, then referenced to move confirmed notarization forward again on the current chain. 
 * All notarization threads are started with a chain definition on the paying chain, or at block 1 on the PBaaS chain.
 * 
 * Every notarization besides the chain definition is initiated on the PBaaS chain as an effort to create a notarization that is accepted
 * and confirmed on the paying chain by first being accepted by a Verus miner before a more valuable 
 * notarization is completed and available for acceptance, then being confirmed by multiple cross notarizations.
 * 
 * A notarization submission is earned when a block is won by staking or mining on the PBaaS chain. The miner puts a notarization
 * of the paying chain into the block mined, spending the notarization thread. In order for the miner to have a transaction output to spend from,
 * all PBaaS chains have a block 1 output of a small, transferable amount of Verus, which is only used as a notarization thread.
 * 
 * After "n" blocks, currently 8, from the block won, the earned notarization may be submitted, proving the last notarization and 
 * including an MMR root that is 8 blocks after the asserted winning block, which must also be proven along with at least one staked block. 
 * Once accepted and confirmed, the notarization transaction itself may be used to spend from the pool of notarization rewards, 
 * with an output that pays 50% to the notary and 50% to the block miner/staker recipient on the paying chain.
 *
 * A notarizaton must be either the first in the chain or refer to a prior notarization with which it agrees. If it skips existing
 * notarizations, referring to a prior notarization as valid, that is the same as asserting that the skipped notarizations are invalid.
 * In that case, the notarization and 2 after it must prove one additional block since the notarization skipped.
 * 
 * The intent is to make it extremely improbable cryptographically to achieve full confirmation of any notarization unless an alternate 
 * fork actually represents a valid chain with a majority of combined work and stake, even if more than the majority of notarizers are 
 * attempting to notarize an invalid chain.
 * 
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for the accepting chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined
 *    block that is owned by the submitter and exactly 8 blocks behind the submitted MMR, which is used for proof.
 * 2) must prove a chain definition tx and be block 1 or contain a notarization tx, which asserts a previous, valid MMR for this
 *    chain and properly proves objects using that MMR, as well as has the proper notarization thread inputs and outputs.
 * 3) must spend the notarization thread to the specified chainID in a fee free transaction with notarization thread input and output
 * 
 * to agree with a previous notarization, we must:
 * 1) agree that at the indicated block height, the MMR root is the root claimed, and is a correct representation of the best chain.
 * 
 */

#ifndef PBAAS_NOTARIZATION_H
#define PBAAS_NOTARIZATION_H

#include "key_io.h"
#include "pbaas/pbaas.h"

// This is the data for a PBaaS notarization transaction, either of a PBaaS chain into the Verus chain, or the Verus
// chain into a PBaaS chain.

// Part of a transaction with an opret that contains only the hashes and proofs, without the source
// headers, transactions, and objects. This type of notarizatoin is mined into a block by the miner, and is created on the PBaaS
// chain.
//
// Notarizations include the following elements in order:
//  Latest block header being notarized, or a header ref for a merge-mined header
//  Proof of the header using the latest MMR root
//  Cross notarization transaction less its op_ret
//  Proof of the cross notarization using the latest MMR root
class CPBaaSNotarization
{
public:
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1,
        FINAL_CONFIRMATIONS = 9,
        BLOCK_NOTARIZATION_MODULO = 10,                 // incentive to earn one valid notarization during this many blocks
        MIN_BLOCKS_BEFORE_NOTARY_FINALIZED = 15,        // 15 blocks must go by before notary signatures or confirming evidence can be provided
        MAX_NODES = 2,                                  // only provide 2 nodes per notarization
        MIN_NOTARIZATION_OUTPUT = 0,                    // inimum amount for notarization output
    };
    //static const int FINAL_CONFIRMATIONS = 10;
    //static const int MIN_BLOCKS_BETWEEN_NOTARIZATIONS = 8;

    enum FLAGS
    {
        FLAGS_NONE = 0,
        FLAG_DEFINITION_NOTARIZATION = 1,   // initial notarization on definition of currency/system/chain
        FLAG_PRE_LAUNCH = 2,                // pre-launch notarization
        FLAG_START_NOTARIZATION = 4,        // first notarization after pre-launch
        FLAG_LAUNCH_CONFIRMED = 8,
        FLAG_REFUNDING = 0x10,
        FLAG_ACCEPTED_MIRROR = 0x20,        // if this is set, this notarization is a mirror of an earned notarization on another chain
        FLAG_BLOCKONE_NOTARIZATION = 0x40,  // block 1 notarizations are auto-finalized, the blockchain itself will be worthless if it is wrong
        FLAG_SAME_CHAIN = 0x80              // set if all currency information is verifiable on this chain
    };

    uint32_t nVersion;
    uint32_t flags;                         // notarization options
    CTransferDestination proposer;          // paid when this gets used on import (miner/staker, shares this with 1 notary for each validation)

    uint160 currencyID;                     // the primary currency this notarization represents for the system, may be gateway or external chain
    uint32_t notarizationHeight;            // <= height on the current system as of this notarization (can't be confirmed earlier)
    CCoinbaseCurrencyState currencyState;   // state of the currency being notarized as of this notarization

    CUTXORef prevNotarization;              // reference of the prior notarization on this system with which we agree
    uint256 hashPrevNotarization;           // hash of the prior notarization on this system with which we agree, even one not accepted yet
    uint32_t prevHeight;                    // height of previous notarization we agree with

    std::map<uint160, CCoinbaseCurrencyState> currencyStates; // currency state of other currencies to be co-notarized for gateways
    std::map<uint160, CProofRoot> proofRoots; // if cross-chain notarization, includes valid proof root of systemID at notarizationHeight + others verified

    std::vector<CNodeData> nodes;           // if cross chain notarization, network nodes

    CPBaaSNotarization() : nVersion(PBAAS_VERSION_INVALID) {}

    CPBaaSNotarization(const uint160 &currencyid,
                       const CCoinbaseCurrencyState CurrencyState,
                       uint32_t height,
                       const CUTXORef &prevnotarization,
                       uint32_t prevheight,
                       const std::vector<CNodeData> &Nodes=std::vector<CNodeData>(),
                       const std::map<uint160, CCoinbaseCurrencyState> &CurrencyStates=std::map<uint160, CCoinbaseCurrencyState>(),
                       const CTransferDestination &Proposer=CTransferDestination(),
                       const std::map<uint160, CProofRoot> &ProofRoots=std::map<uint160, CProofRoot>(),
                       uint32_t version=VERSION_CURRENT,
                       uint32_t Flags=FLAGS_NONE) : 
                       nVersion(version),
                       flags(Flags),
                       proposer(Proposer),
                       currencyID(currencyid),
                       notarizationHeight(height),
                       currencyState(CurrencyState),
                       prevNotarization(prevnotarization),
                       prevHeight(prevheight),
                       currencyStates(CurrencyStates),
                       proofRoots(ProofRoots),
                       nodes(Nodes)
    {
    }

    CPBaaSNotarization(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CPBaaSNotarization(const CTransaction &tx, int32_t *pOutIdx=nullptr);

    CPBaaSNotarization(const CScript &scriptPubKey);

    CPBaaSNotarization(const UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nVersion));
        READWRITE(VARINT(flags));
        READWRITE(proposer);
        READWRITE(currencyID);
        READWRITE(currencyState);
        READWRITE(notarizationHeight);
        READWRITE(prevNotarization);
        READWRITE(prevHeight);

        std::vector<std::pair<uint160, CCoinbaseCurrencyState>> vecCurrencyStates;
        if (ser_action.ForRead())
        {
            READWRITE(vecCurrencyStates);
            for (auto &oneRoot : vecCurrencyStates)
            {
                currencyStates.insert(oneRoot);
            }
        }
        else
        {
            for (auto &oneRoot : currencyStates)
            {
                vecCurrencyStates.push_back(oneRoot);
            }
            READWRITE(vecCurrencyStates);
        }

        std::vector<std::pair<uint160, CProofRoot>> vecProofRoots;

        if (ser_action.ForRead())
        {
            READWRITE(vecProofRoots);
            for (auto &oneRoot : vecProofRoots)
            {
                proofRoots.insert(oneRoot);
            }
        }
        else
        {
            for (auto &oneRoot : proofRoots)
            {
                vecProofRoots.push_back(oneRoot);
            }
            READWRITE(vecProofRoots);
        }

        READWRITE(nodes);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nVersion >= VERSION_FIRST && nVersion <= VERSION_LAST && !currencyID.IsNull();
    }

    static std::string NotaryNotarizationKeyName()
    {
        return "vrsc::system.notarization.notarization";
    }
    static uint160 NotaryNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 notaryNotarizationKey = CVDXF::GetDataKey(NotaryNotarizationKeyName(), nameSpace);
        return notaryNotarizationKey;
    }

    // if false, *this is unmodifed, otherwise, it is set to the last valid notarization in the requested range
    bool GetLastNotarization(const uint160 &currencyID, 
                             uint32_t eCode, 
                             int32_t startHeight=0, 
                             int32_t endHeight=0, 
                             uint256 *txIDOut=nullptr,
                             CTransaction *txOut=nullptr);

    // if false, no matching, unspent notarization found
    bool GetLastUnspentNotarization(const uint160 &currencyID, 
                                    uint32_t eCode, 
                                    uint256 &txIDOut,
                                    int32_t &txOutNum,
                                    CTransaction *txOut=nullptr);

    bool NextNotarizationInfo(const CCurrencyDefinition &sourceSystem, 
                              const CCurrencyDefinition &destCurrency, 
                              uint32_t lastExportHeight, 
                              uint32_t currentHeight, 
                              std::vector<CReserveTransfer> &exportTransfers,
                              uint256 &transferHash,
                              CPBaaSNotarization &newNotarization,
                              std::vector<CTxOut> &importOutputs,
                              CCurrencyValueMap &importedCurrency,
                              CCurrencyValueMap &gatewayDepositsUsed,
                              CCurrencyValueMap &spentCurrencyOut) const;

    static bool CreateEarnedNotarization(const CRPCChainData &externalSystem,
                                         const CTransferDestination &Proposer,
                                         CValidationState &state,
                                         std::vector<CTxOut> &txOutputs,
                                         CPBaaSNotarization &notarization);

    // accepts enough information to build a local accepted notarization transaction
    // miner fees are deferred until an import that uses this notarization, in which case
    // Proposer will get a share of the fees, if they are large enough. any miner,
    // who is mining the bridge can make such a notarization.
    static bool CreateAcceptedNotarization(const CCurrencyDefinition &externalSystem,
                                           const CPBaaSNotarization &notarization,
                                           const CNotaryEvidence &notaryEvidence,
                                           CValidationState &state,
                                           TransactionBuilder &txBuilder);

    static bool ConfirmOrRejectNotarizations(const CWallet *pWallet,
                                             const CRPCChainData &externalSystem,
                                             CValidationState &state,
                                             TransactionBuilder &txBuilder,
                                             bool &finalized);

    static std::vector<uint256> SubmitFinalizedNotarizations(const CRPCChainData &externalSystem,
                                                             CValidationState &state);

    bool CheckProof(const uint160 &systemID, const CMMRProof &transactionBlockProof, uint256 checkHash)
    {
        auto proofRootIt = proofRoots.find(systemID);
        if (proofRootIt == proofRoots.end())
        {
            return false;
        }
        return transactionBlockProof.CheckProof(checkHash) == proofRootIt->second.stateRoot;
    }

    CProofRoot GetProofRoot(const uint160 &systemID) const
    {
        auto proofRootIt = proofRoots.find(systemID);
        if (proofRootIt == proofRoots.end())
        {
            return CProofRoot();
        }
        return proofRootIt->second;
    }

    void SetSameChain(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_SAME_CHAIN;
        }
        else
        {
            flags &= ~FLAG_SAME_CHAIN;
        }
    }

    bool IsSameChain() const
    {
        return flags & FLAG_SAME_CHAIN;
    }

    bool IsMirror() const
    {
        return flags & FLAG_ACCEPTED_MIRROR;
    }

    // both sets the mirror flag and also transforms the notarization
    // between mirror states. returns false if could not change state to requested.
    bool SetMirror(bool setTrue=true, bool transform=true)
    {
        // if we are not changing the mirror state, just return
        if (setTrue == IsMirror())
        {
            return true;
        }

        // we can only reverse notarizations with two proof roots
        // one must be the current chain, and the other is to reverse
        if (proofRoots.size() != 2 ||
            currencyStates.count(currencyID) ||
            !(proofRoots.begin()->first == ASSETCHAINS_CHAINID || (++proofRoots.begin())->first == ASSETCHAINS_CHAINID))
        {
            LogPrintf("%s: invalid earned notarization for acceptance\n", __func__);
            return false;
        }

        uint160 oldCurrencyID = currencyID;
        uint160 altCurrencyID = proofRoots.begin()->first == ASSETCHAINS_CHAINID ? (++proofRoots.begin())->first : proofRoots.begin()->first;
        uint160 newCurrencyID = proofRoots.begin()->first == currencyID ? (++proofRoots.begin())->first : proofRoots.begin()->first;

        if ((currencyID == ASSETCHAINS_CHAINID && !currencyStates.count(currencyID)) ||
            (currencyID != ASSETCHAINS_CHAINID && !currencyStates.count(ASSETCHAINS_CHAINID)))
        {
            LogPrintf("%s: notarization for acceptance must include both currency states\n", __func__);
            return false;
        }

        if (transform)
        {
            currencyStates.insert(std::make_pair(oldCurrencyID, currencyState));
            currencyState = currencyStates[newCurrencyID];
            currencyStates.erase(newCurrencyID);
            currencyID = newCurrencyID;
        }

        if (setTrue)
        {
            flags |= FLAG_ACCEPTED_MIRROR;
        }
        else
        {
            flags &= ~FLAG_ACCEPTED_MIRROR;
        }
        return true;
    }

    bool IsDefinitionNotarization() const
    {
        return flags & FLAG_DEFINITION_NOTARIZATION;
    }

    void SetDefinitionNotarization(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_DEFINITION_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_DEFINITION_NOTARIZATION;
        }
    }

    bool IsBlockOneNotarization() const
    {
        return flags & FLAG_BLOCKONE_NOTARIZATION;
    }

    void SetBlockOneNotarization(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_BLOCKONE_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_BLOCKONE_NOTARIZATION;
        }
    }

    bool IsPreLaunch() const
    {
        return flags & FLAG_PRE_LAUNCH;
    }

    void SetPreLaunch(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_PRE_LAUNCH;
        }
        else
        {
            flags &= ~FLAG_PRE_LAUNCH;
        }
    }

    bool IsLaunchCleared() const
    {
        return flags & FLAG_START_NOTARIZATION;
    }

    void SetLaunchCleared(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_START_NOTARIZATION;
        }
        else
        {
            flags &= ~FLAG_START_NOTARIZATION;
        }
    }

    bool IsLaunchConfirmed() const
    {
        return flags & FLAG_LAUNCH_CONFIRMED;
    }

    void SetLaunchConfirmed(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_LAUNCH_CONFIRMED;
        }
        else
        {
            flags &= ~FLAG_LAUNCH_CONFIRMED;
        }
    }

    bool IsRefunding() const
    {
        return flags & FLAG_REFUNDING;
    }

    void SetRefunding(bool setTrue=true)
    {
        if (setTrue)
        {
            flags |= FLAG_REFUNDING;
        }
        else
        {
            flags &= ~FLAG_REFUNDING;
        }
    }

    UniValue ToUniValue() const;
};

class CObjectFinalization
{
public:
    static const int32_t UNCONFIRMED_INPUT = -1;
    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        VERSION_CURRENT = 1
    };

    enum EFinalizationType {
        FINALIZE_INVALID = 0,
        FINALIZE_NOTARIZATION = 1,      // confirmed when notarization is deemed correct / final
        FINALIZE_EXPORT = 2,            // confirmed when export has no more work to do
        FINALIZE_CURRENCY_LAUNCH = 4,   // confirmed on successful currency launch, rejected on refund
        FINALIZE_REJECTED = 0x40,       // flag set when confirmation is rejected and/or proven false
        FINALIZE_CONFIRMED = 0x80,      // flag set when object finalization is confirmed
        FINALIZE_TYPE_MASK = ~(FINALIZE_REJECTED | FINALIZE_CONFIRMED)
    };

    uint8_t version;
    uint8_t finalizationType;
    uint32_t minFinalizationHeight;     // to enable indexing/querying potential finalizations by height
    uint160 currencyID;                 // here when needed for indexing purposes
    CUTXORef output;                    // output/object to finalize
    std::vector<int32_t> evidenceInputs; // indexes into vin that are evidence to support the current state
    std::vector<int32_t> evidenceOutputs; // tx output indexes that are evidence to support the current state    

    CObjectFinalization() : version(VERSION_INVALID), finalizationType(FINALIZE_INVALID) {}
    CObjectFinalization(uint8_t fType, const uint160 &curID, const uint256 &TxId, uint32_t outNum, uint32_t minFinalHeight=0) : 
        version(VERSION_CURRENT), finalizationType(fType), minFinalizationHeight(minFinalHeight), currencyID(curID), output(TxId, outNum) {}
    CObjectFinalization(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }
    CObjectFinalization(const CTransaction &tx, uint32_t *pEcode=nullptr, int32_t *pFinalizationOutNum=nullptr);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(finalizationType);
        READWRITE(currencyID);
        READWRITE(output);
        if (IsConfirmed() || IsRejected())
        {
            READWRITE(evidenceInputs);
            READWRITE(evidenceOutputs);
        }
    }

    bool IsValid() const
    {
        return version >= VERSION_FIRST && 
                version <= VERSION_LAST &&
                finalizationType != FINALIZE_INVALID && 
                !currencyID.IsNull() &&
                output.IsValid();
    }

    bool IsPending() const
    {
        return !(finalizationType & FINALIZE_REJECTED || finalizationType & FINALIZE_CONFIRMED);
    }

    bool IsConfirmed() const
    {
        return finalizationType & FINALIZE_CONFIRMED;
    }

    void SetConfirmed(bool setTrue=true)
    {
        if (setTrue)
        {
            SetRejected(false);
            finalizationType |= FINALIZE_CONFIRMED;
        }
        else
        {
            finalizationType &= ~FINALIZE_CONFIRMED;
        }
    }

    bool IsRejected() const
    {
        return finalizationType & FINALIZE_REJECTED;
    }

    void SetRejected(bool setTrue=true)
    {
        if (setTrue)
        {
            SetConfirmed(false);
            finalizationType |= FINALIZE_REJECTED;
        }
        else
        {
            finalizationType &= ~FINALIZE_REJECTED;
        }
    }

    bool IsLaunchFinalization() const
    {
        return (finalizationType & FINALIZE_TYPE_MASK) == FINALIZE_CURRENCY_LAUNCH;
    }

    bool IsExportFinalization() const
    {
        return (finalizationType & FINALIZE_TYPE_MASK) == FINALIZE_EXPORT;
    }

    bool IsNotarizationFinalization() const
    {
        return (finalizationType & FINALIZE_TYPE_MASK) == FINALIZE_NOTARIZATION;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool GetOutputTransaction(const CTransaction &initialTx, CTransaction &tx, uint256 &blockHash) const;

    // Sign the output object with an ID or signing authority of the ID from the wallet.
    CNotaryEvidence SignConfirmed(const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID) const;
    CNotaryEvidence SignRejected(const CWallet *pWallet, const CTransaction &initialTx, const CIdentityID &signatureID) const;

    // Verify that the output object is signed with an ID or signing authority of the ID from the wallet.
    CIdentitySignature::ESignatureVerification VerifyOutputSignature(const CTransaction &initialTx, const CNotaryEvidence &signature, const COptCCParams &p, uint32_t height) const;
    CIdentitySignature::ESignatureVerification VerifyOutputSignature(const CTransaction &initialTx, const CNotaryEvidence &signature, uint32_t height) const;

    std::vector<std::pair<uint32_t, CInputDescriptor>> GetUnspentNotaryEvidence() const;

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationPendingKeyName()
    {
        return "vrsc::system.finalization.pending";
    }

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationPrelaunchKeyName()
    {
        return "vrsc::system.finalization.prelaunch";
    }

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationNotarizationKeyName()
    {
        return "vrsc::system.finalization.notarization";
    }

    // enables easily finding all pending finalizations for a
    // currency, either notarizations or exports
    static std::string ObjectFinalizationExportKeyName()
    {
        return "vrsc::system.finalization.export";
    }

    // enables easily finding all confirmed finalizations
    static std::string ObjectFinalizationConfirmedKeyName()
    {
        return "vrsc::system.finalization.confirmed";
    }

    // enables location of rejected finalizations
    static std::string ObjectFinalizationRejectedKeyName()
    {
        return "vrsc::system.finalization.rejected";
    }

    static uint160 ObjectFinalizationPendingKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationPendingKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationPrelaunchKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationPrelaunchKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationNotarizationKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationNotarizationKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationExportKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationExportKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationConfirmedKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationConfirmedKeyName(), nameSpace);
        return key;
    }

    static uint160 ObjectFinalizationRejectedKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ObjectFinalizationRejectedKeyName(), nameSpace);
        return key;
    }

    UniValue ToUniValue() const;
};

class CChainNotarizationData
{
public:
    static const int CURRENT_VERSION = PBAAS_VERSION;
    uint32_t version;

    std::vector<std::pair<CUTXORef, CPBaaSNotarization>> vtx;
    int32_t lastConfirmed;                          // last confirmed notarization
    std::vector<std::vector<int32_t>> forks;        // chains that represent alternate branches from the last confirmed notarization
    int32_t bestChain;                              // index in forks of the chain, beginning with the last confirmed notarization, that has the most power

    CChainNotarizationData() : version(0), lastConfirmed(-1) {}

    CChainNotarizationData(const std::vector<std::pair<CUTXORef, CPBaaSNotarization>> &txes,
                           int32_t lastConf=-1,
                           const std::vector<std::vector<int32_t>> &Forks=std::vector<std::vector<int32_t>>(),
                           int32_t Best=-1, 
                           uint32_t ver=CURRENT_VERSION) : 
                           version(ver),
                           vtx(txes), 
                           lastConfirmed(lastConf), 
                           bestChain(Best), 
                           forks(Forks) {}

    CChainNotarizationData(std::vector<unsigned char> vch)
    {
        ::FromVector(vch, *this);
    }

    CChainNotarizationData(UniValue &obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(vtx);
        READWRITE(bestChain);
        READWRITE(lastConfirmed);
        READWRITE(forks);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        // this needs an actual check
        return version != 0;
    }

    bool IsConfirmed() const
    {
        return lastConfirmed != -1;
    }

    UniValue ToUniValue() const;
};

bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsEarnedNotarizationInput(const CScript &scriptSig);
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsAcceptedNotarizationInput(const CScript &scriptSig);
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsFinalizeNotarizationInput(const CScript &scriptSig);
bool IsNotaryEvidenceInput(const CScript &scriptSig);
extern string PBAAS_HOST, PBAAS_USERPASS, ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;;
extern int32_t PBAAS_PORT;

#endif
