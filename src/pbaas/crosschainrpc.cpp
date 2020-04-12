/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS cross chain communication.
 * 
 * In merge mining and notarization, Verus acts as a hub that other PBaaS chains
 * call via RPC in order to get information that allows earning and submitting
 * notarizations.
 * 
 * All PBaaS chains communicate with their primary reserve chain, which is either Verus
 * or the chain that is their reserve coin. The child PBaaS chain initiates all of
 * the communication with the parent / reserve daemon.
 * 
 * Generally, the PBaaS chain will call the Verus chain to either get information needed
 * to create an earned or accepted notarization. If there is no Verus daemon available
 * staking and mining of a PBaaS chain proceeds as usual, but without notarization
 * reward opportunities.
 * 
 */

#include "chainparamsbase.h"
#include "clientversion.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/filesystem/operations.hpp>
#include <boost/format.hpp>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include "support/events.h"

#include <univalue.h>

#include "uint256.h"
#include "hash.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/identity.h"

using namespace std;

extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

static CCrossChainRPCData LoadFromConfig(std::string name)
{
    map<string, string> settings;
    map<string, vector<string>> settingsmulti;
    CCrossChainRPCData ret;

    // if we are requested to automatically load the information from the Verus chain, do it if we can find the daemon
    if (ReadConfigFile(name, settings, settingsmulti))
    {
        auto rpcuser = settings.find("-rpcuser");
        auto rpcpwd = settings.find("-rpcpassword");
        auto rpcport = settings.find("-rpcport");
        auto rpchost = settings.find("-rpchost");
        ret.credentials = rpcuser != settings.end() ? rpcuser->second + ":" : "";
        ret.credentials += rpcpwd != settings.end() ? rpcpwd->second : "";
        ret.port = rpcport != settings.end() ? atoi(rpcport->second) : (name == "VRSC" ? 27486 : 0);
        ret.host = rpchost != settings.end() ? rpchost->second : "127.0.0.1";
    }
    return ret;
}

// credentials for now are "user:password"
UniValue RPCCall(const string& strMethod, const UniValue& params, const string credentials, int port, const string host, int timeout)
{
    // Used for inter-daemon communicatoin to enable merge mining and notarization without a client
    //

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), timeout);

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(credentials)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

UniValue RPCCallRoot(const string& strMethod, const UniValue& params, int timeout)
{
    string host, credentials;
    int port;
    map<string, string> settings;
    map<string, vector<string>> settingsmulti;

    if (PBAAS_HOST != "" && PBAAS_PORT != 0)
    {
        return RPCCall(strMethod, params, PBAAS_USERPASS, PBAAS_PORT, PBAAS_HOST);
    }
    else if (ReadConfigFile(PBAAS_TESTMODE ? "VRSCTEST" : "VRSC", settings, settingsmulti))
    {
        PBAAS_USERPASS = settingsmulti.find("-rpcuser")->second[0] + ":" + settingsmulti.find("-rpcpassword")->second[0];
        PBAAS_PORT = atoi(settingsmulti.find("-rpcport")->second[0]);
        PBAAS_HOST = settingsmulti.find("-rpchost")->second[0];
        if (!PBAAS_HOST.size())
        {
            PBAAS_HOST = "127.0.0.1";
        }
        return RPCCall(strMethod, params, credentials, port, host, timeout);
    }
    return UniValue(UniValue::VNULL);
}

bool uni_get_bool(UniValue uv, bool def)
{
    try
    {
        if (uv.isStr())
        {
            std::string boolStr;
            if ((boolStr = uni_get_str(uv, def ? "true" : "false")) == "true" || boolStr == "1")
            {
                return true;
            }
            else if (boolStr == "false" || boolStr == "0")
            {
                return false;
            }
            return def;
        }
        else
        {
            return uv.get_bool();
        }
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int32_t uni_get_int(UniValue uv, int32_t def)
{
    try
    {
        return uv.get_int();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

int64_t uni_get_int64(UniValue uv, int64_t def)
{
    try
    {
        return uv.get_int64();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::string uni_get_str(UniValue uv, std::string def)
{
    try
    {
        return uv.get_str();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

std::vector<UniValue> uni_getValues(UniValue uv, std::vector<UniValue> def)
{
    try
    {
        return uv.getValues();
    }
    catch(const std::exception& e)
    {
        return def;
    }
}

UniValue CCrossChainRPCData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("host", host));
    obj.push_back(Pair("port", port));
    obj.push_back(Pair("credentials", credentials));
    return obj;
}

CNodeData::CNodeData(const UniValue &obj)
{
    networkAddress = uni_get_str(find_value(obj, "networkaddress"));
    CTxDestination dest = DecodeDestination(uni_get_str(find_value(obj, "nodeidentity")));
    if (dest.which() != COptCCParams::ADDRTYPE_ID)
    {
        nodeIdentity = uint160();
    }
    else
    {
        nodeIdentity = GetDestinationID(dest);
    }
}

CNodeData::CNodeData(std::string netAddr, std::string paymentAddr) :
    networkAddress(netAddr)
{
    nodeIdentity = GetDestinationID(DecodeDestination(paymentAddr));
}

UniValue CNodeData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("networkaddress", networkAddress));
    obj.push_back(Pair("nodeidentity", EncodeDestination(CIdentityID(nodeIdentity))));
    return obj;
}

uint160 CurrencyNameToChainID(std::string currencyStr)
{
    std::string extraName;
    uint160 retVal;
    currencyStr = TrimSpaces(currencyStr);
    if (!currencyStr.size())
    {
        return retVal;
    }
    ParseSubNames(currencyStr, extraName, true);
    if (currencyStr.back() == '@' || extraName != "")
    {
        return retVal;
    }
    CTxDestination currencyDest = DecodeDestination(currencyStr);
    if (currencyDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        currencyDest = DecodeDestination(currencyStr + "@");
    }
    if (currencyDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        retVal = GetDestinationID(currencyDest);
    }
    return retVal;
}

CCurrencyDefinition::CCurrencyDefinition(const UniValue &obj)
{
    try
    {
        nVersion = PBAAS_VERSION;
        name = std::string(uni_get_str(find_value(obj, "name")), 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));

        std::string parentStr = uni_get_str(find_value(obj, "parent"));
        if (parentStr != "")
        {
            CTxDestination parentDest = DecodeDestination(parentStr);
            parent = GetDestinationID(parentDest);
            // if we have a destination, but it is invalid, the json for this definition cannot be valid
            if (parentDest.which() == COptCCParams::ADDRTYPE_INVALID)
            {
                nVersion = PBAAS_VERSION_INVALID;
            }
        }

        name = CleanName(name, parent);

        options = (uint32_t)uni_get_int64(find_value(obj, "options"));

        idRegistrationAmount = AmountFromValueNoErr(find_value(obj, "idregistrationprice"));
        idReferralLevels = uni_get_int(find_value(obj, "idreferrallevels"));

        UniValue notaryArr = find_value(obj, "notaries");
        minNotariesConfirm = 0;
        if (notaryArr.isArray())
        {
            for (int i = 0; i < notaryArr.size(); i++)
            {
                CIdentityID notaryID;
                CTxDestination notaryDest = DecodeDestination(uni_get_str(notaryArr[i]));
                notaryID = GetDestinationID(notaryDest);
                // if we have a destination, but it is invalid, the json for this definition cannot be valid
                if (notaryID.IsNull())
                {
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    notaries.push_back(notaryID);
                }
            }
            minNotariesConfirm = uni_get_int(find_value(obj, "minnotariesconfirm"));
        }
        billingPeriod = uni_get_int(find_value(obj, "billingperiod"));
        notarizationReward = AmountFromValueNoErr(find_value(obj, "notarizationreward"));

        startBlock = uni_get_int(find_value(obj, "startblock"));
        endBlock = uni_get_int(find_value(obj, "endblock"));

        proofProtocol = (EProofProtocol)uni_get_int(find_value(obj, "proofprotocol"), (int32_t)PROOF_PBAASMMR);
        notarizationProtocol = (ENotarizationProtocol)uni_get_int(find_value(obj, "notarizationprotocol"), (int32_t)NOTARIZATION_AUTO);
        int32_t totalReserveWeight = AmountFromValueNoErr(find_value(obj, "reserveratio"));
        UniValue currencyArr = find_value(obj, "currencies");
        UniValue weightArr = find_value(obj, "weights");
        UniValue conversionArr = find_value(obj, "conversions");
        UniValue minPreconvertArr = find_value(obj, "minpreconversion");
        UniValue maxPreconvertArr = find_value(obj, "maxpreconversion");
        UniValue initialContributionArr = find_value(obj, "initialcontributions");
        UniValue preConversionsArr = find_value(obj, "preconversions");

        bool convertible = false;

        if (currencyArr.isArray() && currencyArr.size())
        {
            // if weights are defined, make sure they are defined correctly, if not, define them
            if (weightArr.isArray() && weightArr.size())
            {
                if (weightArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: reserve currency weights must be specified for all currencies\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    for (int i = 0; i < currencyArr.size(); i++)
                    {
                        int32_t weight = (int32_t)AmountFromValueNoErr(weightArr[i]);
                        if (weight <= 0)
                        {
                            nVersion = PBAAS_VERSION_INVALID;
                            break;
                        }
                        weights.push_back(weight);
                    }
                }
            }
            else if (totalReserveWeight)
            {
                uint32_t oneWeight = totalReserveWeight / SATOSHIDEN;
                uint32_t mod = totalReserveWeight % SATOSHIDEN;
                for (int i = 0; i < currencyArr.size(); i++)
                {
                    // distribute remainder of weight among first come currencies
                    int32_t weight = oneWeight;
                    if (mod > 0)
                    {
                        weight++;
                        mod--;
                    }
                    weights.push_back(weight);
                }
            }

            // if we have weights, we can be a reserve currency
            if (weights.size())
            {
                // if we are a reserve currency, explicit conversion values are not valid
                // and are based on non-zero, initial contributions relative to supply
                if ((conversionArr.isArray() && conversionArr.size()) ||
                    !initialContributionArr.isArray() || 
                    initialContributionArr.size() != currencyArr.size() ||
                    weights.size() != currencyArr.size() ||
                    !IsReserve())
                {
                    LogPrintf("%s: reserve currencies must have weights, initial contributions in every currency, and no explicit conversion rates\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    convertible = true;
                }
            }
            else
            {
                // if we are not a reserve currency, we either have a conversion vector, or we are not convertible at all
                if (conversionArr.isArray() && conversionArr.size() && conversionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: non-reserve currencies must define all conversion rates for supported currencies if they define any\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else if (initialContributionArr.isArray() && initialContributionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: initial contributions for currencies must all be specified if any are specified\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                else
                {
                    convertible = true;
                }
            }

            if (convertible && nVersion != PBAAS_VERSION_INVALID)
            {
                if (minPreconvertArr.isArray() && minPreconvertArr.size() && minPreconvertArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies with minimum conversion required must define all minimums if they define any\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                if (maxPreconvertArr.isArray() && maxPreconvertArr.size() && maxPreconvertArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies that include maximum conversions on pre-launch must specify all maximums\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
                if (initialContributionArr.isArray() && initialContributionArr.size() && initialContributionArr.size() != currencyArr.size())
                {
                    LogPrintf("%s: currencies that include initial contributions in one currency on pre-launch must specify all currency amounts\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                }
            }

            bool isInitialContributions = initialContributionArr.isArray() && initialContributionArr.size();
            bool isPreconvertMin = minPreconvertArr.isArray() && minPreconvertArr.size();
            bool isPreconvertMax = maxPreconvertArr.isArray() && maxPreconvertArr.size();
            bool explicitConversions = conversionArr.isArray() && conversionArr.size();
            bool havePreConversions = preConversionsArr.isArray() && preConversionsArr.size();

            if (IsReserve() && explicitConversions)
            {
                LogPrintf("%s: cannot specify explicit conversion values for reserve currencies\n", __func__);
                nVersion = PBAAS_VERSION_INVALID;
            }

            for (int i = 0; nVersion != PBAAS_VERSION_INVALID && i < currencyArr.size(); i++)
            {
                uint160 currencyID = CurrencyNameToChainID(uni_get_str(currencyArr[i]));
                // if we have a destination, but it is invalid, the json for this definition cannot be valid
                if (currencyID.IsNull())
                {
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }
                else
                {
                    currencies.push_back(currencyID);
                }

                if (isInitialContributions)
                {
                    int64_t contrib = AmountFromValueNoErr(initialContributionArr[i]);
                    if (IsReserve() && contrib < MIN_RESERVE_CONTRIBUTION)
                    {
                        LogPrintf("%s: all fractional reserve currencies must start with %s minimum initial contribution in each currency\n", __func__, ValueFromAmount(MIN_RESERVE_CONTRIBUTION).write().c_str());
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    contributions.push_back(contrib);
                    preconverted.push_back(contrib);
                }

                if (havePreConversions && i < preConversionsArr.size())
                {
                    int64_t contrib = AmountFromValueNoErr(preConversionsArr[i]);
                    preconverted.push_back(contrib);
                }

                int64_t minPre = 0;
                if (isPreconvertMin)
                {
                    minPre = AmountFromValueNoErr(minPreconvertArr[i]);
                    if (minPre < 0)
                    {
                        LogPrintf("%s: minimum preconversions for any currency may not be less than 0\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    minPreconvert.push_back(minPre);
                }
                if (isPreconvertMax)
                {
                    int64_t maxPre = AmountFromValueNoErr(maxPreconvertArr[i]);
                    if (maxPre < 0 || maxPre < minPre)
                    {
                        LogPrintf("%s: maximum preconversions for any currency may not be less than 0 or minimum\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    maxPreconvert.push_back(maxPre);
                }
                if (explicitConversions)
                {
                    int64_t conversion = AmountFromValueNoErr(conversionArr[i]);
                    if (conversion < 0)
                    {
                        LogPrintf("%s: conversions for any currency must be greater than 0\n", __func__);
                        nVersion = PBAAS_VERSION_INVALID;
                        break;
                    }
                    conversions.push_back(conversion);
                }
            }
        }

        preAllocationRatio = AmountFromValueNoErr(find_value(obj, "preallocationratio"));

        UniValue preallocationArr = find_value(obj, "preallocation");
        if (preallocationArr.isArray())
        {
            for (int i = 0; i < preallocationArr.size(); i++)
            {
                std::vector<std::string> preallocationKey = preallocationArr[i].getKeys();
                std::vector<UniValue> preallocationValue = preallocationArr[i].getValues();
                if (preallocationKey.size() != 1 || preallocationValue.size() != 1)
                {
                    LogPrintf("%s: each preallocation entry must contain one destination identity and one amount\n", __func__);
                    printf("%s: each preallocation entry must contain one destination identity and one amount\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }

                CTxDestination preallocDest = DecodeDestination(preallocationKey[0]);

                if (preallocDest.which() != COptCCParams::ADDRTYPE_ID && preallocDest.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    LogPrintf("%s: preallocation destination must be an identity\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }

                CAmount preAllocAmount = AmountFromValueNoErr(preallocationValue[0]);
                if (preAllocAmount <= 0)
                {
                    LogPrintf("%s: preallocation values must be greater than zero\n", __func__);
                    nVersion = PBAAS_VERSION_INVALID;
                    break;
                }
                preAllocation.push_back(make_pair(CIdentityID(GetDestinationID(preallocDest)), preAllocAmount));
            }
        }

        auto vEras = uni_getValues(find_value(obj, "eras"));
        if (vEras.size() > ASSETCHAINS_MAX_ERAS)
        {
            vEras.resize(ASSETCHAINS_MAX_ERAS);
        }

        for (auto era : vEras)
        {
            rewards.push_back(uni_get_int64(find_value(era, "reward")));
            rewardsDecay.push_back(uni_get_int64(find_value(era, "decay")));
            halving.push_back(uni_get_int64(find_value(era, "halving")));
            eraEnd.push_back(uni_get_int64(find_value(era, "eraend")));
        }
    }
    catch (exception e)
    {
        LogPrintf("%s: exception reading currency definition JSON\n", __func__, e.what());
        nVersion = PBAAS_VERSION_INVALID;
    }
}

int64_t CCurrencyDefinition::CalculateRatioOfValue(int64_t value, int64_t ratio)
{
    arith_uint256 bigAmount(value);
    static const arith_uint256 bigSatoshi(SATOSHIDEN);

    int64_t retVal = ((bigAmount * arith_uint256(ratio)) / bigSatoshi).GetLow64();
    return retVal;
}

// this will only return an accurate result after total preconversion has been updated and before any emission
int64_t CCurrencyDefinition::GetTotalPreallocation() const
{
    CAmount totalPreconvertedNative = 0;
    CAmount totalPreallocatedNative = 0;
    if (preAllocationRatio == 0)
    {
        for (auto onePreallocation : preAllocation)
        {
            totalPreallocatedNative += onePreallocation.second;
        }
        return totalPreallocatedNative;
    }
    for (auto oneConversion : preconverted)
    {
        totalPreconvertedNative += oneConversion;
    }
    if (!totalPreconvertedNative || preAllocationRatio >= SATOSHIDEN)
    {
        return 0;
    }
    arith_uint256 bigAmount(totalPreconvertedNative);
    static const arith_uint256 bigSatoshi(SATOSHIDEN);
    arith_uint256 conversionPercent(preAllocationRatio);

    CAmount newAmount = ((bigAmount * bigSatoshi) / (bigSatoshi - conversionPercent)).GetLow64();
    CAmount retAmount = CalculateRatioOfValue(newAmount, preAllocationRatio);
    newAmount = totalPreconvertedNative + retAmount;

    retAmount = CalculateRatioOfValue(newAmount, preAllocationRatio); // again to account for minimum fee
    retAmount += totalPreconvertedNative - (newAmount - retAmount);   // add any additional difference
    return retAmount;
}

std::vector<std::pair<uint160, int64_t>> CCurrencyDefinition::GetPreAllocationAmounts() const
{
    if (!preAllocationRatio)
    {
        return preAllocation;
    }
    if (preAllocationRatio >= SATOSHIDEN)
    {
        return std::vector<std::pair<uint160, int64_t>>();
    }
    int64_t totalPreAllocation = GetTotalPreallocation();
    int64_t totalPreAllocUnits = 0;
    for (auto &onePreAlloc : preAllocation)
    {
        totalPreAllocUnits += onePreAlloc.second;
    }
    static arith_uint256 bigSatoshi(SATOSHIDEN);

    std::vector<std::pair<uint160, int64_t>> retVal(preAllocation.size());
    for (int i = 0; i < preAllocation.size(); i++)
    {
        if (i == preAllocation.size() - 1)
        {
            retVal[i] = make_pair(preAllocation[i].first, totalPreAllocation);
        }
        else
        {
            CAmount subRatio = ((arith_uint256(preAllocation[i].second) * bigSatoshi) / totalPreAllocUnits).GetLow64();
            CAmount thisPreAlloc = CalculateRatioOfValue(totalPreAllocation, subRatio);
            retVal[i] = make_pair(preAllocation[i].first, thisPreAlloc);
            totalPreAllocation -= thisPreAlloc;
        }
    }
    return retVal;
}

UniValue CCurrencyDefinition::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);

    obj.push_back(Pair("name", name));
    obj.push_back(Pair("version", (int64_t)nVersion));
    obj.push_back(Pair("options", (int64_t)options));
    obj.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(GetID()))));
    obj.push_back(Pair("notarizationprotocol", (int)notarizationProtocol));
    obj.push_back(Pair("proofprotocol", (int)proofProtocol));

    obj.push_back(Pair("idregistrationprice", idRegistrationAmount));
    obj.push_back(Pair("idreferrallevels", idReferralLevels));

    // notaries are identities that perform specific functions for the currency's operation
    // related to notarizing an external currency source, as well as proving imports
    if (notaries.size())
    {
        UniValue notaryArr(UniValue::VARR);
        for (auto &notary : notaries)
        {
            notaryArr.push_back(EncodeDestination(CIdentityID(notary)));
        }
        obj.push_back(Pair("notaries", notaryArr));
    }
    obj.push_back(Pair("minnotariesconfirm", minNotariesConfirm));

    obj.push_back(Pair("billingperiod", billingPeriod));
    obj.push_back(Pair("notarizationreward", notarizationReward));
    obj.push_back(Pair("startblock", (int32_t)startBlock));
    obj.push_back(Pair("endblock", (int32_t)endBlock));

    // notaries are identities that perform specific functions for the currency's operation
    // related to notarizing an external currency source, as well as proving imports
    if (currencies.size())
    {
        UniValue currencyArr(UniValue::VARR);
        for (auto &currency : currencies)
        {
            currencyArr.push_back(EncodeDestination(CIdentityID(currency)));
        }
        obj.push_back(Pair("currencies", currencyArr));
    }

    if (weights.size())
    {
        UniValue weightArr(UniValue::VARR);
        for (auto &weight : weights)
        {
            weightArr.push_back(ValueFromAmount(weight));
        }
        obj.push_back(Pair("weights", weightArr));
    }

    if (conversions.size())
    {
        UniValue conversionArr(UniValue::VARR);
        for (auto &conversion : conversions)
        {
            conversionArr.push_back(ValueFromAmount(conversion));
        }
        obj.push_back(Pair("conversions", conversionArr));
    }

    if (minPreconvert.size())
    {
        UniValue minPreconvertArr(UniValue::VARR);
        for (auto &oneMin : minPreconvert)
        {
            minPreconvertArr.push_back(ValueFromAmount(oneMin));
        }
        obj.push_back(Pair("minpreconversion", minPreconvertArr));
    }

    if (maxPreconvert.size())
    {
        UniValue maxPreconvertArr(UniValue::VARR);
        for (auto &oneMax : maxPreconvert)
        {
            maxPreconvertArr.push_back(ValueFromAmount(oneMax));
        }
        obj.push_back(Pair("maxpreconversion", maxPreconvertArr));
    }

    if (preAllocationRatio)
    {
        obj.push_back(Pair("preallocationratio", ValueFromAmount(preAllocationRatio)));
    }

    if (preAllocation.size())
    {
        UniValue preAllocationArr(UniValue::VARR);
        for (auto &onePreAllocation : preAllocation)
        {
            UniValue onePreAlloc(UniValue::VOBJ);
            onePreAlloc.push_back(Pair(EncodeDestination(CIdentityID(onePreAllocation.first)), ValueFromAmount(onePreAllocation.second)));
            preAllocationArr.push_back(onePreAlloc);
        }
        obj.push_back(Pair("preallocation", preAllocationArr));
    }

    if (contributions.size())
    {
        UniValue initialContributionArr(UniValue::VARR);
        for (auto &oneCurContributions : contributions)
        {
            initialContributionArr.push_back(ValueFromAmount(oneCurContributions));
        }
        obj.push_back(Pair("initialcontributions", initialContributionArr));
    }

    if (preconverted.size())
    {
        UniValue preconversionArr(UniValue::VARR);
        for (auto &onePreconversion : preconverted)
        {
            preconversionArr.push_back(ValueFromAmount(onePreconversion));
        }
        obj.push_back(Pair("preconversions", preconversionArr));
    }

    UniValue eraArr(UniValue::VARR);
    for (int i = 0; i < rewards.size(); i++)
    {
        UniValue era(UniValue::VOBJ);
        era.push_back(Pair("reward", rewards.size() > i ? rewards[i] : (int64_t)0));
        era.push_back(Pair("decay", rewardsDecay.size() > i ? rewardsDecay[i] : (int64_t)0));
        era.push_back(Pair("halving", halving.size() > i ? (int32_t)halving[i] : (int32_t)0));
        era.push_back(Pair("eraend", eraEnd.size() > i ? (int32_t)eraEnd[i] : (int32_t)0));
        eraArr.push_back(era);
    }
    obj.push_back(Pair("eras", eraArr));
    return obj;
}

