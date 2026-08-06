# ───────────────────────────────────────────────────────────────
# RootScope x402 API —— 把 Taproot 脚本路径确定性重建做成按次付费 API
#   GET /decode-taproot?txid=&vin=&network=   (network=被分析的比特币网络)
#   付费墙:x402 exact,USDC。env 驱动:测试网/主网一键切。
#   有 CDP 凭据 → 用 CDP facilitator(可上 Bazaar);否则 x402.org(测试网)。
# 本地:  uvicorn app:app --port 4033
# Render: uvicorn app:app --host 0.0.0.0 --port $PORT
# ───────────────────────────────────────────────────────────────
import os
from fastapi import FastAPI, HTTPException
from backend.analyzer import analyze_taproot, AnalysisError
from backend.fetch_witness import fetch_witness_by_txid, FetchWitnessError
from x402 import x402ResourceServer
from x402.http import HTTPFacilitatorClient
from x402.http.middleware.fastapi import payment_middleware
from x402.mechanisms.evm.exact.server import ExactEvmScheme

X402_NETWORK = os.environ.get("X402_NETWORK", "eip155:84532")  # 主网改 eip155:8453
PAY_TO = os.environ.get("PAY_TO", "0x4b5887B6E399C2E104becd01f7c406229c15891d")
PRICE = os.environ.get("PRICE", "$0.001")                       # 主网可设 "$0.01"

CDP_HOST = "api.cdp.coinbase.com"
CDP_BASE = "/platform/v2/x402"


def make_facilitator():
    """有 CDP 凭据 → CDP facilitator(可被 Bazaar 收录);否则默认 x402.org(测试网)。
    每个端点各签一个绑定 method+host+path 的短期 JWT(cdp-sdk),经 x402 的
    {"url","create_headers"} 协议交给 HTTPFacilitatorClient。
    """
    key_id = os.environ.get("CDP_API_KEY_ID")
    key_secret = os.environ.get("CDP_API_KEY_SECRET")
    if key_id and key_secret:
        from cdp.auth.utils.http import get_auth_headers, GetAuthHeadersOptions

        def _h(method, path):
            return get_auth_headers(GetAuthHeadersOptions(
                api_key_id=key_id, api_key_secret=key_secret,
                request_method=method, request_host=CDP_HOST, request_path=path,
            ))

        def create_headers():
            return {
                "verify":    _h("POST", CDP_BASE + "/verify"),
                "settle":    _h("POST", CDP_BASE + "/settle"),
                "supported": _h("GET",  CDP_BASE + "/supported"),
                "list":      _h("GET",  CDP_BASE + "/discovery/resources"),
            }

        return HTTPFacilitatorClient({"url": f"https://{CDP_HOST}{CDP_BASE}", "create_headers": create_headers})
    return HTTPFacilitatorClient()


facilitator = make_facilitator()
server = x402ResourceServer(facilitator).register(X402_NETWORK, ExactEvmScheme())

# Bazaar 发现元数据:让 agent 在 Bazaar 上搜到、知道怎么调
BAZAAR = {
    "info": {
        "input": {
            "type": "http",
            "method": "GET",
            "queryParams": {
                "txid": "Bitcoin transaction id (hex)",
                "vin": "input index (integer, default 0)",
                "network": "mainnet | testnet",
            },
        },
        "output": {
            "type": "object",
            "example": {
                "address": "bc1p...", "addressMatch": True,
                "outputKey": "…", "merkleRootHex": "…", "tweakHex": "…", "leafHex": "…",
            },
        },
    },
    "schema": {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "addressMatch": {"type": "boolean"},
            "outputKey": {"type": "string"},
            "merkleRootHex": {"type": "string"},
            "tweakHex": {"type": "string"},
            "leafHex": {"type": "string"},
            "steps": {"type": "array"},
        },
    },
}

routes = {
    "GET /decode-taproot": {
        "accepts": {"scheme": "exact", "payTo": PAY_TO, "price": PRICE, "network": X402_NETWORK},
        "description": "Deterministic Taproot script-path reconstruction: given a Bitcoin txid+vin, "
                       "fetch the witness and rebuild TapLeaf/Merkle/TapTweak/output key, then verify the bech32m address.",
        "mimeType": "application/json",
        "extensions": {"bazaar": BAZAAR},
    }
}

app = FastAPI(title="RootScope x402 API")


@app.middleware("http")
async def x402_gate(request, call_next):
    return await payment_middleware(routes, server)(request, call_next)


@app.get("/decode-taproot")
def decode_taproot(txid: str, vin: int = 0, network: str = "mainnet"):
    try:
        w = fetch_witness_by_txid(txid=txid, vin=vin, network=network)
    except FetchWitnessError as e:
        raise HTTPException(status_code=e.status_code, detail=e.to_payload())
    try:
        result = analyze_taproot(
            control_block=w["controlBlockHex"], script=w["scriptHex"],
            network=w["network"], expected_address=w.get("expectedAddress"),
        )
    except AnalysisError as e:
        raise HTTPException(status_code=400, detail={"errorCode": e.code, "message": e.message})
    return {
        "txid": txid, "vin": vin, "network": w["network"],
        "outputKey": result.outputKey, "address": result.address,
        "addressMatch": result.checks.expectedAddressMatch,
        "merkleRootHex": result.merkleRootHex, "tweakHex": result.tweakHex,
        "leafHex": result.leafHex, "steps": [s.model_dump() for s in result.steps],
    }


@app.get("/health")
def health():
    return {"status": "ok", "network": X402_NETWORK, "price": PRICE}
