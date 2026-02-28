from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import AnalysisError, analyze_taproot
from .fetch_witness import FetchWitnessError, fetch_witness_by_txid
from .models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ErrorResponse,
    FetchWitnessErrorResponse,
    FetchWitnessResponse,
)


app = FastAPI(title="RootScope Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse, responses={400: {"model": ErrorResponse}})
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return analyze_taproot(
            control_block=request.controlBlock,
            script=request.script,
            network=request.network,
            expected_address=request.expectedAddress,
        )
    except AnalysisError as exc:
        raise HTTPException(status_code=400, detail={"errorCode": exc.code, "message": exc.message}) from exc


@app.get(
    "/fetch-witness",
    response_model=FetchWitnessResponse,
    responses={400: {"model": FetchWitnessErrorResponse}, 404: {"model": FetchWitnessErrorResponse}},
)
def fetch_witness(txid: str, vin: int, network: str = "auto") -> FetchWitnessResponse:
    try:
        payload = fetch_witness_by_txid(txid=txid, vin=vin, network=network)
        return FetchWitnessResponse(**payload)
    except FetchWitnessError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.to_payload()) from exc
