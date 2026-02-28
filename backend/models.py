from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Network = Literal["testnet", "mainnet"]


class AnalyzeRequest(BaseModel):
    controlBlock: str = Field(..., description="Hex control block from witness")
    script: str = Field(..., description="Hex executed script from witness")
    network: Network = Field(default="testnet")
    expectedAddress: str | None = Field(default=None)


class ControlBlockInfo(BaseModel):
    raw: str
    versionByte: int
    leafVersion: int
    parity: int
    internalKey: str
    depth: int
    path: list[str]


class StepInfo(BaseModel):
    id: str
    label: str
    formula: str
    hash: str
    leftHash: str | None = None
    rightHash: str | None = None
    sibling: str | None = None
    siblingIsRight: bool | None = None
    type: Literal["leaf", "branch", "root"]


class AnalysisChecks(BaseModel):
    expectedProvided: bool
    expectedAddressMatch: bool | None
    expectedAddressReason: str | None = None
    parityMatch: bool


class AnalyzeResponse(BaseModel):
    cb: ControlBlockInfo
    steps: list[StepInfo]
    leafHex: str
    merkleRootHex: str
    tweakHex: str
    outputKey: str
    computedParity: int
    parityMatch: bool
    address: str
    checks: AnalysisChecks


class ErrorResponse(BaseModel):
    errorCode: str
    message: str


class FetchWitnessResponse(BaseModel):
    ok: Literal[True]
    source: Literal["mempool", "blockstream"]
    network: Literal["testnet", "mainnet"]
    txid: str
    vin: int
    scriptHex: str
    controlBlockHex: str
    expectedAddress: str | None = None
    witnessStack: list[str]
    notes: list[str] = []


class FetchWitnessErrorResponse(BaseModel):
    ok: Literal[False]
    errorCode: str
    message: str
    details: dict | None = None
