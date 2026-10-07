"""FastAPI wrapper around the guardrails engine.

Run with the application factory so nothing happens at import time:

    uvicorn app.main:create_app --factory --port 8000
"""
import json
import logging
import os
import secrets
import time
import uuid
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from .guardrails import VALID_CATEGORIES, GuardrailsEngine

logger = logging.getLogger("guardrails")
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "20000"))


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_CHARS,
                      description="The prompt or model response to screen.")
    include_redacted: bool = Field(False, description="Also return text with secrets/PII masked.")


class FindingOut(BaseModel):
    category: str
    rule: str
    start: int | None = None
    end: int | None = None


class CheckResponse(BaseModel):
    request_id: str
    direction: Literal["prompt", "response"]
    decision: Literal["allow", "block"]
    reasons: list[str]
    findings: list[FindingOut]
    redacted_text: str | None = None
    latency_ms: float


def _parse_categories(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return VALID_CATEGORIES
    cats = tuple(c.strip() for c in raw.split(",") if c.strip())
    return cats or VALID_CATEGORIES


def create_app(api_key: str | None = None, auth_disabled: bool | None = None,
               block_categories: tuple[str, ...] | None = None) -> FastAPI:
    api_key = api_key if api_key is not None else os.getenv("API_KEY", "")
    if auth_disabled is None:
        auth_disabled = os.getenv("GUARDRAILS_AUTH_DISABLED", "false").lower() == "true"
    if not auth_disabled and not api_key:
        raise RuntimeError("API_KEY is not set (set GUARDRAILS_AUTH_DISABLED=true for local development only)")

    engine = GuardrailsEngine(block_categories or _parse_categories(os.getenv("BLOCK_CATEGORIES")))
    app = FastAPI(title="LLM Guardrails Service", version="0.1.0")

    def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if auth_disabled:
            return
        if x_api_key is None or not secrets.compare_digest(x_api_key.encode(), api_key.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")

    def run(direction: str, req: CheckRequest) -> CheckResponse:
        t0 = time.perf_counter()
        result = engine.check(req.text)
        redacted = engine.redact(req.text, result.findings) if req.include_redacted else None
        latency_ms = (time.perf_counter() - t0) * 1000
        rid = str(uuid.uuid4())
        # Never log the text itself: it may contain the very secrets/PII we detect.
        logger.info(json.dumps({"request_id": rid, "direction": direction, "decision": result.decision,
                                "reasons": result.reasons, "chars": len(req.text),
                                "latency_ms": round(latency_ms, 3)}))
        return CheckResponse(
            request_id=rid, direction=direction, decision=result.decision, reasons=result.reasons,
            findings=[FindingOut(category=f.category, rule=f.rule, start=f.start, end=f.end)
                      for f in result.findings],
            redacted_text=redacted, latency_ms=round(latency_ms, 3))

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"])
    def readyz() -> dict:
        return {"status": "ready", "block_categories": sorted(engine.block_categories)}

    @app.post("/v1/check/prompt", response_model=CheckResponse, tags=["guardrails"],
              dependencies=[Depends(require_api_key)])
    def check_prompt(req: CheckRequest) -> CheckResponse:
        return run("prompt", req)

    @app.post("/v1/check/response", response_model=CheckResponse, tags=["guardrails"],
              dependencies=[Depends(require_api_key)])
    def check_response(req: CheckRequest) -> CheckResponse:
        return run("response", req)

    return app
