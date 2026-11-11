#!/usr/bin/env python3

import os
import re
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from smart_hash_cracker import analyze, detect_hash_types, generate_hashes, hibp_lookup

app = FastAPI(
    title="Smart Hash Tool API",
    description="Analyze, crack, and generate hashes. Zero config.",
    version="2.0.0",
)

DEFAULT_WORDLIST = Path(__file__).with_name("wordlist.txt")


def wordlist_dir() -> Path:
    """Files the API is allowed to read as wordlists.

    Restricting this to one directory prevents an API caller from pointing the
    cracker at arbitrary server files (for example /etc/passwd).
    """
    return Path(os.getenv("WORDLIST_DIR", Path(__file__).parent)).resolve()


def resolve_wordlist(wordlist: Optional[str]) -> str:
    base = wordlist_dir()
    candidate = Path(wordlist) if wordlist else Path("wordlist.txt")
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = candidate.resolve()

    try:
        candidate.relative_to(base)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Wordlist must be inside {base}",
        )

    if not candidate.is_file():
        raise HTTPException(status_code=400, detail=f"Wordlist not found: {candidate.name}")
    return str(candidate)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Optional API key. Set API_KEY to protect a publicly exposed instance."""
    expected = os.getenv("API_KEY", "")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class AnalyzeRequest(BaseModel):
    string: str = Field(min_length=1, max_length=4096)
    wordlist: Optional[str] = Field(default=None, max_length=255)
    rules: bool = False
    hibp: bool = False


class CrackRequest(BaseModel):
    hash: str = Field(min_length=1, max_length=4096)
    wordlist: Optional[str] = Field(default=None, max_length=255)
    rules: bool = False


class GenerateRequest(BaseModel):
    plaintext: str = Field(min_length=1, max_length=4096)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", dependencies=[Depends(require_api_key)])
def analyze_endpoint(req: AnalyzeRequest):
    if req.wordlist:
        wordlist = resolve_wordlist(req.wordlist)
    else:
        wordlist = str(DEFAULT_WORDLIST) if DEFAULT_WORDLIST.is_file() else None

    return analyze(
        req.string.strip(),
        wordlist=wordlist,
        json_mode=True,
        use_rules=req.rules,
        use_hibp=req.hibp,
    )


@app.post("/generate", dependencies=[Depends(require_api_key)])
def generate_endpoint(req: GenerateRequest):
    return {
        "plaintext": req.plaintext,
        "hashes": generate_hashes(req.plaintext),
    }


@app.post("/crack", dependencies=[Depends(require_api_key)])
def crack_endpoint(req: CrackRequest):
    hash_types = detect_hash_types(req.hash.strip())
    if not hash_types:
        raise HTTPException(status_code=400, detail="Input is not a recognized hash format.")

    wordlist = resolve_wordlist(req.wordlist)
    result = analyze(
        req.hash.strip(),
        wordlist=wordlist,
        json_mode=True,
        use_rules=req.rules,
    )
    return result


@app.get("/hibp/{sha1_hash}", dependencies=[Depends(require_api_key)])
def hibp_endpoint(sha1_hash: str):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha1_hash):
        raise HTTPException(status_code=400, detail="HIBP lookup requires a SHA1 hash (40 hex chars).")

    count = hibp_lookup(sha1_hash)
    if count is None:
        raise HTTPException(status_code=503, detail="HIBP API unavailable.")
    return {
        "hash": sha1_hash.lower(),
        "breached": count > 0,
        "occurrences": count,
    }


@app.get("/detect/{string}", dependencies=[Depends(require_api_key)])
def detect_endpoint(string: str):
    if len(string) > 4096:
        raise HTTPException(status_code=400, detail="Input is too long (max 4096 chars).")
    types = detect_hash_types(string)
    return {
        "input": string,
        "hash_types": types,
        "is_hash": len(types) > 0,
    }
