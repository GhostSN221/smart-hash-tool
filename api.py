#!/usr/bin/env python3

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import os

from smart_hash_cracker import analyze, generate_hashes, detect_hash_types, hibp_lookup

app = FastAPI(
    title="Smart Hash Tool API",
    description="Analyze, crack, and generate hashes. Zero config.",
    version="2.0.0",
)

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlist.txt")


class AnalyzeRequest(BaseModel):
    string: str
    wordlist: Optional[str] = None
    rules: bool = False
    hibp: bool = False


class CrackRequest(BaseModel):
    hash: str
    wordlist: Optional[str] = None
    rules: bool = False


class GenerateRequest(BaseModel):
    plaintext: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest):
    wordlist = req.wordlist or (DEFAULT_WORDLIST if os.path.exists(DEFAULT_WORDLIST) else None)
    return analyze(
        req.string.strip(),
        wordlist=wordlist,
        json_mode=True,
        use_rules=req.rules,
        use_hibp=req.hibp,
    )


@app.post("/generate")
def generate_endpoint(req: GenerateRequest):
    return {
        "plaintext": req.plaintext,
        "hashes": generate_hashes(req.plaintext),
    }


@app.post("/crack")
def crack_endpoint(req: CrackRequest):
    hash_types = detect_hash_types(req.hash.strip())
    if not hash_types:
        raise HTTPException(status_code=400, detail="Input is not a recognized hash format.")

    wordlist = req.wordlist or DEFAULT_WORDLIST
    if not os.path.exists(wordlist):
        raise HTTPException(status_code=400, detail=f"Wordlist not found: {wordlist}")

    result = analyze(
        req.hash.strip(),
        wordlist=wordlist,
        json_mode=True,
        use_rules=req.rules,
    )
    return result


@app.get("/hibp/{sha1_hash}")
def hibp_endpoint(sha1_hash: str):
    if len(sha1_hash) != 40:
        raise HTTPException(status_code=400, detail="HIBP lookup requires a SHA1 hash (40 hex chars).")
    count = hibp_lookup(sha1_hash)
    if count is None:
        raise HTTPException(status_code=503, detail="HIBP API unavailable.")
    return {
        "hash": sha1_hash.lower(),
        "breached": count > 0,
        "occurrences": count,
    }


@app.get("/detect/{string}")
def detect_endpoint(string: str):
    types = detect_hash_types(string)
    return {
        "input": string,
        "hash_types": types,
        "is_hash": len(types) > 0,
    }
