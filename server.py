#!/usr/bin/env python3
"""cerase-skillcheck — defensive static security scan for third-party skills.

A small HTTP service (FastAPI) that wraps the NVIDIA **skillspector** static
scanner (Apache-2.0, https://github.com/NVIDIA/skillspector) so the Cerase
platform can WARN a user, in plain language, before they install a risky
third-party skill.

This is DEFENSIVE tooling: the verdict is **advisory only** — it never blocks
an install and never quarantines anything. A caller (the control-plane at an
import chokepoint, or an agent via a CLI recipe) POSTs a skill and gets back a
risk verdict it can surface to the user, who always retains the final choice.

Scope (M-SKILLSCAN-1): **static-only**. skillspector's optional LLM analysis is
disabled here (`--no-llm`); wiring it through our LiteLLM is a later milestone.

Endpoints
  GET  /healthz        liveness + scanner version.
  POST /scan           JSON {path?|skill_md?} → verdict (mounted dir/file, or
                       raw SKILL.md content).
  POST /scan/bundle    multipart upload of a .zip skill bundle → verdict.

Verdict JSON
  {
    "score": 0-100,                              # skillspector risk score
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "recommendation": "SAFE|CAUTION|DO_NOT_INSTALL",
    "findings": [ ... ],                         # skillspector issues[]
    "scanner_version": "2.3.9",
    "mode": "static",
    "partial": bool,                             # true = SKILL.md-only scan
    "skill_name": str|null,
    "components_scanned": int
  }

skillspector invocation
  We shell out to the pinned CLI:
      skillspector scan <target> --no-llm --format json --output <tmp.json>
  and read the JSON report from the output file (decoupled from any console
  chatter on stdout). Exit code 0 (score<=50) and 1 (score>50) both produce a
  valid report — only exit 2 is a real error. skillspector's SC4 supply-chain
  check may reach out to OSV.dev; when the network is unavailable it degrades
  automatically to a built-in fallback list, so the verdict is still returned
  offline.

Env
  PORT                    listen port (default 8000).
  SKILLCHECK_SCAN_TIMEOUT per-scan subprocess timeout, seconds (default 180).
  SKILLCHECK_MAX_UPLOAD   max bundle upload size, bytes (default 25 MiB).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile
from pydantic import BaseModel, Field, model_validator

MODE = "static"
_VALID_RECOMMENDATIONS = {"SAFE", "CAUTION", "DO_NOT_INSTALL"}
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

_SCAN_TIMEOUT = int(os.environ.get("SKILLCHECK_SCAN_TIMEOUT", "180"))
_MAX_UPLOAD = int(os.environ.get("SKILLCHECK_MAX_UPLOAD", str(25 * 1024 * 1024)))

app = FastAPI(
    title="cerase-skillcheck",
    summary="Defensive static security scan for third-party agent skills.",
    version="1",
)


def _scanner_version() -> str:
    """skillspector package version — cheap (reads metadata, no heavy import)."""
    try:
        return _pkg_version("skillspector")
    except PackageNotFoundError:
        return "unknown"


class ScanRequest(BaseModel):
    """Scan input: exactly one of a mounted path or raw SKILL.md content."""

    path: str | None = Field(
        default=None,
        description="Path (already mounted in this container) to a skill directory "
        "or a single SKILL.md file to scan.",
    )
    skill_md: str | None = Field(
        default=None,
        description="Raw SKILL.md content to scan directly (SKILL.md-only = partial "
        "coverage; used when only the manifest is available).",
    )

    @model_validator(mode="after")
    def _exactly_one(self) -> ScanRequest:
        if bool(self.path) == bool(self.skill_md):
            raise ValueError("provide exactly one of 'path' or 'skill_md'")
        return self


class Verdict(BaseModel):
    score: int
    severity: str
    recommendation: str
    findings: list[dict[str, Any]]
    scanner_version: str
    mode: str = MODE
    partial: bool = False
    skill_name: str | None = None
    components_scanned: int = 0


class ScanError(RuntimeError):
    """skillspector failed to produce a report (non-verdict error)."""


def _scan_env() -> dict[str, str]:
    """Environment for the skillspector subprocess.

    Static-only: no LLM provider credentials are passed, and LangSmith tracing
    is force-disabled so a scan never phones home. HOME is kept writable for any
    cache the scanner touches.
    """
    env = dict(os.environ)
    env["LANGCHAIN_TRACING_V2"] = "false"
    env["LANGCHAIN_TRACING"] = "false"
    env.setdefault("SKILLSPECTOR_LOG_LEVEL", "ERROR")
    return env


def _run_static_scan(target: Path, *, partial: bool) -> Verdict:
    """Run skillspector static-only on *target* and map its report to a Verdict."""
    with tempfile.TemporaryDirectory(prefix="skillcheck-out-") as outdir:
        report_path = Path(outdir) / "report.json"
        cmd = [
            "skillspector",
            "scan",
            str(target),
            "--no-llm",
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT,
                env=_scan_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"scan timed out after {_SCAN_TIMEOUT}s") from exc
        except FileNotFoundError as exc:  # skillspector binary missing
            raise ScanError("skillspector executable not found") from exc

        # Exit 0 = clean/low, 1 = risky (score>50) — both still write a report.
        # Exit 2 (or any other) = a real scan error.
        if not report_path.exists():
            detail = (proc.stderr or proc.stdout or "").strip()[:2000]
            raise ScanError(detail or f"skillspector exited {proc.returncode} with no report")

        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"could not parse skillspector report: {exc}") from exc

    return _to_verdict(data, partial=partial)


def _to_verdict(data: dict[str, Any], *, partial: bool) -> Verdict:
    """Map a skillspector JSON report into our advisory Verdict.

    Defensive: clamps/normalises every field so a schema drift in the scanner
    degrades to a well-formed verdict rather than a 500.
    """
    risk = data.get("risk_assessment") or {}
    meta = data.get("metadata") or {}
    skill = data.get("skill") or {}

    try:
        score = int(risk.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))

    severity = str(risk.get("severity", "LOW")).upper()
    if severity not in _VALID_SEVERITIES:
        severity = "LOW"

    recommendation = str(risk.get("recommendation", "CAUTION")).upper()
    if recommendation not in _VALID_RECOMMENDATIONS:
        recommendation = "CAUTION"

    findings = data.get("issues")
    if not isinstance(findings, list):
        findings = []

    components = data.get("components")
    components_scanned = len(components) if isinstance(components, list) else 0

    return Verdict(
        score=score,
        severity=severity,
        recommendation=recommendation,
        findings=findings,
        scanner_version=str(meta.get("skillspector_version") or _scanner_version()),
        mode=MODE,
        partial=partial,
        skill_name=skill.get("name"),
        components_scanned=components_scanned,
    )


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness probe + scanner identity."""
    version = _scanner_version()
    return {
        "status": "ok",
        "service": "cerase-skillcheck",
        "scanner": "skillspector",
        "scanner_version": version,
        "scanner_available": version != "unknown",
        "mode": MODE,
    }


@app.post("/scan", response_model=Verdict)
def scan(req: ScanRequest) -> Verdict:
    """Scan a mounted path or raw SKILL.md content, static-only.

    A directory is a full scan; a lone `.md` file or `skill_md` content is a
    SKILL.md-only (partial) scan whose weaker coverage is flagged in `partial`.
    """
    if req.path:
        target = Path(req.path)
        if not target.exists():
            raise HTTPException(status_code=404, detail=f"path not found: {req.path}")
        partial = target.is_file() and target.suffix.lower() == ".md"
        try:
            return _run_static_scan(target, partial=partial)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=f"scan failed: {exc}") from exc

    # skill_md — write to a temp SKILL.md and scan (always partial coverage).
    with tempfile.TemporaryDirectory(prefix="skillcheck-md-") as tmp:
        md_path = Path(tmp) / "SKILL.md"
        md_path.write_text(req.skill_md or "", encoding="utf-8")
        try:
            return _run_static_scan(md_path, partial=True)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=f"scan failed: {exc}") from exc


@app.post("/scan/bundle", response_model=Verdict)
async def scan_bundle(file: UploadFile) -> Verdict:
    """Scan an uploaded **.zip** skill bundle (full directory scan)."""
    name = (file.filename or "").lower()
    if not name.endswith(".zip"):
        raise HTTPException(status_code=415, detail="only .zip bundles are supported")

    payload = await file.read()
    if len(payload) > _MAX_UPLOAD:
        raise HTTPException(
            status_code=413, detail=f"bundle exceeds {_MAX_UPLOAD} bytes"
        )

    tmp = tempfile.mkdtemp(prefix="skillcheck-bundle-")
    try:
        extract_dir = Path(tmp) / "skill"
        extract_dir.mkdir()
        try:
            with zipfile.ZipFile(_bytes_io(payload)) as zf:
                _safe_extract_zip(zf, extract_dir)
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=400, detail="invalid .zip bundle") from exc

        root = _skill_root(extract_dir)
        try:
            return _run_static_scan(root, partial=False)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=f"scan failed: {exc}") from exc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _bytes_io(payload: bytes):
    import io

    return io.BytesIO(payload)


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip, refusing path traversal (zip-slip) entries."""
    dest = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        if not str(target).startswith(str(dest)):
            raise HTTPException(status_code=400, detail="unsafe path in bundle")
    zf.extractall(dest)


def _skill_root(extracted: Path) -> Path:
    """Find the directory that holds SKILL.md (bundles often nest one level)."""
    if (extracted / "SKILL.md").exists():
        return extracted
    for child in sorted(extracted.iterdir()):
        if child.is_dir() and (child / "SKILL.md").exists():
            return child
    return extracted
