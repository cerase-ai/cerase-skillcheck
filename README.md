# cerase-skillcheck

Defensive static security scan for third-party agent skills. A small FastAPI
HTTP service that wraps [NVIDIA **skillspector**](https://github.com/NVIDIA/skillspector)
(Apache-2.0) in **static-only** mode and returns an advisory risk verdict.

Its job is to let the Cerase platform **warn a user, in plain language, before
they install a risky third-party skill** — surfacing findings so they can judge.
The verdict is **advisory only**: it never blocks an install and never
quarantines anything. The user always retains the final choice.

This is **not an MCP** — it is a plain HTTP service. It runs as a
cluster-internal compose service in `cerase-core` (no public port); the
control-plane reaches it by hostname (`http://cerase-skillcheck:8000`).

## Endpoints

| Method | Path | Input | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | — | Liveness + scanner version. |
| `POST` | `/scan` | JSON `{path}` or `{skill_md}` | Scan a mounted skill dir / `.md`, or raw `SKILL.md` content. |
| `POST` | `/scan/bundle` | multipart `.zip` | Scan an uploaded skill bundle (full directory scan). |

`POST /scan` takes **exactly one** of:
- `path` — an absolute path already mounted in the container. A **directory** is
  a full scan; a lone `.md` file is a `SKILL.md`-only (partial) scan.
- `skill_md` — raw `SKILL.md` content, written to a temp file and scanned
  (always partial coverage — used when only the manifest is available).

## Verdict shape

```json
{
  "score": 72,
  "severity": "HIGH",
  "recommendation": "DO_NOT_INSTALL",
  "findings": [ { "rule_id": "...", "severity": "...", "message": "...", "file": "...", "confidence": 0.9 } ],
  "scanner_version": "2.3.9",
  "mode": "static",
  "partial": false,
  "skill_name": "my-skill",
  "components_scanned": 3
}
```

`recommendation` ∈ `SAFE | CAUTION | DO_NOT_INSTALL`; `severity` ∈
`LOW | MEDIUM | HIGH | CRITICAL`. `partial: true` flags a `SKILL.md`-only scan
(weaker coverage). `mode` is always `"static"` in this build.

## How skillspector is invoked

The service shells out to the pinned skillspector CLI:

```
skillspector scan <target> --no-llm --format json --output <tmp.json>
```

and reads the JSON report from the output file (decoupled from console output).
Exit code `0` (score ≤ 50) and `1` (score > 50) both yield a valid report; only
exit `2` is a real error. skillspector's **static** ruleset (68 patterns across
17 categories) runs locally; its optional **LLM** analysis is disabled here
(`--no-llm`).

**OSV.dev / offline.** skillspector's SC4 supply-chain check may query
`api.osv.dev` for dependency vulnerabilities. When the network is unavailable it
degrades **automatically** to a built-in fallback list, so a scan still returns
a verdict offline. (If that egress is enabled in production, add an OSV.dev row
to the sub-processor / egress doc.)

## Env

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `8000` | Listen port. |
| `SKILLCHECK_SCAN_TIMEOUT` | `180` | Per-scan subprocess timeout (seconds). |
| `SKILLCHECK_MAX_UPLOAD` | `26214400` | Max `.zip` bundle upload size (bytes). |

## Run shape

`uvicorn server:app --host 0.0.0.0 --port 8000`. The GHCR image
`ghcr.io/cerase-ai/cerase-skillcheck:<tag>` is built by
`.github/workflows/publish.yml`. Local iteration from `cerase-core`:
`./cli.sh build skillcheck`.

## Tests

`tests/test_scan.py` (pytest) drives a **running** service over HTTP: it asserts
the verdict shape for a benign and a deliberately-suspicious sample and checks
that the suspicious one scores no lower than the benign one. Point it at a live
container:

```
SKILLCHECK_URL=http://127.0.0.1:8000 python -m pytest tests/ -v
```

## Licensing

Apache-2.0. Wraps and redistributes NVIDIA skillspector (Apache-2.0) at runtime
— see `NOTICE`.
