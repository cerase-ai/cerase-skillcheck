# cerase-skillcheck

Defensive security scan for third-party agent skills. A small FastAPI HTTP
service that wraps [NVIDIA **skillspector**](https://github.com/NVIDIA/skillspector)
(Apache-2.0) and returns an advisory risk verdict. It runs skillspector's
**static** ruleset always, and — when configured — its **LLM intent analysis**
routed through our own LiteLLM.

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
  "mode": "llm",
  "degraded": false,
  "partial": false,
  "skill_name": "my-skill",
  "components_scanned": 3
}
```

`recommendation` ∈ `SAFE | CAUTION | DO_NOT_INSTALL`; `severity` ∈
`LOW | MEDIUM | HIGH | CRITICAL`. `partial: true` flags a `SKILL.md`-only scan
(weaker coverage). `mode` ∈ `static | llm` — the analysis **actually
performed**. `degraded: true` means LLM analysis was requested but the scan
fell back to static (LiteLLM unreachable / misconfigured / the LLM stage
failed) — a model outage **never** blocks a scan.

## Analysis modes — static and LLM-assisted

skillspector's **static** ruleset (68 patterns across 17 categories) runs
locally on every scan, no egress. When `LITELLM_BASE_URL` **and**
`SKILLCHECK_LLM_API_KEY` are set, the service also enables skillspector's
**LLM intent analysis**, routing its OpenAI provider at **our** LiteLLM
(`OPENAI_BASE_URL = ${LITELLM_BASE_URL}/v1`, `OPENAI_API_KEY =` the service
virtual key, `SKILLSPECTOR_MODEL =` the `core` alias). Whatever `core` maps to
is our existing routing/metering — **no new sub-processor**. The service key is
**never** the LiteLLM master key.

**Degrade to static.** Before an LLM scan the service probes LiteLLM's
`/health/liveliness`; if unreachable it runs static-only and flags
`degraded: true`. If LiteLLM is reachable but the LLM stage fails at runtime
(bad key, timeout, every call erroring), the verdict is likewise mapped to
`mode: static` / `degraded: true` from skillspector's own report metadata
(`meta_analysis_applied`). Either way a well-formed verdict is returned.

## How skillspector is invoked

The service shells out to the pinned skillspector CLI:

```
# static-only
skillspector scan <target> --no-llm --format json --output <tmp.json>
# LLM-assisted (LLM configured + LiteLLM reachable)
skillspector scan <target>          --format json --output <tmp.json>
```

and reads the JSON report from the output file (decoupled from console output).
Exit code `0` (score ≤ 50) and `1` (score > 50) both yield a valid report; exit
`2` is a real error (in LLM mode it triggers a static fallback, `degraded:true`).

**OSV.dev / offline.** skillspector's SC4 supply-chain check may query
`api.osv.dev` for dependency vulnerabilities. When the network is unavailable it
degrades **automatically** to a built-in fallback list, so a scan still returns
a verdict offline. (If that egress is enabled in production, add an OSV.dev row
to the sub-processor / egress doc.)

## Env

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `8000` | Listen port. |
| `SKILLCHECK_SCAN_TIMEOUT` | `180` | Static-scan subprocess timeout (seconds). |
| `SKILLCHECK_LLM_SCAN_TIMEOUT` | `300` | LLM-scan subprocess timeout (seconds). |
| `SKILLCHECK_MAX_UPLOAD` | `26214400` | Max `.zip` bundle upload size (bytes). |
| `LITELLM_BASE_URL` | _(unset)_ | Our LiteLLM base (e.g. `http://cerase-litellm:4000`). Set **with** the key to enable LLM mode. |
| `SKILLCHECK_LLM_API_KEY` | _(unset)_ | LiteLLM **service** virtual key (`cerase-svc-skillcheck`). Never the master key. Set **with** the base URL to enable LLM mode. |
| `SKILLCHECK_LLM_MODEL` | `core` | LiteLLM model alias to route at; switch to a cheaper alias (e.g. `spark`). |
| `SKILLCHECK_LLM_PROBE_TIMEOUT` | `5` | LiteLLM reachability-probe timeout (seconds). |

LLM mode is **off** unless both `LITELLM_BASE_URL` and `SKILLCHECK_LLM_API_KEY`
are set; with neither the service is static-only and identical to the M1 build.
`GET /healthz` reports `llm_configured` + the active `llm_model`.

## Run shape

`uvicorn server:app --host 0.0.0.0 --port 8000`. The GHCR image
`ghcr.io/cerase-ai/cerase-skillcheck:<tag>` is built by
`.github/workflows/publish.yml`. Local iteration from `cerase-core`:
`./cli.sh build skillcheck`.

## Tests

- `tests/test_helpers.py` (pytest) unit-tests the pure routing/degrade helpers
  (mode-flag mapping, degrade-to-static, the model-alias knob, base-URL
  normalisation) — no running service, no skillspector install needed:

  ```
  python -m pytest tests/test_helpers.py -v
  ```

- `tests/test_scan.py` (pytest) drives a **running** service over HTTP: it
  asserts the verdict shape for a benign and a deliberately-suspicious sample
  and that the suspicious one scores no lower than the benign one. It adapts its
  `mode` assertions to the container's `/healthz` (`llm_configured`):

  ```
  SKILLCHECK_URL=http://127.0.0.1:8000 python -m pytest tests/test_scan.py -v
  ```

## Licensing

Apache-2.0. Wraps and redistributes NVIDIA skillspector (Apache-2.0) at runtime
— see `NOTICE`.
