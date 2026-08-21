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
| `GET` | `/healthz` | — | Liveness + scanner version + how many scans are running. |
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
`mode: static` / `degraded: true`. Either way a well-formed verdict is
returned.

**A requested LLM stage that produced no completion is degraded, whatever
stopped it.** The service routes the scanner's model calls through a loopback
forwarder on `127.0.0.1` that relays each request to LiteLLM unchanged
(`Authorization` included), returns the answer verbatim, and counts the
responses that carried output. Zero of them means the semantic analyzers saw
nothing, so the verdict is `mode: static` / `degraded: true` — the same
treatment a timeout gets. A rejected key, a rate limit, a refused connection
and a `200` with an empty `choices` array are one fact to a caller.

The count is needed because the report cannot carry that fact. skillspector
marks a scan degraded only when its `llm_call_log` holds no successful record,
and three of its four LLM nodes (`meta_analyzer`, `semantic_developer_intent`,
`semantic_quality_policy`) run their batches through
`LLMAnalyzerBase.arun_batches`, which drops a failed batch and returns the
survivors — so a node whose every call was rejected records a *successful* call
and `meta_analysis_applied` stays `true`. Measured with a key the router
rejects: every call 401s in under a second, a bundle finishes in 2.4 s instead
of 187 s, and the verdict read `SAFE / LOW / 0` with no findings and
`degraded: false`. `tests/test_llm_degrade.py` drives that path and fails when
the counting is removed.

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
| `SKILLCHECK_SCAN_DEADLINE` | `420` | Wall-clock ceiling for ONE request, covering the LLM attempt, the static fallback, and any wait for a scan slot. Without it the two step timeouts above simply add up. |
| `SKILLCHECK_MAX_CONCURRENT_SCANS` | `2` | skillspector subprocesses allowed at once. Further requests wait for a slot inside their own deadline. |
| `SKILLCHECK_MAX_UPLOAD` | `26214400` | Max `.zip` bundle upload size (bytes). |
| `LITELLM_BASE_URL` | _(unset)_ | Our LiteLLM base (e.g. `http://cerase-litellm:4000`). Set **with** the key to enable LLM mode. |
| `SKILLCHECK_LLM_API_KEY` | _(unset)_ | LiteLLM **service** virtual key (`cerase-svc-skillcheck`). Never the master key. Set **with** the base URL to enable LLM mode. |
| `SKILLCHECK_LLM_MODEL` | `core` | LiteLLM model alias to route at; switch to a cheaper alias (e.g. `spark`). |
| `SKILLCHECK_LLM_PROBE_TIMEOUT` | `5` | LiteLLM reachability-probe timeout (seconds). |

LLM mode is **off** unless both `LITELLM_BASE_URL` and `SKILLCHECK_LLM_API_KEY`
are set; with neither the service is static-only and identical to the M1 build.
`GET /healthz` reports `llm_configured` + the active `llm_model`.

## Liveness while busy

A scan is a blocking subprocess that runs for minutes. Every scan therefore runs
in the threadpool, and `/healthz` is an async handler that touches nothing but
memory, so it is answered on the event loop while scans are in flight. It
reports `scans_in_flight`, `busy` and `oldest_scan_seconds`, which is what lets
a caller tell a working scanner from a stuck one.

This is not a refinement. `POST /scan/bundle` used to call the scan directly
from an async handler, which held uvicorn's only event loop for the whole scan.
Measured against the live service: one real bundle scan ran 237 seconds and
across those 237 seconds nineteen consecutive `/healthz` probes hit their 10s
ceiling and returned nothing, so the container was marked unhealthy while the
scan it was running returned HTTP 200. `tests/test_liveness.py` holds both
halves of the fix and fails when either is reverted.

## Run shape

`uvicorn server:app --host 0.0.0.0 --port 8000`. The GHCR image
`ghcr.io/cerase-ai/cerase-skillcheck:<tag>` is built by
`.github/workflows/publish.yml`. Local iteration from `cerase-core`:
`./cli.sh build skillcheck`.

## Tests

Every file below runs in CI on each push and pull request, split by what it
needs. The `tests` job runs the three offline files against pip wheels only
(`fastapi`, `pydantic`, `python-multipart`, `httpx`, `pytest` — no skillspector
install), and the `live-scan` job builds the image and runs
`tests/test_scan.py` against the running container. `build-and-push` waits on
both, so a failing test stops the publish. The offline job excludes
`tests/test_scan.py` by name rather than listing the files to run, so a new
offline file is picked up without editing the workflow.

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

- `tests/test_llm_degrade.py` (pytest) drives a scan against a stand-in router
  and a stand-in scanner: every rejection shape (401 / 429 / 500 / a `200` with
  no completion) must come back `mode: static` / `degraded: true`, a healthy
  router must keep `mode: llm`, and the service key must still reach the router
  through the forwarder. No running service and no skillspector install needed:

  ```
  python -m pytest tests/test_llm_degrade.py -v
  ```

- `tests/test_liveness.py` (pytest) drives the ASGI app with two concurrent
  requests and requires the health probe to finish before the scan, and walks
  the AST to refuse any `async def` that calls a blocking function directly — no
  running service needed:

  ```
  python -m pytest tests/test_liveness.py -v
  ```

## Licensing

Apache-2.0. Wraps and redistributes NVIDIA skillspector (Apache-2.0) at runtime
— see `NOTICE`.
