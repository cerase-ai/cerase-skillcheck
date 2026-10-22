# cerase-skillcheck

An HTTP service (FastAPI) that scans an agent skill for security risks and
returns an advisory verdict. It wraps
[NVIDIA skillspector](https://github.com/NVIDIA/skillspector) (Apache-2.0),
pinned to one commit in `requirements.txt`, and runs its static ruleset on
every scan and its LLM intent analysis when a LiteLLM proxy is configured.

The Cerase platform uses the verdict to tell a person what a third-party skill
does before they install it. The verdict never blocks an install and never
quarantines anything; the person decides.

It is not an MCP server and not a Marketplace package. In a Cerase appliance it
is an internal service with no published port, which the control-plane starts
when a scan is requested and stops after a quiet period.

## Endpoints

| Method | Path | Input | Returns |
|---|---|---|---|
| `GET` | `/healthz` | none | Status, scanner version, whether LLM analysis is configured and with which model, scans in flight, age of the oldest one, the concurrency limit and the request deadline. |
| `POST` | `/scan` | JSON with exactly one of `path` or `skill_md` | A verdict. |
| `POST` | `/scan/bundle` | multipart upload of a `.zip` skill bundle | A verdict. |

`path` is an absolute path inside the container: a directory is scanned whole,
a single `.md` file is scanned as a `SKILL.md` alone. `skill_md` is raw
`SKILL.md` content, written to a temporary file and scanned alone. A bundle is
extracted (entries that would escape the extraction directory are refused) and
scanned whole. A missing path answers 404, a bundle that is not a `.zip` 415, a
bundle over `SKILLCHECK_MAX_UPLOAD` 413, and a scan the scanner cannot complete
422.

## Verdict

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

- `score` is skillspector's 0-100 risk score; `severity` is `LOW`, `MEDIUM`,
  `HIGH` or `CRITICAL`; `recommendation` is `SAFE`, `CAUTION` or
  `DO_NOT_INSTALL`.
- `partial: true` marks a scan of a `SKILL.md` alone, which sees less than a
  scan of the whole skill.
- `mode` is the analysis actually performed, `static` or `llm`.
- `degraded: true` means LLM analysis was requested and the verdict is static
  only.

## Static and LLM analysis

The static ruleset runs locally with no network access, except that
skillspector's supply-chain check may query `api.osv.dev` for dependency
vulnerabilities; without network it falls back to a built-in list and the scan
still completes.

LLM analysis is on when both `LITELLM_BASE_URL` and `SKILLCHECK_LLM_API_KEY`
are set. skillspector's OpenAI provider is then pointed at
`<LITELLM_BASE_URL>/v1` with that key and the model alias in
`SKILLCHECK_LLM_MODEL`. Before each LLM scan the service checks LiteLLM's
`/health/liveliness`; when it does not answer, the scan runs static only and
is marked `degraded`.

The scanner's model calls pass through a forwarder on `127.0.0.1` started for
each LLM scan. It relays every request to LiteLLM unchanged, adds the header
`x-cerase-call-type: scan` so the spend is reported as scanning, and counts the
responses that carried output. When an LLM scan produced no usable completion
(a rejected key, a rate limit, an error, or an empty `choices` array), the
verdict is `mode: static` with `degraded: true`. The count is needed because
skillspector's own report marks the LLM pass as applied even when every call
in three of its four LLM stages failed. A scanner exit code 2, or an LLM scan
that runs out of time, is retried as a static scan and marked `degraded`.

The scanner runs as `skillspector scan <target> [--no-llm] --format json
--output <file>`, and the service reads the report from that file. Exit codes
0 (score up to 50) and 1 (score above 50) both mean a valid report.

## Load and liveness

Each scan runs in a worker thread, at most `SKILLCHECK_MAX_CONCURRENT_SCANS` at
a time; further requests wait for a slot within their deadline.
`SKILLCHECK_SCAN_DEADLINE` bounds a whole request: the LLM attempt, the static
fallback and the wait. `/healthz` runs on the event loop and touches only
memory, so it answers while scans are running.

When the client of `/scan` or `/scan/bundle` disconnects, its scan is
cancelled: the scanner's process group is killed, no static fallback is
started, and the slot is released within about a second. A request still
waiting for a slot stops waiting when its client disconnects, and takes none.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | Listen port. |
| `SKILLCHECK_SCAN_TIMEOUT` | `180` | Timeout of a static scan, in seconds. |
| `SKILLCHECK_LLM_CALL_TIMEOUT` | `900` | Ceiling for one model call inside the LLM step, in seconds. |
| `SKILLCHECK_LLM_SCAN_TIMEOUT` | `1800` | Timeout of an LLM scan's subprocess, in seconds. |
| `SKILLCHECK_SCAN_DEADLINE` | `2100` | Ceiling for one request, in seconds. |
| `SKILLCHECK_MAX_CONCURRENT_SCANS` | `2` | Scans run at once. |
| `SKILLCHECK_MAX_UPLOAD` | `26214400` (25 MiB) | Largest `.zip` bundle accepted. |
| `LITELLM_BASE_URL` | unset | LiteLLM base URL; with the key below, turns LLM analysis on. |
| `SKILLCHECK_LLM_API_KEY` | unset | LiteLLM key for this service; with the URL above, turns LLM analysis on. |
| `SKILLCHECK_LLM_MODEL` | `core` | LiteLLM model alias the analysis uses. |
| `SKILLCHECK_LLM_PROBE_TIMEOUT` | `5` | Timeout of the LiteLLM reachability check, in seconds. |

The three timeouts are ordered so each layer outlasts the one inside it: a
model call (`SKILLCHECK_LLM_CALL_TIMEOUT`, 900 s) is not cut by the model step
(`SKILLCHECK_LLM_SCAN_TIMEOUT`, 1800 s), and the model step plus the static
fallback (180 s) fit inside the request deadline (`SKILLCHECK_SCAN_DEADLINE`,
2100 s). The call ceiling is 900 s because measured calls ran from 163 s to
811 s, almost all of it reasoning tokens; at the previous 120 s every call was
cut before the model answered. skillspector reads no setting for its per-call
timeout, so the image build patches the two literals that hardcode 120 s to
read `SKILLCHECK_LLM_CALL_TIMEOUT`, and fails the build if either line is
missing. It also adds a missing item to SQP-3's "Do NOT flag if" list, so a
skill merely written in a language other than English is not reported as
forcing one.

## Build and run locally

```sh
docker build -t cerase-skillcheck .
docker run --rm -p 8000:8000 cerase-skillcheck
curl -s localhost:8000/healthz
curl -s -X POST localhost:8000/scan -H 'Content-Type: application/json' \
  -d '{"skill_md": "---\nname: demo\ndescription: A demo skill.\n---\nSay hello."}'
```

The image runs `uvicorn server:app` under `tini`, as the unprivileged user
`appuser`, and its `HEALTHCHECK` requests `/healthz`. Each push to `main` runs
the tests and publishes `ghcr.io/cerase-ai/cerase-skillcheck`
(`.github/workflows/publish.yml`).

## Tests

The offline tests need only `fastapi`, `pydantic`, `python-multipart`, `httpx`
and `pytest`, with no skillspector installed:

```sh
python -m pytest tests --ignore=tests/test_scan.py
```

- `tests/test_helpers.py`: mode flags, the degrade-to-static mapping, the
  model-alias setting and base-URL normalisation.
- `tests/test_llm_degrade.py`: a stand-in router and scanner; 401, 429, 500
  and an empty `200` must each give `mode: static` and `degraded: true`, a
  healthy router must keep `mode: llm`, and the key must reach the router
  through the forwarder.
- `tests/test_llm_call_timeout.py`: the per-call ceiling defaults to 900 s and
  is configurable, the three timeouts are ordered call < step < deadline, the
  scanner subprocess is handed the configured value, and the build patch
  rewrites skillspector's two 120 s literals and fails when one is missing.
- `tests/test_liveness.py`: the health probe must answer before a running scan
  finishes, and no `async def` may call a blocking function.
- `tests/test_scan_is_declared.py`: every completion through the forwarder
  carries `x-cerase-call-type: scan`.
- `tests/test_client_disconnect.py`: a client that disconnects mid-scan must
  leave its slot free within seconds, with the scanner killed and no static
  fallback; a request waiting for a slot must stop waiting; and the next
  client in line must get its verdict.

`tests/test_scan.py` runs against a running service and checks the verdict
shape for a benign and a suspicious sample:

```sh
SKILLCHECK_URL=http://127.0.0.1:8000 python -m pytest tests/test_scan.py
```

CI runs the offline tests, then builds the image and runs `tests/test_scan.py`
against it; the image is published only when both pass.

## License

Apache-2.0. See [LICENSE](LICENSE). skillspector is redistributed under its own
Apache-2.0 licence; see [NOTICE](NOTICE).
