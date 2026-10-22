# cerase-skillcheck — defensive static security scan for third-party skills.
#
# A plain FastAPI HTTP service (NOT an MCP) wrapping NVIDIA skillspector
# (Apache-2.0) in static-only mode. Exposes POST /scan → advisory risk verdict.
# Runs as a cluster-internal compose service in cerase-core; the control-plane
# reaches it by hostname to warn users about risky skills before install.
#
# Two-stage build: skillspector drags in a heavy tree (langgraph / langchain /
# yara-python) and needs git to install from its pinned commit. The builder
# resolves everything into a venv; the runtime image copies only the venv, so
# git and the build toolchain never ship in the final layer.

# ---- builder ---------------------------------------------------------------
FROM python:3.13.9-slim@sha256:326df678c20c78d465db501563f3492d17c42a4afe33a1f2bf5406a1d56b0e86 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Raise skillspector's hardcoded 120 s per-call model timeout to
# SKILLCHECK_LLM_CALL_TIMEOUT (default 900) at build time. skillspector reads
# no setting for this: the value is a literal in llm_utils.get_chat_model and
# in the OpenAI provider's default. Measured 16 Oct 2026, single model calls
# took 163-811 s (reasoning tokens), so every call was cut at 120 and the scan
# returned a static verdict the control-plane discarded.
#
# The patcher is server.py's, so build and tests share one definition, and it
# RAISES when either literal is missing: a skillspector bump that moves a line
# fails this build instead of silently restoring the cut. The same block also
# adds a missing item to SQP-3's "Do NOT flag if" list, so a skill merely
# written in a language other than English is not reported as forcing one.
COPY server.py /tmp/cerase-patch/server.py
RUN python - <<'PY'
import pathlib
import sys

import skillspector

sys.path.insert(0, "/tmp/cerase-patch")
import server

root = pathlib.Path(skillspector.__file__).parent
for relative, line in server._SKILLSPECTOR_TIMEOUT_PATCHES:
    source_path = root / relative
    original = source_path.read_text(encoding="utf-8")
    source_path.write_text(
        server._patch_skillspector_llm_call_timeout(original, line),
        encoding="utf-8",
    )

sqp3_path = root / server._SKILLSPECTOR_SQP3_PATCH[0]
original = sqp3_path.read_text(encoding="utf-8")
sqp3_path.write_text(
    server._patch_skillspector_sqp3(original),
    encoding="utf-8",
)
PY

# ---- runtime ---------------------------------------------------------------
FROM python:3.13.9-slim@sha256:326df678c20c78d465db501563f3492d17c42a4afe33a1f2bf5406a1d56b0e86

# `tini` as PID 1, the same way cerase-core's control-plane and agent-slot
# images do it.
#
# A process the daemon execs into this container is reparented to PID 1 when it
# ends, so PID 1 has to reap it, and uvicorn only does so when its event loop
# gets to run. Eleven zombies were counted in a container whose loop had been
# held by a scan; with the loop free the same container sits at zero, so this is
# insurance against the loop being blocked again rather than a leak that is
# live today.
#
# It belongs in the image rather than in a compose `init: true` for the same
# reason the HEALTHCHECK does — the control-plane's on-demand starter creates
# this container with `docker run` and carries nothing from any compose file, so
# a setting written there reaches some containers and not the ones the fleet
# actually runs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY server.py /app/server.py

# Non-root runtime user (image hygiene: matches the other cerase-* packages).
RUN groupadd -r appuser \
 && useradd -r -g appuser -u 1000 -m -d /home/appuser -s /usr/sbin/nologin appuser \
 && chown -R appuser:appuser /app
USER appuser
WORKDIR /app

EXPOSE 8000

# Liveness signal for compose/doctor. python-only probe (no curl in slim).
#
# This is the ONLY healthcheck definition for this service, on purpose. The
# container is not always created by compose — the control-plane's on-demand
# starter creates it with `docker run`, which carries the image's HEALTHCHECK and
# nothing from any compose file. A second definition in compose is therefore not
# an override but a fork that applies to some containers and not others, and it
# already cost an operator an afternoon: the compose file said 5s, the running
# container reported failures at 10s, and both numbers were correct about
# different containers.
#
# The probe carries its own 5s timeout so it fails with a message instead of
# being killed by the daemon at --timeout with an empty log line. It reads PORT
# the same way the entrypoint does, so the two cannot drift.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'), timeout=5).status==200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--", "sh", "-c", "exec uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}"]
