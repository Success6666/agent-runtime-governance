FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/agent-runtime-governance

COPY pyproject.toml README.md LICENSE ./
COPY agent_runtime_governance ./agent_runtime_governance
RUN python -m pip install --no-cache-dir .

COPY integration/k8s/runtime_smoke.py /opt/agent-runtime-governance/runtime_smoke.py

USER 65532:65532
ENTRYPOINT ["python", "-I", "/opt/agent-runtime-governance/runtime_smoke.py"]
