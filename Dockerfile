# syntax=docker/dockerfile:1.7

# Pin the multi-architecture manifest. Dependency upgrades and base-image upgrades are reviewed
# independently, so rebuilding the same revision cannot silently select a different OS image.
ARG PYTHON_IMAGE=python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

FROM ${PYTHON_IMAGE} AS builder

WORKDIR /src

# requirements.lock includes the pinned build frontend, setuptools, and wheel. Build isolation is
# disabled so the wheel can only use those hash-verified versions.
COPY requirements.lock pyproject.toml ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY COPYING.md NOTICE.md README.md ./
COPY carlos_patient_portal ./carlos_patient_portal
RUN python -m build --wheel --no-isolation --outdir /wheel

FROM ${PYTHON_IMAGE} AS runtime

ARG OCI_CREATED
ARG OCI_REVISION
ARG OCI_SOURCE="https://github.com/carlos-emr/carlos-portal"
ARG OCI_VERSION

LABEL org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.description="CARLOS patient credential portal" \
      org.opencontainers.image.licenses="GPL-2.0-or-later" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="CARLOS Patient Portal" \
      org.opencontainers.image.version="${OCI_VERSION}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/opt/portal/lib/python3.12/site-packages" \
    PATH="/opt/portal/bin:${PATH}"

WORKDIR /opt/portal

COPY requirements-runtime.lock ./
RUN python -m pip install \
      --no-cache-dir \
      --prefix=/opt/portal \
      --require-hashes \
      -r requirements-runtime.lock
COPY --from=builder /wheel/*.whl /tmp/
RUN python -m pip install \
      --no-cache-dir \
      --no-deps \
      --prefix=/opt/portal \
      /tmp/*.whl \
    && rm -f /tmp/*.whl requirements-runtime.lock \
    && python -m compileall -q /opt/portal/lib/python3.12/site-packages

# Fixed numeric identity keeps file ownership stable in orchestrators without requiring a host
# user with the same name. The service has no writable application directory.
RUN groupadd --gid 10001 portal \
    && useradd --uid 10001 --gid portal --no-create-home --home-dir /nonexistent portal

USER 10001:10001

EXPOSE 8090
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8090/health', timeout=3).read()"]

CMD ["uvicorn", "carlos_patient_portal.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8090", "--no-access-log"]
