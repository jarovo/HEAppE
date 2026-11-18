FROM registry.access.redhat.com/ubi9/ubi-minimal

# Copy the uv binary from the official Astral image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Set cache and temporary directories to writable paths for OpenShift's random UID
ENV UV_NO_PYTHON_DOWNLOADS=1

WORKDIR /opt/app-root/src

# Copy dependency definitions first for layer caching
COPY --chown=1001:0 pyproject.toml uv.lock ./

# Sync directly into the active /opt/app-root environment
RUN uv sync --active --frozen --no-dev --compile-bytecode

# Copy application source code and ensure group-root ownership
COPY --chown=1001:0 . .

USER 1001
CMD [ "uv", "run", "--no-cache", "kopf", "run", "--namespace", "heappe-testing", "vault-bootstrapper.py"]