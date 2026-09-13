# Alertmanager webhook handler: matches alerts against rules and runs actions
# (HTTP, command, log, Kubernetes writes) on :8080.
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY alert_handler.py /app/alert_handler.py
COPY config.yaml /etc/alert-handler/config.yaml

# Default contract — override via compose `environment:` or the component's
# env_vars. CONFIG_FILE is the one you usually point at a mounted ConfigMap.
ENV CONFIG_FILE="/etc/alert-handler/config.yaml" \
    RUNBOOK_DIR="/etc/alert-handler/runbooks" \
    SECRETS_DIR="/etc/alert-handler/secrets" \
    HTTP_PORT="8080" \
    LOG_LEVEL="INFO"

# Mount points for the two optional capabilities: a ConfigMap of runbook
# scripts, and a Secret of credentials. Both are read at start-up and on SIGHUP.
RUN mkdir -p /etc/alert-handler/runbooks /etc/alert-handler/secrets

# Run as an unprivileged user. `exec` and `runbook` actions therefore run as
# this user too; layer your own image FROM this one to add the tooling they need.
RUN useradd --create-home --uid 10001 handler
USER handler

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status == 200 else 1)"

ENTRYPOINT ["python", "/app/alert_handler.py"]
