#!/usr/bin/env just --justfile

# Image + chart coordinates (override on the CLI, e.g. `just TAG=dev publish`)
REGISTRY := "ghcr.io"
IMAGE := "cznewt/alert-handler"
TAG := `cat VERSION`
CHART := "operations/alert-handler-helm-chart"
CHARTS_NAMESPACE := "cznewt/charts"

default:
  just --list

# --- Local dev ---

# Build the local image via compose
build:
    docker compose build

# Run the handler on :8080 with docker/config.yaml mounted
run:
    docker compose up

# Post a firing test alert to a running handler
fire ALERTNAME="Test" SEVERITY="warning":
    curl -s -X POST -H 'Content-Type: application/json' localhost:8080/alert -d '{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"{{ALERTNAME}}","severity":"{{SEVERITY}}","namespace":"demo"},"annotations":{"summary":"test alert from just fire"}}]}'

# Run the test suite (expects .venv with the deps installed: just venv)
test:
    .venv/bin/pytest -q

# All of it: tests, then the image builds
test-all: test
    docker build -q -t {{REGISTRY}}/{{IMAGE}}:test ./docker >/dev/null && echo "image builds"

# Create .venv with the runtime deps and pytest
venv:
    python3 -m venv .venv
    .venv/bin/pip install -q -r docker/requirements.txt pytest

# Serve the docs locally with live reload (needs: pip install mkdocs-material)
docs-serve:
    mkdocs serve

# Build the docs site (strict; mirrors the Pages workflow)
docs-build:
    mkdocs build --strict

# --- The demo: Prometheus -> Alertmanager -> handler -> actions (demo/) ---

# Start the three-container demo in the foreground; DemoWorkloadUnhealthy fires within a minute
demo:
    docker compose -f demo/docker-compose.yml up

# What the handler did with each alert
demo-logs:
    docker compose -f demo/docker-compose.yml logs -f alert-handler

# Tear the demo down
demo-clean:
    docker compose -f demo/docker-compose.yml down -v

# --- Container registry (ghcr) ---

# Log in to ghcr. Set GHCR_USER + GHCR_TOKEN (a GitHub PAT with write:packages).
login:
    echo "${GHCR_TOKEN:?set GHCR_TOKEN to a GitHub PAT with write:packages}" | docker login {{REGISTRY}} -u "${GHCR_USER:?set GHCR_USER to your GitHub username}" --password-stdin

# Build the image, tagged :<VERSION> and :latest
image:
    docker build -t {{REGISTRY}}/{{IMAGE}}:{{TAG}} -t {{REGISTRY}}/{{IMAGE}}:latest ./docker

# Push both tags to ghcr (run `just login` first)
push:
    docker push {{REGISTRY}}/{{IMAGE}}:{{TAG}}
    docker push {{REGISTRY}}/{{IMAGE}}:latest

# Build and push in one go
publish: image push
    @echo "published {{REGISTRY}}/{{IMAGE}}:{{TAG}} (+ :latest)"

# Print the fully-qualified image reference
image-ref:
    @echo "{{REGISTRY}}/{{IMAGE}}:{{TAG}}"

# --- Helm chart (ghcr OCI) ---

# Lint the chart
chart-lint:
    helm lint {{CHART}}

# Render the chart to stdout (sanity check)
chart-template:
    helm template alert-handler {{CHART}}

# Package + push the chart to ghcr OCI (set GHCR_USER + GHCR_TOKEN)
chart-publish:
    echo "${GHCR_TOKEN:?set GHCR_TOKEN to a GitHub PAT with write:packages}" | helm registry login {{REGISTRY}} -u "${GHCR_USER:?set GHCR_USER to your GitHub username}" --password-stdin
    rm -rf /tmp/alert-handler-charts && mkdir -p /tmp/alert-handler-charts
    helm package {{CHART}} -d /tmp/alert-handler-charts
    helm push /tmp/alert-handler-charts/*.tgz "oci://{{REGISTRY}}/{{CHARTS_NAMESPACE}}"
