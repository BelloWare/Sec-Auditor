FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE requirements.lock ./
COPY src/ ./src/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock \
    && /opt/venv/bin/pip install --no-cache-dir --no-deps .

FROM python:3.12-slim AS runtime

RUN groupadd --gid 10001 auditor \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin auditor \
    && mkdir -p /data \
    && chown 10001:10001 /data
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEC_AUDITOR_STATE_PATH=/data/sec-auditor.sqlite3
WORKDIR /data
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["sec-auditor"]
CMD ["serve", "--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
