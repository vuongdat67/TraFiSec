FROM ghcr.io/foundry-rs/foundry@sha256:8347b728d5d393dac1c018691b36f506d23b9dcd78341d40ea0fcb11c3a19cdd AS foundry

FROM python:3.12.0-slim-bookworm

COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge

WORKDIR /artifact
COPY requirements.txt pyproject.toml README.md ./
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY . .
RUN gzip -dk eval/artifacts/e1_trace_cache.jsonl.gz \
    && mv eval/artifacts/e1_trace_cache.jsonl eval/results/e1_trace_cache.jsonl \
    && test "$(anvil --version | head -n 1)" = "anvil Version: 1.7.1" \
    && test "$(cast --version | head -n 1)" = "cast Version: 1.7.1" \
    && test "$(forge --version | head -n 1)" = "forge Version: 1.7.1"

CMD ["python", "tools/reproduce.py"]
