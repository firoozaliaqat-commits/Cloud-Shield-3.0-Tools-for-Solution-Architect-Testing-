FROM grafana/k6:0.56.0 AS k6bin
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1
COPY --from=k6bin /usr/bin/k6 /usr/local/bin/k6
COPY tools/k6_agent.py /app/agent.py
COPY k6/worker.js /app/k6/worker.js
USER 65534:65534
EXPOSE 8097
CMD ["python", "/app/agent.py"]
