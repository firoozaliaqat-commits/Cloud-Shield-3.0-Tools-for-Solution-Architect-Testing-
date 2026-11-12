FROM grafana/k6:0.56.0 AS k6bin
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=k6bin /usr/bin/k6 /usr/local/bin/k6
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt && useradd --uid 10001 --create-home lab && mkdir -p /data /app/k6 && chown -R lab:lab /data /app
COPY app /app
COPY k6 /app/k6
USER lab
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
