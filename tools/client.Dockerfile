FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1
COPY tools/client.py /srv/client.py
USER 65534:65534
EXPOSE 8098
CMD ["python", "/srv/client.py"]
