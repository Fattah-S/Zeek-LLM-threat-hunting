ARG BASE=python:3.12-slim
FROM ${BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 NSM_DATA=/data NSM_DB=/data/nsm.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --uid 10001 nsm && mkdir -p /data && chown -R nsm /app /data
USER nsm
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1
CMD ["./run_pipeline.sh"]
