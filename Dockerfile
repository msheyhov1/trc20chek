FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CACHE_PATH=/data/cache.db \
    CLUSTER_PATH=/data/cluster.db

# Зависимости отдельным слоем: правка кода не тянет за собой переустановку.
# requirements-dev.txt намеренно НЕ ставим — pytest и ruff в образе не нужны.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY core ./core
COPY api ./api
COPY bot ./bot
COPY web ./web

# Не root: у процесса нет причин иметь право писать куда угодно в контейнере.
# /data — точка монтирования volume, права нужны на запись SQLite.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /data \
    && chown -R app:app /app /data
USER app

# Railway передаёт порт в переменной $PORT
EXPOSE 8000

# Свой healthcheck (Railway использует свой, но локальный docker run тоже
# должен показывать состояние). Обращаемся на localhost изнутри контейнера.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url='http://127.0.0.1:%s/health' % os.getenv('PORT','8000'); \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}
