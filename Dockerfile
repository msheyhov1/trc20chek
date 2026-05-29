FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CACHE_PATH=/data/cache.db

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY core ./core
COPY api ./api
COPY bot ./bot
COPY web ./web

# Railway передаёт порт в переменной $PORT
EXPOSE 8000
CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}
