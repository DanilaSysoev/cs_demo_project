FROM python:3.12-slim

RUN addgroup --gid 1000 appuser && \
    adduser --uid 1000 --gid 1000 appuser && \
    apt update && \
    apt upgrade -y --no-install-recommends && \
    eval $(apt-config shell CACHE Dir::Cache) && \
    eval $(apt-config shell ARCHIVES Dir::Cache::archives) && \
    rm -rf /${CACHE}/${ARCHIVES}

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app

USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
