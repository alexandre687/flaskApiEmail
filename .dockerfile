# ===== Base mínima =====
FROM python:3.11-slim

# Config padrão do Python em containers
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Porta padrão do app Flask
    PORT=8080 \
    # Pasta de cache do tldextract (evita escrever em /root)
    TLD_EXTRACT_CACHE=/tmp/tldextract_cache

# Dependências do sistema (certificados, curl p/ healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Cria diretório de trabalho
WORKDIR /app

# Copia requirements primeiro para aproveitar cache
COPY requirements.txt .

# Adiciona gunicorn (se não estiver no seu requirements)
# Dica: você pode mover "gunicorn" pro requirements.txt se preferir.
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copia o restante do código
COPY app.py .

# Usuário não-root por segurança
RUN useradd -m appuser && chown -R appuser:appuser /app /tmp
USER appuser

# Expõe a porta
EXPOSE 8080

# Healthcheck simples no endpoint /health
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT}/health || exit 1

# Comando de execução (gunicorn é mais estável que flask dev server)
# Ajuste de workers/threads conforme sua infra.
CMD exec gunicorn app:app \
    --bind 0.0.0.0:${PORT} \
    --workers ${GUNICORN_WORKERS:-2} \
    --threads ${GUNICORN_THREADS:-4} \
    --timeout ${GUNICORN_TIMEOUT:-120}
