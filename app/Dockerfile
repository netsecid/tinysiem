FROM python:3.12-slim

# Working directory is / so that 'app' is importable as a Python package at /app
WORKDIR /

RUN useradd -r -s /bin/false appuser

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy source into /app/ — this becomes the 'app' Python package
COPY . /app/

RUN mkdir -p /app/data /app/logs /app/decoder/decoders/custom /app/rules/rules/custom \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
