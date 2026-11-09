FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin quoteops \
 && install -d -m 0700 -o 10001 -g 10001 /var/qo-files
WORKDIR /app
COPY pyproject.toml ./
COPY quoteops ./quoteops
RUN pip install --no-cache-dir .
USER 10001
CMD ["uvicorn", "quoteops.app:app", "--host", "0.0.0.0", "--port", "8091", "--no-access-log"]
