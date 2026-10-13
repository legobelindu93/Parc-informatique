FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY serveur_collecte.py .
COPY wsgi.py .
COPY database.py .
COPY cve_service.py .
COPY enrichissement.py .
COPY export_service.py .
COPY version_editor_service.py .
COPY editeurs.json .
COPY schema.sql .
COPY data/ data/
COPY dashboard/ dashboard/
COPY agent/ agent/

VOLUME ["/app/data", "/app/db"]

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "300", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
