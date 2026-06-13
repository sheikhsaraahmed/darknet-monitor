FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /logs/http /logs/ftp /collected

COPY collector.py .

CMD ["python", "collector.py"]