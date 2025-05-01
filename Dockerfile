# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY main2.py .

# For Flask and Scapy
RUN pip install flask scapy

CMD ["python", "main2.py"]
