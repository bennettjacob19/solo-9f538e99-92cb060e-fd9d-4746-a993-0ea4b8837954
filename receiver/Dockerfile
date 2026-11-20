FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY receiver.py .

EXPOSE 9001/udp
EXPOSE 9002
CMD ["python", "receiver.py"]
