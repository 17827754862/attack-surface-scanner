FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0
COPY app.py ./
EXPOSE 8000 6443
CMD ["python", "app.py"]
