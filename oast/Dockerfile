FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./

RUN groupadd --gid 10002 oast \
    && useradd --uid 10002 --gid 10002 --create-home oast \
    && mkdir -p /data \
    && chown -R oast:oast /data

USER 10002:10002
EXPOSE 8001
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
