FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y build-essential libmaxminddb0 libmaxminddb-dev && \
    pip install --upgrade pip && pip install -r requirements.txt && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["bash", "-lc", "python run_pipeline.py & python webapp/app.py"]
