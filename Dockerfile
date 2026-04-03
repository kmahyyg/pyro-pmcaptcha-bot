FROM python:3.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only runtime dependencies already used by this project.
RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir telethon redis

# App code (teleSecrets.py and .session are expected to be bind-mounted at runtime).
COPY main.py /app/main.py

CMD ["python3", "/app/main.py"]
