FROM python:3.9-slim-bullseye

WORKDIR /app
COPY pyropmCaptcha.py /app
COPY requirements.txt /app

RUN touch /app/pyroSecrets.py
RUN pip3 install wheel setuptools ; pip3 install -r requirements.txt
ENTRYPOINT [ "python3", "pyropmCaptcha.py" ]
