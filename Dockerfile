FROM python:3.12-slim

WORKDIR /app

COPY ./requirements.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt

COPY ./encrypt_decrypt.py ./

ENTRYPOINT ["python3", "encrypt_decrypt.py"]
