FROM python:3.11-slim

WORKDIR /app

COPY ./requirements.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt

COPY ./encrypt_decrypt.py ./

# Set the script as the entrypoint
ENTRYPOINT ["python3", "encrypt_decrypt.py"]
