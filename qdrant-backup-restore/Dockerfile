FROM ghcr.io/aleph-alpha/shared-images/pharia-helper:latest

USER root

# Install required packages using apk (Wolfi uses apk like Alpine)
RUN apk add --no-cache \
    python3 \
    py3-pip

USER appuser

WORKDIR /qdrant_backup_recovery

COPY --chown=appuser:appuser qdrant_backup_recovery.sh requirements.txt s3_util.py .

RUN pip3 install -r requirements.txt

ENTRYPOINT ["/bin/bash"]
