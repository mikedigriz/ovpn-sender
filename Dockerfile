FROM python:3.12-alpine

RUN adduser -D -H -u 10001 ovpn \
 && mkdir -p /profiles /data \
 && chown ovpn:ovpn /data \
 && printf '#!/bin/sh\nexec python /app/ovpn_sender.py "$@"\n' > /usr/local/bin/ovpn \
 && chmod 755 /usr/local/bin/ovpn

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OVPN_PROFILES_DIR=/profiles \
    OVPN_DATA_DIR=/data \
    OVPN_PORT=8080

COPY --chmod=0755 ovpn_sender.py /app/ovpn_sender.py

USER ovpn
WORKDIR /data
VOLUME ["/data"]
# HTTP за своим прокси или HTTPS, если заданы сертификаты (OVPN_DOMAIN / OVPN_CERT+OVPN_KEY)
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["ovpn", "health"]

ENTRYPOINT ["python", "/app/ovpn_sender.py"]
CMD ["serve"]
