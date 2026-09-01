FROM mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9

COPY --chmod=0555 --chown=1001:1001 loopback-entrypoint.sh /app/loopback-entrypoint.sh

USER 1001
CMD ["./loopback-entrypoint.sh"]
