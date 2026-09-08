set -eu
umask 077
mkdir -p /tmp/authclaw-tls
printf '%s\n' "$TLS_CERT_PEM" > /tmp/authclaw-tls/cert.pem
printf '%s\n' "$TLS_KEY_PEM" > /tmp/authclaw-tls/key.pem
printf '%s\n' "$TLS_CONFIG" > /tmp/authclaw-tls/nginx.conf
unset TLS_CERT_PEM TLS_KEY_PEM TLS_CONFIG
exec nginx -c /tmp/authclaw-tls/nginx.conf -g 'daemon off;'
