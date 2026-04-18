#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ] && [ -z "${INSP_WRAPPED:-}" ]; then
  mkdir -p /inspircd/data
  chown -R inspircd:inspircd /inspircd/data || true
  export INSP_WRAPPED=1
  exec su-exec inspircd /bin/sh /inspircd/custom_entrypoint.sh "$@"
fi

mkdir -p /inspircd/data
touch /inspircd/data/filters.db /inspircd/data/permchannels.db

config_file="/inspircd/conf/inspircd.conf"
links_file="/inspircd/conf/links.conf"
cert_file="/inspircd/conf/cert.pem"
key_file="/inspircd/conf/key.pem"

if [ ! -r "$config_file" ]; then
  echo "Missing required InspIRCd config: $config_file" >&2
  exit 1
fi

if [ ! -e "$links_file" ]; then
  : > "$links_file"
fi

cert_readable=true
[ -e "$cert_file" ] && [ ! -r "$cert_file" ] && cert_readable=false
[ -e "$key_file" ] && [ ! -r "$key_file" ] && cert_readable=false

if [ "$cert_readable" = false ]; then
  echo "TLS material present but not readable by inspircd user: $cert_file / $key_file" >&2
  exit 1
fi

if [ ! -e "$cert_file" ] || [ ! -e "$key_file" ]; then
  echo "No TLS certificate found; generating self-signed certs"
  tmp_template="/tmp/inspircd-cert.template"
  cat > "$tmp_template" <<EOF
cn              = "${INSP_TLS_CN:-irc.example.com}"
email           = "${INSP_TLS_MAIL:-nomail@irc.example.com}"
unit            = "${INSP_TLS_UNIT:-RelayOS IRC}"
organization    = "${INSP_TLS_ORG:-RelayOS}"
locality        = "${INSP_TLS_LOC:-Unset}"
state           = "${INSP_TLS_STATE:-Unset}"
country         = "${INSP_TLS_COUNTRY:-US}"
expiration_days = ${INSP_TLS_DURATION:-365}
tls_www_client
tls_www_server
signing_key
encryption_key
cert_signing_key
crl_signing_key
code_signing_key
ocsp_signing_key
time_stamping_key
EOF
  /usr/bin/certtool --generate-privkey --bits 4096 --sec-param normal --outfile "$key_file"
  /usr/bin/certtool --generate-self-signed --load-privkey "$key_file" --outfile "$cert_file" --template "$tmp_template"
  rm -f "$tmp_template"
fi

if [ ! -e /inspircd/conf/dhparams.pem ]; then
  echo "Generating DH parameters"
  /usr/bin/certtool --generate-dh-params --sec-param normal --outfile /inspircd/conf/dhparams.pem
fi

exec /inspircd/bin/inspircd --nofork "$@"
