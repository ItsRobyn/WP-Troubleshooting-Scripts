#!/usr/bin/env bash
# =============================================================
# ssl-dns-check.sh — DNS Checker
# =============================================================
# Usage: ./ssl-dns-check.sh example.com
#        ./ssl-dns-check.sh www.example.com  (www is stripped/swapped)
#
# Checks:
#   • WHOIS domain registration info (registrar, dates, expiry, lock)
#   • SSL certificate validity on both bare and www domains
#   • A records point to the expected IP range (199.16.172.x / 199.16.173.x)
#   • No AAAA, CAA, DS, or DNSKEY records present
#   • DNSSEC is not enabled
#
# Requirements: curl, dig, openssl, python3, whois (optional)
# All reads. Zero writes. Safe for production.
# =============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; YLW='\033[0;33m'; GRN='\033[0;32m'
PRI='\033[1;38;2;182;29;111m'   # #b61d6f — primary (bars/headings)
SEC='\033[1;38;2;255;255;255m'  # #ffffff — secondary (titles)
GRY='\033[3;38;2;136;146;160m'  # grey italic — notes/info
BLD='\033[1m'; RST='\033[0m'
BAR="$(printf '─%.0s' {1..64})"

# ── Args ──────────────────────────────────────────────────────
INPUT="${1:-}"
if [[ -z "$INPUT" ]]; then
    echo "Usage: $0 <domain>"
    echo "  Example: $0 example.com"
    exit 1
fi

# Strip protocol/path, lowercase
DOMAIN=$(echo "$INPUT" | sed -E 's|https?://||' | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')

# Normalise to bare + www pair
if [[ "$DOMAIN" == www.* ]]; then
    BARE_DOMAIN="${DOMAIN#www.}"
    WWW_DOMAIN="$DOMAIN"
else
    BARE_DOMAIN="$DOMAIN"
    WWW_DOMAIN="www.$DOMAIN"
fi

# ── Helpers ───────────────────────────────────────────────────
section() { echo -e "\n${PRI}${BAR}${RST}\n${SEC}  $1${RST}\n${PRI}${BAR}${RST}\n"; }
row()     { printf "  ${BLD}%-38s${RST} %s\n" "$1" "$2"; }
good()    { echo -e "  ${GRN}✓ $1${RST}"; }
warn()    { echo -e "  ${YLW}⚠ $1${RST}"; }
bad()     { echo -e "  ${RED}✗ $1${RST}"; }
note()    { echo -e "  ${GRY}↳ $1${RST}"; }

# Returns 0 if IP is in the expected range (199.16.172.1-254 or 199.16.173.1-254)
is_pressable_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^199\.16\.17[23]\.([0-9]{1,3})$ ]]; then
        local oct="${BASH_REMATCH[1]}"
        (( oct >= 1 && oct <= 254 )) && return 0
    fi
    return 1
}

# ── Global tracking ───────────────────────────────────────────
declare -a POSITIVES=()
declare -a ISSUES=()
SSL_BARE_OK=false
SSL_WWW_OK=false

# ── File output setup ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_BASENAME="dns-check-$(date -u '+%Y-%m-%d-%H%M%S')-${BARE_DOMAIN}.txt"
REPORT_FILENAME="${SCRIPT_DIR}/${REPORT_BASENAME}"
REPORT_TMPFILE="$(mktemp)"
exec 3>&1 1>"$REPORT_TMPFILE" 2>&1
tail -f "$REPORT_TMPFILE" >&3 &
TAIL_PID=$!
sleep 0.1

# ── Header ────────────────────────────────────────────────────
echo -e "\n${PRI}"
echo -e "  ┌──────────────────────────────────────────────────────────┐"
echo -e "  │${SEC}                      DNS Checker                         ${PRI}│"
echo -e "  │${SEC}                    ssl-dns-check.sh                      ${PRI}│"
echo -e "  │${SEC}                       By Robyn                           ${PRI}│"
echo -e "  └──────────────────────────────────────────────────────────┘${RST}"
echo ""
printf "  ${BLD}%-20s${RST} %s\n" "Version"     "2.0.1"
printf "  ${BLD}%-20s${RST} %s\n" "Generated"   "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf "  ${BLD}%-20s${RST} %s\n" "Bare domain" "$BARE_DOMAIN"
printf "  ${BLD}%-20s${RST} %s\n" "WWW domain"  "$WWW_DOMAIN"

# ─────────────────────────────────────────────────────────────
# 1. WHOIS / DOMAIN REGISTRATION
# ─────────────────────────────────────────────────────────────
section "1. WHOIS / DOMAIN REGISTRATION"

if ! command -v whois &>/dev/null; then
    warn "whois not installed — skipping domain registration check"
    note "Install with: brew install whois"
    ISSUES+=("WHOIS: whois not installed — domain registration could not be checked")
else
    WHOIS_RAW=$(whois "$BARE_DOMAIN" 2>/dev/null || true)

    if [[ -z "$WHOIS_RAW" ]] || echo "$WHOIS_RAW" | grep -qiE "^(No match|NOT FOUND|No entries found)"; then
        warn "No WHOIS data returned for ${BARE_DOMAIN}"
        ISSUES+=("WHOIS: no data returned for ${BARE_DOMAIN} — registration status unknown")
    else
        # Extract fields — handle multiple common WHOIS formats
        REGISTRAR=$(echo "$WHOIS_RAW" \
            | grep -iE "^\s*(Registrar|Sponsoring Registrar)\s*:" \
            | grep -iv "IANA\|Abuse\|URL\|WHOIS" \
            | head -1 | sed -E 's/^[^:]+:\s*//' | sed 's/^[[:space:]]*//' || true)

        # Try high-specificity domain-date fields first (avoids matching "Created:" on
        # a registrar sub-object in Nominet / .co.uk WHOIS, which can be a 1980s date).
        CREATED=$(echo "$WHOIS_RAW" \
            | grep -iE "^\s*(Creation Date|Domain Registration Date|Registered on)\s*:" \
            | head -1 | sed -E 's/^[^:]+:\s*//' | sed 's/^[[:space:]]*//' || true)
        # Fallback: generic "created" / "Registered" used by some ccTLDs (.de, .nl, etc.)
        if [[ -z "$CREATED" ]]; then
            CREATED=$(echo "$WHOIS_RAW" \
                | grep -iE "^\s*(created|Registered)\s*:" \
                | grep -iv "Registrar Registration" \
                | head -1 | sed -E 's/^[^:]+:\s*//' | sed 's/^[[:space:]]*//' || true)
        fi

        EXPIRES=$(echo "$WHOIS_RAW" \
            | grep -iE "^\s*(Registry Expiry Date|Expiration Date|Registrar Registration Expiration Date|Expiry Date|paid-till|expires)\s*:" \
            | head -1 | sed -E 's/^[^:]+:\s*//' | sed 's/^[[:space:]]*//' || true)

        UPDATED=$(echo "$WHOIS_RAW" \
            | grep -iE "^\s*(Updated Date|last-update|Last Modified|Last updated)\s*:" \
            | head -1 | sed -E 's/^[^:]+:\s*//' | sed 's/^[[:space:]]*//' || true)

        # Domain status lines — strip ICANN URLs appended after the status code
        STATUSES=$(echo "$WHOIS_RAW" \
            | grep -iE "^\s*Domain Status\s*:" \
            | sed -E 's/^[^:]+:\s*//' | sed 's/^[[:space:]]*//' \
            | sed -E 's/\s+https?:\/\/[^ ]+//' \
            | head -5 || true)

        [[ -n "$REGISTRAR" ]] && row "  Registrar"    "$REGISTRAR"
        [[ -n "$CREATED"   ]] && row "  Registered"   "$CREATED"
        [[ -n "$UPDATED"   ]] && row "  Updated"       "$UPDATED"
        [[ -n "$EXPIRES"   ]] && row "  Expires"       "$EXPIRES"

        if [[ -n "$STATUSES" ]]; then
            while IFS= read -r s; do
                [[ -n "$s" ]] && row "  Status" "$s"
            done <<< "$STATUSES"
        fi

        echo ""

        # Domain expiry countdown
        if [[ -z "$EXPIRES" ]]; then
            warn "Expiry date not found in WHOIS data"
            ISSUES+=("WHOIS: expiry date not found in WHOIS data for ${BARE_DOMAIN}")
        elif ! command -v python3 &>/dev/null; then
            warn "python3 not available — cannot calculate days until expiry"
            ISSUES+=("WHOIS: could not calculate expiry — python3 not available")
        else
            DOMAIN_DAYS=$(echo "$EXPIRES" | python3 -c "
import sys, locale
locale.setlocale(locale.LC_TIME, 'C')
from datetime import datetime, timezone
result = '?'
raw = sys.stdin.read().strip().split()[0]
for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d', '%d-%b-%Y', '%d/%m/%Y',
            '%Y.%m.%d', '%d.%m.%Y', '%m/%d/%Y'):
    try:
        exp = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        result = str((exp - datetime.now(timezone.utc)).days)
        break
    except ValueError:
        pass
print(result)
" 2>/dev/null || echo "?")

            if [[ "$DOMAIN_DAYS" =~ ^-?[0-9]+$ ]]; then
                row "  Days until expiry" "${DOMAIN_DAYS}d"
                if (( DOMAIN_DAYS < 0 )); then
                    bad "Domain registration EXPIRED ${DOMAIN_DAYS#-} days ago"
                    ISSUES+=("WHOIS: domain ${BARE_DOMAIN} registration has EXPIRED")
                elif (( DOMAIN_DAYS <= 14 )); then
                    bad "Domain expires in ${DOMAIN_DAYS} days — renew immediately!"
                    ISSUES+=("WHOIS: domain ${BARE_DOMAIN} expires in ${DOMAIN_DAYS} days (critical)")
                elif (( DOMAIN_DAYS <= 30 )); then
                    warn "Domain expires in ${DOMAIN_DAYS} days — renew soon"
                    ISSUES+=("WHOIS: domain ${BARE_DOMAIN} expires in ${DOMAIN_DAYS} days")
                else
                    good "Domain registration valid for ${DOMAIN_DAYS} more days"
                    POSITIVES+=("Domain registration valid for ${DOMAIN_DAYS} more days")
                fi
            else
                warn "Could not parse expiry date: ${EXPIRES}"
                ISSUES+=("WHOIS: could not parse expiry date for ${BARE_DOMAIN} — verify manually")
            fi
        fi

        # Transfer lock
        if echo "$STATUSES" | grep -qiE "clientTransferProhibited|serverTransferProhibited"; then
            good "Transfer lock active (registrar-locked)"
            POSITIVES+=("Domain transfer lock is active")
        else
            note "No transfer lock detected — domain may be transferable"
        fi
    fi
fi

# ─────────────────────────────────────────────────────────────
# 2. SSL CERTIFICATES
# ─────────────────────────────────────────────────────────────
section "2. SSL CERTIFICATES"

check_ssl() {
    local d="$1" result_var="$2"
    local this_ok=true

    echo -e "  ${BLD}${d}${RST}"
    echo -e "  $(printf '·%.0s' {1..44})"

    local raw_cert cert_pem ssl_info
    raw_cert=$(echo | openssl s_client -connect "${d}:443" -servername "$d" 2>/dev/null || true)
    cert_pem=$(echo "$raw_cert" | openssl x509 2>/dev/null || true)

    if [[ -z "$cert_pem" ]]; then
        local conn_err
        conn_err=$(echo "$raw_cert" | grep -iE "error|unable|refused|timed out|no route" | head -1 | sed 's/^ *//' || true)
        bad "SSL connection failed${conn_err:+ — ${conn_err}}"
        ISSUES+=("SSL: could not retrieve certificate for ${d}")
        eval "$result_var=false"
        return
    fi

    ssl_info=$(echo "$cert_pem" | openssl x509 -noout -subject -issuer -dates 2>/dev/null || true)

    local issuer not_before not_after
    issuer=$(echo "$ssl_info"    | grep 'issuer='    | sed 's/issuer=//'    | sed 's/^ *//')
    not_before=$(echo "$ssl_info" | grep 'notBefore=' | sed 's/notBefore=//'  | sed 's/^ *//')
    not_after=$(echo "$ssl_info"  | grep 'notAfter='  | sed 's/notAfter=//'   | sed 's/^ *//')

    row "  Issuer"     "$issuer"
    row "  Valid from" "$not_before"
    row "  Expires"    "$not_after"

    # Days until expiry
    if command -v python3 &>/dev/null && [[ -n "$not_after" ]]; then
        local days_left
        days_left=$(python3 -c "
from datetime import datetime
result = '?'
for fmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z'):
    try:
        exp = datetime.strptime('${not_after}', fmt)
        result = str((exp - datetime.utcnow()).days)
        break
    except ValueError:
        pass
print(result)
" 2>/dev/null || echo "?")
        if [[ "$days_left" =~ ^-?[0-9]+$ ]]; then
            row "  Days until expiry" "${days_left}d"
            if (( days_left < 0 )); then
                bad "Certificate EXPIRED ${days_left#-} days ago"
                ISSUES+=("SSL: certificate for ${d} has EXPIRED")
                this_ok=false
            elif (( days_left < 14 )); then
                bad "Certificate expires in ${days_left} days!"
                ISSUES+=("SSL: certificate for ${d} expires in ${days_left} days (critical)")
                this_ok=false
            elif (( days_left < 30 )); then
                warn "Certificate expires in ${days_left} days"
                ISSUES+=("SSL: certificate for ${d} expires soon (${days_left} days)")
            else
                good "Certificate valid for ${days_left} more days"
            fi
        fi
    fi

    # TLS version
    local tls_ver
    tls_ver=$(echo "$raw_cert" | grep -i "^    Protocol" | awk '{print $NF}' | head -1 || true)
    [[ -n "$tls_ver" ]] && row "  TLS version" "$tls_ver"

    # SAN coverage check — does cert cover this domain?
    local sans d_lower covered
    sans=$(echo "$cert_pem" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
           | grep -oE 'DNS:[^,]+' | sed 's/DNS://' | tr -d ' ' | tr '[:upper:]' '[:lower:]' || true)
    d_lower=$(echo "$d" | tr '[:upper:]' '[:lower:]')
    covered=false

    while IFS= read -r san; do
        [[ -z "$san" ]] && continue
        if [[ "$san" == \*.* ]]; then
            local base="${san#\*.}"
            [[ "$d_lower" == *."$base" || "$d_lower" == "$base" ]] && { covered=true; break; }
        elif [[ "$san" == "$d_lower" ]]; then
            covered=true; break
        fi
    done <<< "$sans"

    if $covered; then
        good "Certificate covers ${d}"
    else
        bad "Certificate does NOT cover ${d}"
        note "SANs on cert: $(echo "$sans" | tr '\n' ' ')"
        ISSUES+=("SSL: certificate does not cover ${d}")
        this_ok=false
    fi

    $this_ok && eval "$result_var=true" || eval "$result_var=false"
}

check_ssl "$BARE_DOMAIN" SSL_BARE_OK
check_ssl "$WWW_DOMAIN"  SSL_WWW_OK

# ─────────────────────────────────────────────────────────────
# 3. A RECORDS (PRESSABLE RANGE)
# ─────────────────────────────────────────────────────────────
section "3. A RECORDS (PRESSABLE RANGE CHECK)"

note "Expected IP ranges: 199.16.172.1–254 and 199.16.173.1–254"
echo ""

check_a_records() {
    local d="$1"
    echo -e "  ${BLD}${d}${RST}"

    local records
    records=$(dig +short A "$d" @8.8.8.8 2>/dev/null \
              | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -10 || true)

    if [[ -z "$records" ]]; then
        bad "No A records found for ${d}"
        ISSUES+=("DNS: no A records found for ${d}")
        echo ""
        return
    fi

    local all_ok=true
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if is_pressable_ip "$ip"; then
            good "${ip}  —  expected range"
        else
            bad "${ip}  —  NOT in expected range"
            ISSUES+=("DNS: A record for ${d} (${ip}) is not in the expected IP range")
            all_ok=false
        fi
    done <<< "$records"

    $all_ok && POSITIVES+=("A records for ${d} all point to the expected range")
}

check_a_records "$BARE_DOMAIN"
check_a_records "$WWW_DOMAIN"

# ─────────────────────────────────────────────────────────────
# 4. PROBLEMATIC RECORD TYPES
# ─────────────────────────────────────────────────────────────
section "4. PROBLEMATIC RECORD TYPES"

note "The following record types must be absent for SSL provisioning to function"
echo ""

check_absent() {
    local d="$1" rtype="$2" reason="$3"
    local result
    # Strip lines ending with '.' — these are CNAME chain artifacts from dig +short,
    # not actual records of the queried type (e.g. AAAA showing a CNAME target).
    result=$(dig +short "$rtype" "$d" @8.8.8.8 2>/dev/null | grep -v '\.$' | head -5 || true)

    if [[ -n "$result" ]]; then
        bad "${rtype} records present on ${d}"
        note "Issue: ${reason}"
        while IFS= read -r r; do
            [[ -n "$r" ]] && note "  ${r}"
        done <<< "$result"
        ISSUES+=("DNS: ${rtype} record present on ${d} — ${reason}")
    else
        good "No ${rtype} records on ${d}"
    fi
}

for dom in "$BARE_DOMAIN" "$WWW_DOMAIN"; do
    echo -e "  ${BLD}${dom}${RST}"
    check_absent "$dom" "AAAA"   "IPv6 addresses can break SSL provisioning"
    check_absent "$dom" "CAA"    "May prevent the certificate authority from issuing"
    check_absent "$dom" "DS"     "DS records signal DNSSEC delegation — blocks certificate management"
    check_absent "$dom" "DNSKEY" "Indicates the zone is cryptographically signed with DNSSEC"
done

# ─────────────────────────────────────────────────────────────
# 5. DNSSEC STATUS
# ─────────────────────────────────────────────────────────────
section "5. DNSSEC STATUS"

note "DNSSEC must be fully disabled for SSL provisioning to work"
echo ""

check_dnssec() {
    local d="$1"
    echo -e "  ${BLD}${d}${RST}"
    local dnssec_found=false

    # Check: DNSKEY records (zone signing keys) — reported here for visibility;
    # the issue is already tracked via section 4's problematic-record check
    local dnskey
    dnskey=$(dig +short DNSKEY "$d" @8.8.8.8 2>/dev/null | grep -v '\.$' | head -3 || true)
    if [[ -n "$dnskey" ]]; then
        bad "DNSKEY records found — zone is cryptographically signed"
        dnssec_found=true
    else
        good "No DNSKEY records"
    fi

    # Check: RRSIG in A record response (signed zone)
    local rrsig
    rrsig=$(dig +dnssec A "$d" @8.8.8.8 2>/dev/null \
            | grep -E "^[^;].*[[:space:]]RRSIG[[:space:]]" | head -2 || true)
    if [[ -n "$rrsig" ]]; then
        bad "RRSIG records in A query response — zone signing active"
        dnssec_found=true
        ISSUES+=("DNSSEC: RRSIG records present for ${d}")
    else
        good "No RRSIG records in A response"
    fi

    # Check: AD (Authenticated Data) flag — full DNSSEC chain of trust
    local flags_line
    flags_line=$(dig +dnssec A "$d" @8.8.8.8 2>/dev/null | grep "^;; flags:" | head -1 || true)
    if echo "$flags_line" | grep -qwi "ad"; then
        bad "AD flag set in DNS response — DNSSEC chain of trust is established"
        note "$flags_line"
        dnssec_found=true
        ISSUES+=("DNSSEC: AD flag set for ${d} — full DNSSEC validation active")
    else
        good "AD flag not set — no active DNSSEC validation"
        [[ -n "$flags_line" ]] && note "$flags_line"
    fi

    $dnssec_found || POSITIVES+=("DNSSEC not active on ${d}")
}

check_dnssec "$BARE_DOMAIN"
check_dnssec "$WWW_DOMAIN"

# ─────────────────────────────────────────────────────────────
# 6. SUMMARY
# ─────────────────────────────────────────────────────────────
section "6. SUMMARY"

# Add SSL results to positives
$SSL_BARE_OK && POSITIVES+=("SSL certificate valid and covers ${BARE_DOMAIN}")
$SSL_WWW_OK  && POSITIVES+=("SSL certificate valid and covers ${WWW_DOMAIN}")

if (( ${#POSITIVES[@]} > 0 )); then
    echo -e "  ${PRI}✓ Passing:${RST}"
    for p in "${POSITIVES[@]}"; do good "$p"; done
    echo ""
fi

if (( ${#ISSUES[@]} > 0 )); then
    echo -e "  ${PRI}✗ Issues to resolve:${RST}"
    for issue in "${ISSUES[@]}"; do bad "$issue"; done
else
    if $SSL_BARE_OK || $SSL_WWW_OK; then
        good "All checks passed — SSL is functioning correctly"
    else
        good "All checks passed — domain is ready for SSL provisioning"
    fi
fi

echo ""
echo -e "  ${GRY}↳ Common resolutions:${RST}"
echo -e "  ${GRY}  • Wrong A record IP : Update DNS to 199.16.172.x or 199.16.173.x${RST}"
echo -e "  ${GRY}  • AAAA records      : Remove IPv6 records from DNS${RST}"
echo -e "  ${GRY}  • CAA records       : Remove entirely, or add letsencrypt.org${RST}"
echo -e "  ${GRY}  • DS / DNSKEY       : Disable DNSSEC at your registrar or DNS provider${RST}"
echo -e "  ${GRY}  • DNSSEC            : Disable at registrar — changes may take up to 48 hrs${RST}"
echo -e "  ${GRY}  • Domain expiry     : Renew registration via your registrar immediately${RST}"
echo ""

# ── Save report ───────────────────────────────────────────────
kill "$TAIL_PID" 2>/dev/null || true; wait "$TAIL_PID" 2>/dev/null || true; sleep 0.2
exec 1>&3 2>&3 3>&-

_PY=$(mktemp)
cat > "$_PY" <<'PYEOF'
import sys, re

with open(sys.argv[1], 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Strip ANSI escape codes
content = re.sub(r'\033\[[0-9;]*m', '', content)

# Replace box-drawing and symbol characters with ASCII equivalents
replacements = {
    '┌': '+', '─': '-', '┐': '+',
    '└': '+', '┘': '+', '│': '|',
    '—': '--', '–': '-', '→': '->',
    '…': '...', '×': 'x', '↳': '>',
    '⚠': '!', '✓': '+', '✗': 'x',
    '•': '*', '·': '.',
}
for char, replacement in replacements.items():
    content = content.replace(char, replacement)

with open(sys.argv[2], 'w', encoding='utf-8') as f:
    f.write(content)
PYEOF

if python3 "$_PY" "$REPORT_TMPFILE" "$REPORT_FILENAME"; then
    rm -f "$REPORT_TMPFILE" "$_PY"
    printf "\033[3;38;2;136;146;160m  Report saved: %s\033[0m\n" "$REPORT_BASENAME"
else
    printf "\033[33m  Could not write report to: %s\033[0m\n" "$REPORT_FILENAME"
    rm -f "$REPORT_TMPFILE" "$_PY"
fi
