#!/bin/bash
#
# dbcheck.sh - Verify CA database, CRL, and cert-file consistency.
#
# Checks:
#   1. Database format  — no empty subject DNs, all entries V or R
#   2. Explicit revocations — certs that revoke.sh marks R are actually R
#   3. CRL vs database  — R entries in each database match the corresponding CRL exactly
#   4. CRL signatures   — each CRL verifies against its issuing CA cert
#   5. Cert coverage    — every non-CA cert in pem/ appears in the right database
#
# Run from the certutils/ directory.

CWD=$(pwd)
DBDIR=$CWD/data/database
PEMDIR=$CWD/data/pem
CRLDIR=$CWD/../cards/ICAM_Card_Objects/ICAM_CA_and_Signer/crls

PASS=0
FAIL=0
SKIP=0

pass() { printf "  PASS  %s\n" "$*"; PASS=$((PASS+1)); }
fail() { printf "  FAIL  %s\n" "$*"; FAIL=$((FAIL+1)); }
skip() { printf "  SKIP  %s\n" "$*"; SKIP=$((SKIP+1)); }

# ---------------------------------------------------------------------------
# CA Subject Key Identifiers (must match mkcadata.sh)
# ---------------------------------------------------------------------------
PIV_GEN3="0C703BB5460F1B743D0762F30AD090AC7AE33E84"
PIV_GEN3_P384="243394A67A7941F42F5D208A6F4E610BA4851CFA"
PIV_GEN3_P256="0D51EDB2C8D33DB97AA05FE0D4F59A275363AB3C"
PIV_GEN3_RSA2048="3FDC04DB5C26E9A7FA60C2205982130B0E4AEA45"
PIV_GEN1_2="0A657668E6A866BB506AB5BB2B0F91D621EEA2D1"
PIVI_GEN3="20DC6669B935ACCCEDDBB43A6C5C6950BE69AB31"

# ---------------------------------------------------------------------------
# Cert files that revoke.sh explicitly marks as R, grouped by database.
# Card 24 certs are copied from the cards directory by mkcadata.sh before
# revocation, so they appear in pem/ as ICAM_Test_Card_24_PIV_*.crt.
# ---------------------------------------------------------------------------
GEN3_REVOKED_CERTS="
ICAM_Test_Card_PIV_OCSP_Revoked_Signer_No_Check_Present_gen3.crt
ICAM_Test_Card_PIV_OCSP_Revoked_Signer_No_Check_Not_Present_gen3.crt
ICAM_Test_Card_PIV_Revoked_CHUID_Signer_Cert_gen3.crt
ICAM_Test_Card_PIV_Card_Auth_SP_800-73-4_Revoked_Card_Auth_Cert.crt
"

GEN1_2_REVOKED_CERTS="
ICAM_Test_Card_PIV_Revoked_Content_Signer_gen1-2.crt
ICAM_Test_Card_24_PIV_Auth.crt
ICAM_Test_Card_24_PIV_Card_Auth.crt
"

# ---------------------------------------------------------------------------
# Helper: strip leading zeros and uppercase a hex serial
# ---------------------------------------------------------------------------
normalize_serial() {
    printf '%s' "$1" | sed 's/^0*//' | tr '[:lower:]' '[:upper:]'
}

# ---------------------------------------------------------------------------
# Helper: get normalized serial from a cert file
# ---------------------------------------------------------------------------
cert_serial() {
    openssl x509 -serial -noout -in "$1" 2>/dev/null | sed 's/serial=//'
}

# ---------------------------------------------------------------------------
# Helper: get AKID from a cert file (uppercase hex, no colons or whitespace)
# Works with both OpenSSL 1.x ("keyid:XX:XX") and 3.x ("XX:XX") formats.
# ---------------------------------------------------------------------------
cert_akid() {
    openssl x509 -text -noout -in "$1" 2>/dev/null |
        grep -A1 "Authority Key Identifier" |
        grep -v "Authority Key" |
        sed 's/[[:space:]]//g; s/://g' |
        tr '[:lower:]' '[:upper:]'
}

# ---------------------------------------------------------------------------
# Helper: map an AKID to the appropriate index file
# ---------------------------------------------------------------------------
db_for_akid() {
    case "$1" in
        "$PIV_GEN3")         echo "$DBDIR/piv-gen3-index.txt" ;;
        "$PIV_GEN3_P384")    echo "$DBDIR/piv-gen3-p384-index.txt" ;;
        "$PIV_GEN3_P256")    echo "$DBDIR/piv-gen3-p256-index.txt" ;;
        "$PIV_GEN3_RSA2048") echo "$DBDIR/piv-rsa-2048-index.txt" ;;
        "$PIV_GEN1_2")       echo "$DBDIR/piv-gen1-2-index.txt" ;;
        "$PIVI_GEN3")        echo "$DBDIR/pivi-gen3-index.txt" ;;
        *)                   echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: look up a serial in a database; return V, R, or "" if not found.
# Comparison is case-insensitive and leading-zero-insensitive.
# ---------------------------------------------------------------------------
db_lookup() {
    local dbfile="$1"
    local target
    target=$(normalize_serial "$2")
    awk -F'\t' -v t="$target" 'BEGIN { IGNORECASE=1 } {
        s = $4; gsub(/^0+/, "", s)
        if (toupper(s) == toupper(t)) { print $1; exit }
    }' "$dbfile" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: return sorted normalized revoked serials from a database file
# ---------------------------------------------------------------------------
db_revoked_serials() {
    awk -F'\t' '$1=="R" { s=$4; gsub(/^0+/,"",s); print toupper(s) }' "$1" 2>/dev/null | sort
}

# ---------------------------------------------------------------------------
# Helper: return sorted normalized revoked serials from a DER CRL
# ---------------------------------------------------------------------------
crl_revoked_serials() {
    openssl crl -inform DER -in "$1" -text -noout 2>/dev/null |
        awk '/Serial Number:/ { s=$NF; gsub(/^0+/,"",s); print toupper(s) }' | sort
}

# ===========================================================================
# Section 1: Database format
# ===========================================================================
echo "=== 1. Database format ==="

for db in piv-gen3-index.txt piv-gen1-2-index.txt pivi-gen3-index.txt \
           piv-gen3-p384-index.txt piv-gen3-p256-index.txt \
           piv-rsa-2048-index.txt pivi-gen1-2-index.txt legacy-index.txt; do
    f="$DBDIR/$db"
    if [ ! -f "$f" ]; then
        skip "$db — file not found"
        continue
    fi
    rows=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
    if [ "${rows:-0}" -eq 0 ]; then
        skip "$db — empty (0 entries)"
        continue
    fi
    empty=$(awk -F'\t' 'NF < 6 || $6 == "" { c++ } END { print c+0 }' "$f")
    bad=$(awk   -F'\t' '$1 != "V" && $1 != "R" { c++ } END { print c+0 }' "$f")
    if [ "$empty" -eq 0 ] && [ "$bad" -eq 0 ]; then
        pass "$db — $rows entries, all well-formed, no empty DNs"
    else
        [ "$empty" -gt 0 ] && fail "$db — $empty of $rows entries have an empty subject DN"
        [ "$bad"   -gt 0 ] && fail "$db — $bad of $rows entries have an invalid status flag (not V or R)"
    fi
done

# ===========================================================================
# Section 2: Explicit revocations
# ===========================================================================
echo ""
echo "=== 2. Explicit revocations ==="

check_revoked_certs() {
    local dbfile="$1"
    local dbname
    dbname=$(basename "$dbfile")
    shift
    for certname in "$@"; do
        certfile="$PEMDIR/$certname"
        if [ ! -f "$certfile" ]; then
            fail "$dbname: $certname — cert file not found in pem/"
            continue
        fi
        serial=$(cert_serial "$certfile")
        status=$(db_lookup "$dbfile" "$serial")
        snorm=$(normalize_serial "$serial")
        if [ -z "$status" ]; then
            fail "$dbname: $certname (serial $snorm) — not found in database"
        elif [ "$status" = "R" ]; then
            pass "$dbname: $certname (serial $snorm) — correctly marked R"
        else
            fail "$dbname: $certname (serial $snorm) — status is $status, expected R"
        fi
    done
}

# shellcheck disable=SC2086
check_revoked_certs "$DBDIR/piv-gen3-index.txt"  $GEN3_REVOKED_CERTS
# shellcheck disable=SC2086
check_revoked_certs "$DBDIR/piv-gen1-2-index.txt" $GEN1_2_REVOKED_CERTS

# ===========================================================================
# Section 3: CRL vs database consistency
# ===========================================================================
echo ""
echo "=== 3. CRL vs database consistency ==="

check_crl_vs_db() {
    local dbfile="$1"
    local crlfile="$2"
    local label="$3"

    if [ ! -f "$crlfile" ]; then
        skip "$label — CRL file not found: $crlfile"
        return
    fi

    db_r=$(db_revoked_serials "$dbfile")
    crl_r=$(crl_revoked_serials "$crlfile")

    if [ "$db_r" = "$crl_r" ]; then
        count=$(echo "$db_r" | grep -c . 2>/dev/null | tr -d ' ' || echo 0)
        pass "$label — $count revoked entries agree between database and CRL"
    else
        fail "$label — database R entries do not match CRL"
        only_db=$(comm -23 <(echo "$db_r") <(echo "$crl_r"))
        only_crl=$(comm -13 <(echo "$db_r") <(echo "$crl_r"))
        [ -n "$only_db"  ] && printf "        in DB only:  %s\n" "$only_db"
        [ -n "$only_crl" ] && printf "        in CRL only: %s\n" "$only_crl"
    fi
}

check_crl_vs_db "$DBDIR/piv-gen3-index.txt"       "$CRLDIR/ICAMTestCardGen3SigningCA.crl"        "Gen3 Signing CA"
check_crl_vs_db "$DBDIR/piv-gen1-2-index.txt"    "$CRLDIR/ICAMTestCardSigningCA.crl"           "Gen1-2 Signing CA"
check_crl_vs_db "$DBDIR/pivi-gen3-index.txt"     "$CRLDIR/ICAMTestCardPIV-ISigningCA.crl"      "PIV-I Signing CA"
check_crl_vs_db "$DBDIR/piv-gen3-p384-index.txt" "$CRLDIR/ICAMTestCardP384PIVSigningCA.crl"    "P-384 Signing CA"
check_crl_vs_db "$DBDIR/piv-rsa-2048-index.txt"  "$CRLDIR/ICAMTestCardRSA2048PIVSigningCA.crl" "RSA-2048 Signing CA"

# ===========================================================================
# Section 4: CRL signature verification
# ===========================================================================
echo ""
echo "=== 4. CRL signature verification ==="

verify_crl_sig() {
    local crlfile="$1"
    local cacert="$2"
    local label="$3"
    if [ ! -f "$crlfile" ]; then skip "$label — CRL not found"; return; fi
    if [ ! -f "$cacert"  ]; then skip "$label — CA cert not found"; return; fi
    result=$(openssl crl -inform DER -in "$crlfile" -CAfile "$cacert" -noout 2>&1)
    if echo "$result" | grep -q "verify OK"; then
        pass "$label — CRL signature valid"
    else
        fail "$label — CRL signature invalid: $result"
    fi
}

verify_crl_sig "$CRLDIR/ICAMTestCardGen3SigningCA.crl" \
    "$PEMDIR/ICAM_Test_Card_PIV_Signing_CA_-_gold_gen3.crt" \
    "Gen3 Signing CA"
verify_crl_sig "$CRLDIR/ICAMTestCardSigningCA.crl" \
    "$PEMDIR/ICAM_Test_Card_PIV_Signing_CA_-_gold_gen1-2.crt" \
    "Gen1-2 Signing CA"
verify_crl_sig "$CRLDIR/ICAMTestCardPIV-ISigningCA.crl" \
    "$PEMDIR/ICAM_Test_Card_PIV-I_Signing_CA_-_gold_gen3.crt" \
    "PIV-I Signing CA"
verify_crl_sig "$CRLDIR/ICAMTestCardP384PIVSigningCA.crl" \
    "$PEMDIR/ICAM_Test_Card_PIV_P-384_Signing_CA_-_gold_gen3.crt" \
    "P-384 Signing CA"
verify_crl_sig "$CRLDIR/ICAMTestCardRSA2048PIVSigningCA.crl" \
    "$PEMDIR/ICAM_Test_Card_PIV_RSA_2048_Signing_CA_-_gold_gen3.crt" \
    "RSA-2048 Signing CA"

# ===========================================================================
# Section 5: Signer cert coverage
#
# Checks that the OCSP response signers and content signers — the cert
# group routed by AKID in mkcadata.sh's "Adding OCSP response, content
# signing certs" loop — all appear in the correct database with the right
# status.  Card EE certs (PIV Auth, Dig Sig, etc.) are indexed from the
# card directories by reindex() and are not checked here; their revoked
# members are already verified in Section 2.
# ===========================================================================
echo ""
echo "=== 5. Signer cert coverage ==="

# Build revoked-serial set from Section 2's cert list
revoked_serials=""
for certname in $GEN3_REVOKED_CERTS $GEN1_2_REVOKED_CERTS; do
    cf="$PEMDIR/$certname"
    [ -f "$cf" ] || continue
    s=$(normalize_serial "$(cert_serial "$cf")")
    revoked_serials="$revoked_serials $s"
done

ok=0; missing=0; wrong_status=0

for certfile in "$PEMDIR"/*.crt; do
    [ -f "$certfile" ] || continue
    base=$(basename "$certfile")

    # Only check OCSP signers, content signers, and SM cert signers.
    # These are the certs the AKID-routing loop in mkcadata.sh places into the
    # index files.  Card EE certs (PIV_Auth, Dig_Sig, Key_Mgmt, Card_Auth)
    # have different pem/-vs-card-directory serial pairs and are excluded here.
    case "$base" in
        *OCSP*|*Content_Signer*|*SM_Certificate_Signer*|*Intermediate_CVC_Signer*) ;;
        *) continue ;;
    esac

    # Skip CA certificates
    if openssl x509 -text -noout -in "$certfile" 2>/dev/null | grep -q "CA:TRUE"; then
        continue
    fi

    serial=$(cert_serial "$certfile")
    [ -z "$serial" ] && continue
    snorm=$(normalize_serial "$serial")

    akid=$(cert_akid "$certfile")
    dbfile=$(db_for_akid "$akid")

    if [ -z "$dbfile" ]; then
        # Issued by a CA not in our known set (e.g. PIV-I gen1-2 content signer).
        # Not an error — mkcadata.sh also skips these.
        continue
    fi

    actual=$(db_lookup "$dbfile" "$serial")

    if [ -z "$actual" ]; then
        fail "$(basename "$dbfile"): $base (serial $snorm) — missing from database"
        missing=$((missing+1))
        continue
    fi

    expected="V"
    for r in $revoked_serials; do
        if [ "$r" = "$snorm" ]; then expected="R"; break; fi
    done

    if [ "$actual" = "$expected" ]; then
        ok=$((ok+1))
    else
        fail "$(basename "$dbfile"): $base (serial $snorm) — status $actual, expected $expected"
        wrong_status=$((wrong_status+1))
    fi
done

total=$((ok + missing + wrong_status))
if [ $missing -eq 0 ] && [ $wrong_status -eq 0 ]; then
    pass "$total signer certs present in correct database with correct status"
else
    fail "$missing missing, $wrong_status wrong status out of $total signer certs checked"
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo "=== Summary ==="
printf "  Passed: %d\n" "$PASS"
printf "  Failed: %d\n" "$FAIL"
printf "  Skipped: %d\n" "$SKIP"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
