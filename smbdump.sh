#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="3.0"
MAX_BIN_MB="${MAX_BIN_MB:-50}"
CONTEXT_LINES="${CONTEXT_LINES:-2}"

SOURCE=""
OUT=""
NO_PROMPT=0
CUSTOM_IGNORE_CASE=0
CHECK_ARCHIVES=0
CHECK_GIT=0
CUSTOM_KEYWORDS=()

banner() {
cat <<'EOF'
   _____ __  _______   _______  ___    ____  ____________
  / ___//  |/  / __ ) / ____// / / |  / /  |/  / ____/ _ \
  \__ \/ /|_/ / __  |/ / _/ /_//| | / / /|_/ / __/ / /_/ /
 ___/ / /  / / /_/ / /_/ /    / | |/ / /  / / /___/ _, _/
/____/_/  /_/_____/\____/____/  |___/_/  /_/_____/_/ |_|

                 SMB DUMP 
        Secrets • Accounts • Configs • Privilege Hunt  
EOF
printf '                         v%s\n\n' "$VERSION"
}

usage() {
cat <<'EOF'
Usage:
  smbgrabber.sh -s <share_dump> [options]

Required:
  -s, --share <path|name>       Local directory containing the dumped SMB share.

Options:
  -o, --output <dir>            Output directory.
  -k, --keyword <pattern>       Add custom keyword. Can be repeated.
                                '*' works as wildcard.
  -i, --ignore-case-custom      Custom keyword search becomes case-insensitive.
                                Default: case-sensitive.
  -m, --max-bin-mb <MB>         Max file size for strings pass. Default: 50 MB.
  -c, --context <lines>         Context lines around text matches. Default: 2.
  -a, --archives                Inspect archive file listings when supported.
  -g, --git-history             Inspect local Git history when .git is found.
  -n, --no-prompt               Skip interactive keyword prompt.
  -h, --help                    Show help.
  -V, --version                 Show version.

Examples:
  ./smbgrabber.sh -s Development
  ./smbgrabber.sh -s ./dump/Department_Shares
  ./smbgrabber.sh -s Development -k 'svc_*'
  ./smbgrabber.sh -s Development -k 'C:\Users\*\Desktop\*'
  ./smbgrabber.sh -s Development -k '*password*' -i
  ./smbgrabber.sh -s Development -a -g

Custom keyword rules:
  - Default: CASE-SENSITIVE
  - '*' = wildcard for any number of characters
  - Other regex metacharacters are treated literally
  - Quote -k values in the shell, especially paths and special characters

Interactive mode:
  Enter one keyword per line.
  Type x and press ENTER to start the grabber.

This tool only analyzes the supplied local dump directory.
EOF
}

die()  { printf '[-] %s\n' "$*" >&2; exit 1; }
log()  { printf '[*] %s\n' "$*"; }
good() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

sanitize_filename() {
    printf '%s' "$1" | sed 's#[^A-Za-z0-9._-]#_#g'
}

keyword_to_regex() {
    local input="$1"
    local output=""
    local char
    local i

    for (( i=0; i<${#input}; i++ )); do
        char="${input:i:1}"

        case "$char" in
            '*')
                output+='.*'
                ;;
            '.'|'['|']'|'('|')'|'{'|'}'|'+'|'?'|'^'|'$'|'|'|'\\')
                output+="\\$char"
                ;;
            *)
                output+="$char"
                ;;
        esac
    done

    printf '%s' "$output"
}

count_lines() {
    local f="$1"

    if [[ -f "$f" ]]; then
        wc -l < "$f"
    else
        echo 0
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in

        -s|--share)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            SOURCE="$2"
            shift 2
            ;;

        -o|--output)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            OUT="$2"
            shift 2
            ;;

        -k|--keyword)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            CUSTOM_KEYWORDS+=("$2")
            shift 2
            ;;

        -i|--ignore-case-custom)
            CUSTOM_IGNORE_CASE=1
            shift
            ;;

        -m|--max-bin-mb)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            MAX_BIN_MB="$2"
            shift 2
            ;;

        -c|--context)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            CONTEXT_LINES="$2"
            shift 2
            ;;

        -a|--archives)
            CHECK_ARCHIVES=1
            shift
            ;;

        -g|--git-history)
            CHECK_GIT=1
            shift
            ;;

        -n|--no-prompt)
            NO_PROMPT=1
            shift
            ;;

        -h|--help)
            banner
            usage
            exit 0
            ;;

        -V|--version)
            echo "SMB DUMP GRABBER v$VERSION"
            exit 0
            ;;

        *)
            die "Unknown option: $1 (use -h)"
            ;;
    esac
done

banner

[[ -n "$SOURCE" ]] || {
    usage
    exit 1
}

if [[ ! -d "$SOURCE" && -d "./$SOURCE" ]]; then
    SOURCE="./$SOURCE"
fi

[[ -d "$SOURCE" ]] || die "Share dump directory not found: $SOURCE"
[[ "$MAX_BIN_MB" =~ ^[0-9]+$ ]] || die "--max-bin-mb must be an integer"
[[ "$CONTEXT_LINES" =~ ^[0-9]+$ ]] || die "--context must be an integer"

ROOT="$(readlink -f "$SOURCE")"
SHARE_NAME="$(basename "$ROOT")"
SAFE_SHARE="$(sanitize_filename "$SHARE_NAME")"

if [[ -z "$OUT" ]]; then
    OUT="smbgrab_${SAFE_SHARE}_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "$OUT"/{hits,lists,meta,priority,optional}
OUT="$(readlink -f "$OUT")"

############################################
# Interactive keyword collection
############################################

if [[ "$NO_PROMPT" -eq 0 ]]; then

    echo
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 CUSTOM KEYWORD SEARCH                       ║"
    echo "╠══════════════════════════════════════════════════════════════╣"

    if [[ "$CUSTOM_IGNORE_CASE" -eq 1 ]]; then
        echo "║ Search mode: CASE-INSENSITIVE                               ║"
    else
        echo "║ Search mode: CASE-SENSITIVE                                 ║"
    fi

    echo "║ Wildcard: '*' = any number of characters                   ║"
    echo "║ Other special characters are searched literally.           ║"
    echo "║ Examples: svc_*   *password*   C:\\Users\\*\\Desktop\\*        ║"
    echo "║                                                              ║"
    echo "║ Press x and ENTER to start the grabber.                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo

    while true; do

        IFS= read -r -p "keyword> " USER_KEYWORD || break

        if [[ "$USER_KEYWORD" == "x" ]]; then
            echo
            good "Starting SMB Grabber..."
            break
        fi

        if [[ -z "$USER_KEYWORD" ]]; then
            continue
        fi

        CUSTOM_KEYWORDS+=("$USER_KEYWORD")

        printf '[+] Added keyword: %s\n' "$USER_KEYWORD"

    done
fi

echo

log "Share     : $SHARE_NAME"
log "Root      : $ROOT"
log "Output    : $OUT"
log "Context   : ${CONTEXT_LINES} line(s)"
log "Strings   : <= ${MAX_BIN_MB} MB"
log "Archives  : $([[ "$CHECK_ARCHIVES" -eq 1 ]] && echo enabled || echo disabled)"
log "Git       : $([[ "$CHECK_GIT" -eq 1 ]] && echo enabled || echo disabled)"

if [[ ${#CUSTOM_KEYWORDS[@]} -gt 0 ]]; then

    log "Keywords  :"

    for kw in "${CUSTOM_KEYWORDS[@]}"; do
        printf '             [%s]\n' "$kw"
    done

else
    log "Keywords  : none"
fi

echo

############################################
# Patterns
############################################

CRITICAL_PATTERN='BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|cpassword|DefaultPassword|AutoAdminLogon|ANSIBLE_VAULT|vault_password|client_secret|secret_access_key|aws_secret_access_key|AccountKey=|SharedAccessSignature|password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|pwd[[:space:]]*[:=]'

HIGH_PATTERN='credential|passphrase|api[_-]?key|access[_-]?key|secret[_-]?key|token|bearer|authorization:|connectionstring|connection string|bind_password|ldap_password|ansible_password|become_pass|private[_-]?key|PSCredential|ConvertTo-SecureString|User ID=|UID=|PWD=|Password='

AD_PATTERN='sAMAccountName|userPrincipalName|memberOf|servicePrincipalName|msDS-|distinguishedName|Domain Admins|Enterprise Admins|Administrators|Remote Management Users|Remote Desktop Users|Backup Operators|Account Operators|Server Operators|DnsAdmins|GenericAll|GenericWrite|WriteDACL|WriteOwner|AllowedToActOnBehalfOfOtherIdentity|DONT_REQ_PREAUTH|TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION'

DEVOPS_PATTERN='ansible_user|ansible_password|vault_password_file|VAULT_PASSWORD|remote_user|become_pass|docker login|registry_password|KUBECONFIG|client-certificate-data|client-key-data|AWS_|AZURE_|ARM_|GOOGLE_APPLICATION_CREDENTIALS|terraform|tenant|subscription|client_secret|servicePrincipal'

DB_PATTERN='jdbc:(mysql|postgresql|sqlserver|oracle)|mongodb(\+srv)?://|redis://|postgres(ql)?://|mysql://|Server=.*Database=.*(User|UID)|Data Source=.*Initial Catalog|Integrated Security|Trusted_Connection|User ID=|UID=|Password=|PWD='

WINDOWS_PATTERN='cpassword|AutoAdminLogon|DefaultPassword|DefaultUserName|DefaultDomainName|RunAs|runas /user|net use|cmdkey|New-PSDrive|ConvertTo-SecureString|PSCredential|ScheduledTask|schtasks|WinRM|WSMan|CredSSP|NTLM|Kerberos'

############################################
# 1. Inventory
############################################

log "1/12  Building inventory..."

find "$ROOT" \
    -type f \
    -printf '%p\t%s\t%TY-%Tm-%Td %TH:%TM:%TS\n' \
    2>/dev/null \
    | sort \
    > "$OUT/meta/files.tsv"

find "$ROOT" \
    -type d \
    -printf '%p\n' \
    2>/dev/null \
    | sort \
    > "$OUT/meta/dirs.txt"

find "$ROOT" \
    -type f \
    2>/dev/null \
    | wc -l \
    > "$OUT/meta/file_count.txt"

du -sh "$ROOT" \
    2>/dev/null \
    > "$OUT/meta/size.txt" || true

############################################
# 2. Interesting filenames
############################################

log "2/12  Hunting interesting filenames..."

find "$ROOT" -type f \( \
    -iname '*password*' \
    -o -iname '*passwd*' \
    -o -iname '*secret*' \
    -o -iname '*credential*' \
    -o -iname '*creds*' \
    -o -iname '*token*' \
    -o -iname '*vault*' \
    -o -iname '*backup*' \
    -o -iname '*.bak' \
    -o -iname '*.old' \
    -o -iname '*.orig' \
    -o -iname '*.save' \
    -o -iname '*.env' \
    -o -iname '.env*' \
    -o -iname 'web.config' \
    -o -iname 'appsettings*.json' \
    -o -iname 'application*.properties' \
    -o -iname 'application*.yml' \
    -o -iname 'application*.yaml' \
    -o -iname 'settings*.xml' \
    -o -iname 'config*.xml' \
    -o -iname 'config*.ini' \
    -o -iname 'ansible.cfg' \
    -o -iname 'inventory*' \
    -o -iname 'unattend.xml' \
    -o -iname 'sysprep*.xml' \
    -o -iname 'groups.xml' \
    -o -iname 'services.xml' \
    -o -iname 'scheduledtasks.xml' \
    -o -iname 'registry.xml' \
    -o -iname 'ntds.dit' \
    -o -iname '*.kdbx' \
    -o -iname '*.pfx' \
    -o -iname '*.p12' \
    -o -iname '*.pem' \
    -o -iname '*.key' \
    -o -iname 'id_rsa' \
    -o -iname 'id_ed25519' \
    -o -iname '*.rdp' \
    -o -iname '*.ovpn' \
    -o -iname '*.ppk' \
    -o -iname '*.ps1' \
    -o -iname '*.bat' \
    -o -iname '*.cmd' \
    -o -iname '*.sql' \
    -o -iname '*.sqlite' \
    -o -iname '*.db' \
    -o -iname '*.zip' \
    -o -iname '*.7z' \
    -o -iname '*.rar' \
    -o -iname '*.tar' \
    -o -iname '*.gz' \
    -o -iname '*.vhd' \
    -o -iname '*.vhdx' \
\) -print \
2>/dev/null \
| sort -u \
> "$OUT/lists/interesting_files.txt"

find "$ROOT" \
    -type d \
    \( \
        -name '.git' \
        -o -name '.svn' \
        -o -name '.hg' \
    \) \
    -print \
    2>/dev/null \
    | sort -u \
    > "$OUT/lists/repos.txt"

############################################
# 3. High-value shortlist
############################################

log "3/12  Building high-value shortlist..."

find "$ROOT" -type f \( \
    -iname 'unattend.xml' \
    -o -iname 'unattended.xml' \
    -o -iname 'sysprep*.xml' \
    -o -iname 'Groups.xml' \
    -o -iname 'Services.xml' \
    -o -iname 'ScheduledTasks.xml' \
    -o -iname 'Registry.xml' \
    -o -iname 'web.config' \
    -o -iname '.env' \
    -o -iname 'appsettings*.json' \
    -o -iname 'PwmConfiguration.xml' \
    -o -iname '*.kdbx' \
    -o -iname 'id_rsa' \
    -o -iname 'id_ed25519' \
    -o -iname 'ntds.dit' \
    -o -iname 'SAM' \
    -o -iname 'SYSTEM' \
    -o -iname '*.pfx' \
    -o -iname '*.p12' \
    -o -iname '*.ppk' \
    -o -iname '*.rdp' \
\) -print \
2>/dev/null \
| sort -u \
> "$OUT/lists/high_value_artifacts.txt"

############################################
# 4. Severity hunting
############################################

log "4/12  Running severity-based content hunt..."

if have rg; then

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$CRITICAL_PATTERN" \
        "$ROOT" \
        > "$OUT/priority/CRITICAL.txt" \
        2>/dev/null || true

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$HIGH_PATTERN" \
        "$ROOT" \
        > "$OUT/priority/HIGH.txt" \
        2>/dev/null || true

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$AD_PATTERN|$DEVOPS_PATTERN|$DB_PATTERN|$WINDOWS_PATTERN" \
        "$ROOT" \
        > "$OUT/priority/MEDIUM.txt" \
        2>/dev/null || true

else

    grep \
        -RniIE \
        "$CRITICAL_PATTERN" \
        "$ROOT" \
        > "$OUT/priority/CRITICAL.txt" \
        2>/dev/null || true

    grep \
        -RniIE \
        "$HIGH_PATTERN" \
        "$ROOT" \
        > "$OUT/priority/HIGH.txt" \
        2>/dev/null || true

    grep \
        -RniIE \
        "$AD_PATTERN|$DEVOPS_PATTERN|$DB_PATTERN|$WINDOWS_PATTERN" \
        "$ROOT" \
        > "$OUT/priority/MEDIUM.txt" \
        2>/dev/null || true

fi

############################################
# 5. Category reports
############################################

log "5/12  Building category reports..."

if have rg; then

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$CRITICAL_PATTERN|$HIGH_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/credentials_secrets.txt" \
        2>/dev/null || true

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$AD_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/ad_privilege_indicators.txt" \
        2>/dev/null || true

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$WINDOWS_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/windows_auth_deployment.txt" \
        2>/dev/null || true

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$DEVOPS_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/devops_cloud.txt" \
        2>/dev/null || true

    rg \
        -n \
        -i \
        -I \
        --hidden \
        -C "$CONTEXT_LINES" \
        -e "$DB_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/database_connections.txt" \
        2>/dev/null || true

else

    grep \
        -RniIE \
        "$CRITICAL_PATTERN|$HIGH_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/credentials_secrets.txt" \
        2>/dev/null || true

    grep \
        -RniIE \
        "$AD_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/ad_privilege_indicators.txt" \
        2>/dev/null || true

    grep \
        -RniIE \
        "$WINDOWS_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/windows_auth_deployment.txt" \
        2>/dev/null || true

    grep \
        -RniIE \
        "$DEVOPS_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/devops_cloud.txt" \
        2>/dev/null || true

    grep \
        -RniIE \
        "$DB_PATTERN" \
        "$ROOT" \
        > "$OUT/hits/database_connections.txt" \
        2>/dev/null || true

fi

############################################
# 6. Identity extraction
############################################

log "6/12  Extracting identities / emails / UPN-like strings..."

: > "$OUT/hits/identities.txt"

if have rg; then

    rg \
        -o \
        -I \
        --hidden \
        -N \
        '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
        "$ROOT" \
        2>/dev/null \
        | sort -fu \
        >> "$OUT/hits/identities.txt" || true

    rg \
        -o \
        -I \
        --hidden \
        -N \
        '(CN|OU|DC)=[^,\r\n]+' \
        "$ROOT" \
        2>/dev/null \
        | sort -fu \
        >> "$OUT/hits/identities.txt" || true

fi

############################################
# 7. Keys / certs / DBs / archives
############################################

log "7/12  Classifying high-value artifacts..."

find "$ROOT" -type f \( \
    -iname '*.pem' \
    -o -iname '*.key' \
    -o -iname '*.crt' \
    -o -iname '*.cer' \
    -o -iname '*.der' \
    -o -iname '*.pfx' \
    -o -iname '*.p12' \
    -o -iname '*.jks' \
    -o -iname '*.keystore' \
    -o -iname 'id_rsa' \
    -o -iname 'id_ed25519' \
\) -print \
2>/dev/null \
| sort -u \
> "$OUT/lists/key_cert_material.txt"

find "$ROOT" -type f \( \
    -iname '*.zip' \
    -o -iname '*.7z' \
    -o -iname '*.rar' \
    -o -iname '*.tar' \
    -o -iname '*.tgz' \
    -o -iname '*.gz' \
    -o -iname '*.bz2' \
    -o -iname '*.xz' \
    -o -iname '*.bak' \
    -o -iname '*.old' \
    -o -iname '*.orig' \
    -o -iname '*backup*' \
\) -print \
2>/dev/null \
| sort -u \
> "$OUT/lists/archives_backups.txt"

find "$ROOT" -type f \( \
    -iname '*.kdbx' \
    -o -iname '*.sqlite' \
    -o -iname '*.sqlite3' \
    -o -iname '*.db' \
    -o -iname '*.mdb' \
    -o -iname '*.accdb' \
\) -print \
2>/dev/null \
| sort -u \
> "$OUT/lists/databases.txt"

############################################
# 8. Custom keyword search
############################################

log "8/12  Running custom keyword searches..."

: > "$OUT/hits/custom_keywords.txt"
: > "$OUT/meta/custom_keywords.txt"

if [[ ${#CUSTOM_KEYWORDS[@]} -gt 0 ]]; then

    idx=0

    for kw in "${CUSTOM_KEYWORDS[@]}"; do

        ((idx+=1))

        printf '%s\n' \
            "$kw" \
            >> "$OUT/meta/custom_keywords.txt"

        REGEX="$(keyword_to_regex "$kw")"

        {
            echo "================================================================"
            printf 'KEYWORD %d : %s\n' "$idx" "$kw"
            printf 'REGEX      : %s\n' "$REGEX"

            if [[ "$CUSTOM_IGNORE_CASE" -eq 1 ]]; then
                echo "MODE       : CASE-INSENSITIVE / * WILDCARD"
            else
                echo "MODE       : CASE-SENSITIVE / * WILDCARD"
            fi

            echo "================================================================"
            echo "--- CONTENT MATCHES ---"

        } >> "$OUT/hits/custom_keywords.txt"

        if have rg; then

            RG_ARGS=(
                -n
                -I
                --hidden
                -C "$CONTEXT_LINES"
            )

            if [[ "$CUSTOM_IGNORE_CASE" -eq 1 ]]; then
                RG_ARGS+=(-i)
            fi

            rg \
                "${RG_ARGS[@]}" \
                -e "$REGEX" \
                "$ROOT" \
                >> "$OUT/hits/custom_keywords.txt" \
                2>/dev/null || true

        else

            GREP_ARGS=(
                -RnE
            )

            if [[ "$CUSTOM_IGNORE_CASE" -eq 1 ]]; then
                GREP_ARGS+=(-i)
            fi

            grep \
                "${GREP_ARGS[@]}" \
                "$REGEX" \
                "$ROOT" \
                >> "$OUT/hits/custom_keywords.txt" \
                2>/dev/null || true

        fi

        {
            echo
            echo "--- PATH / FILENAME MATCHES ---"
        } >> "$OUT/hits/custom_keywords.txt"

        find "$ROOT" \
            -print0 \
            2>/dev/null \
        | while IFS= read -r -d '' entry; do

            relative="${entry#$ROOT/}"

            if [[ "$CUSTOM_IGNORE_CASE" -eq 1 ]]; then

                shopt -s nocasematch

                if [[ "$relative" == $kw ]]; then
                    printf '%s\n' "$entry"
                fi

                shopt -u nocasematch

            else

                if [[ "$relative" == $kw ]]; then
                    printf '%s\n' "$entry"
                fi

            fi

        done >> "$OUT/hits/custom_keywords.txt"

        echo >> "$OUT/hits/custom_keywords.txt"

    done
fi

############################################
# 9. Binary strings pass
############################################

log "9/12  Running bounded strings pass..."

: > "$OUT/hits/binary_strings_hits.txt"

while IFS= read -r f; do

    [[ -f "$f" ]] || continue

    bytes="$(
        stat \
            -c '%s' \
            "$f" \
            2>/dev/null \
        || echo 0
    )"

    mb=$(( bytes / 1024 / 1024 ))

    (( mb <= MAX_BIN_MB )) || continue

    if strings \
        -a \
        -n 6 \
        "$f" \
        2>/dev/null \
        | grep \
            -Eai \
            "$CRITICAL_PATTERN|$HIGH_PATTERN|$AD_PATTERN|$DEVOPS_PATTERN|$DB_PATTERN" \
            > "/tmp/smbgrab.$$" \
            2>/dev/null
    then

        if [[ -s "/tmp/smbgrab.$$" ]]; then

            {
                echo "===== $f ====="
                head -n 250 "/tmp/smbgrab.$$"
                echo
            } >> "$OUT/hits/binary_strings_hits.txt"

        fi
    fi

done < "$OUT/lists/interesting_files.txt"

rm -f "/tmp/smbgrab.$$" 2>/dev/null || true

############################################
# 10. Optional archive listing
############################################

log "10/12 Archive inspection..."

: > "$OUT/optional/archive_contents.txt"

if [[ "$CHECK_ARCHIVES" -eq 1 ]]; then

    while IFS= read -r f; do

        [[ -f "$f" ]] || continue

        {
            echo "===== $f ====="

            case "${f,,}" in

                *.zip)

                    if have unzip; then
                        unzip -l "$f" 2>/dev/null || true
                    else
                        echo "[!] unzip not installed"
                    fi
                    ;;

                *.7z|*.rar)

                    if have 7z; then
                        7z l "$f" 2>/dev/null || true
                    else
                        echo "[!] 7z not installed"
                    fi
                    ;;

                *.tar|*.tgz|*.tar.gz|*.tar.bz2|*.tar.xz)

                    if have tar; then
                        tar -tf "$f" 2>/dev/null || true
                    else
                        echo "[!] tar not installed"
                    fi
                    ;;

                *)

                    echo "[i] Listing unsupported for this archive type."
                    ;;

            esac

            echo

        } >> "$OUT/optional/archive_contents.txt"

    done < "$OUT/lists/archives_backups.txt"

else

    echo "Archive inspection disabled. Use -a / --archives." \
        > "$OUT/optional/archive_contents.txt"

fi

############################################
# 11. Optional Git history
############################################

log "11/12 Git history inspection..."

: > "$OUT/optional/git_history.txt"

if [[ "$CHECK_GIT" -eq 1 ]]; then

    while IFS= read -r gitdir; do

        [[ -d "$gitdir" ]] || continue

        repo="$(dirname "$gitdir")"

        {
            echo "================================================================"
            echo "REPOSITORY: $repo"
            echo "================================================================"

            git \
                -C "$repo" \
                status \
                --short \
                2>/dev/null || true

            echo
            echo "--- RECENT COMMITS ---"

            git \
                -C "$repo" \
                log \
                --all \
                --decorate \
                --oneline \
                -n 50 \
                2>/dev/null || true

            echo
            echo "--- SECRET-RELEVANT HISTORY ---"

            git \
                -C "$repo" \
                log \
                --all \
                -p \
                --no-color \
                2>/dev/null \
                | grep \
                    -Eai \
                    -C "$CONTEXT_LINES" \
                    "$CRITICAL_PATTERN|$HIGH_PATTERN|$DEVOPS_PATTERN|$DB_PATTERN" \
                | head -n 2000 || true

            echo

        } >> "$OUT/optional/git_history.txt"

    done < "$OUT/lists/repos.txt"

else

    echo "Git history inspection disabled. Use -g / --git-history." \
        > "$OUT/optional/git_history.txt"

fi

############################################
# 12. Summary + Markdown report
############################################

log "12/12 Building summary..."

CRIT_COUNT="$(count_lines "$OUT/priority/CRITICAL.txt")"
HIGH_COUNT="$(count_lines "$OUT/priority/HIGH.txt")"
MED_COUNT="$(count_lines "$OUT/priority/MEDIUM.txt")"

{
    echo "SMB DUMP GRABBER SUMMARY"
    echo "========================"

    echo "Version : $VERSION"
    echo "Share   : $SHARE_NAME"
    echo "Root    : $ROOT"
    echo

    printf "Files total:              "
    cat "$OUT/meta/file_count.txt"

    printf "Interesting filenames:    "
    count_lines "$OUT/lists/interesting_files.txt"

    printf "High-value artifacts:     "
    count_lines "$OUT/lists/high_value_artifacts.txt"

    printf "Key/cert material:        "
    count_lines "$OUT/lists/key_cert_material.txt"

    printf "Databases:                "
    count_lines "$OUT/lists/databases.txt"

    printf "Archives/backups:         "
    count_lines "$OUT/lists/archives_backups.txt"

    echo
    echo "Priority hit lines:"
    echo "  CRITICAL : $CRIT_COUNT"
    echo "  HIGH     : $HIGH_COUNT"
    echo "  MEDIUM   : $MED_COUNT"

    echo
    echo "Review first:"
    echo "  $OUT/priority/CRITICAL.txt"
    echo "  $OUT/priority/HIGH.txt"
    echo "  $OUT/lists/high_value_artifacts.txt"
    echo "  $OUT/hits/custom_keywords.txt"
    echo "  $OUT/hits/credentials_secrets.txt"
    echo "  $OUT/hits/ad_privilege_indicators.txt"
    echo "  $OUT/optional/git_history.txt"
    echo "  $OUT/optional/archive_contents.txt"

} | tee "$OUT/SUMMARY.txt"

{
    echo "# SMB Dump Grabber Report"
    echo

    echo "- **Version:** $VERSION"
    echo "- **Share:** \`$SHARE_NAME\`"
    echo "- **Root:** \`$ROOT\`"
    echo "- **Generated:** $(date -Is)"

    echo
    echo "## Priority overview"
    echo

    echo "| Priority | Hit lines |"
    echo "|---|---:|"
    echo "| CRITICAL | $CRIT_COUNT |"
    echo "| HIGH | $HIGH_COUNT |"
    echo "| MEDIUM | $MED_COUNT |"

    echo
    echo "## Artifact overview"
    echo

    echo "| Category | Count |"
    echo "|---|---:|"

    echo "| Total files | $(cat "$OUT/meta/file_count.txt") |"
    echo "| Interesting files | $(count_lines "$OUT/lists/interesting_files.txt") |"
    echo "| High-value artifacts | $(count_lines "$OUT/lists/high_value_artifacts.txt") |"
    echo "| Keys / certificates | $(count_lines "$OUT/lists/key_cert_material.txt") |"
    echo "| Databases | $(count_lines "$OUT/lists/databases.txt") |"
    echo "| Archives / backups | $(count_lines "$OUT/lists/archives_backups.txt") |"

    echo
    echo "## Recommended review order"
    echo

    echo "1. \`priority/CRITICAL.txt\`"
    echo "2. \`priority/HIGH.txt\`"
    echo "3. \`lists/high_value_artifacts.txt\`"
    echo "4. \`hits/custom_keywords.txt\`"
    echo "5. \`hits/credentials_secrets.txt\`"
    echo "6. \`hits/ad_privilege_indicators.txt\`"
    echo "7. \`optional/git_history.txt\`"
    echo "8. \`optional/archive_contents.txt\`"

} > "$OUT/REPORT.md"

echo
good "Finished."
good "Summary : $OUT/SUMMARY.txt"
good "Report  : $OUT/REPORT.md"
good "Results : $OUT"
