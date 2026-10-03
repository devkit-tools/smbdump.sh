param(
    [Parameter(Mandatory = $true)]
    [Alias("s")]
    [string]$Share,

    [Alias("o")]
    [string]$Output,

    [Alias("k")]
    [string[]]$Keyword = @(),

    [Alias("i")]
    [switch]$IgnoreCaseCustom,

    [Alias("m")]
    [int]$MaxBinMB = 50,

    [Alias("c")]
    [int]$Context = 2,

    [Alias("a")]
    [switch]$Archives,

    [Alias("g")]
    [switch]$GitHistory,

    [Alias("n")]
    [switch]$NoPrompt,

    [Alias("V")]
    [switch]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ToolVersion = "3.0-win-ps"

function Write-Banner {
@"
   _____ __  _______   _______  ___    ____  ____________
  / ___//  |/  / __ ) / ____// / / |  / /  |/  / ____/ _ \
  \__ \/ /|_/ / __  |/ / _/ /_//| | / / /|_/ / __/ / /_/ /
 ___/ / /  / / /_/ / /_/ /    / | |/ / /  / / /___/ _, _/
/____/_/  /_/_____/\____/____/  |___/_/  /_/_____/_/ |_|

                 SMB DUMP
        Secrets • Accounts • Configs • Privilege Hunt

                         v$ToolVersion
"@ | Write-Host
}

function Write-Info([string]$Message) { Write-Host "[*] $Message" }
function Write-Good([string]$Message) { Write-Host "[+] $Message" }
function Get-LineCount([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    }
    return 0
}
function Convert-WildcardToRegex([string]$InputText) {
    ([regex]::Escape($InputText) -replace '\\\*', '.*')
}
function Add-TextResult([string]$Path,[string]$Text) {
    Add-Content -LiteralPath $Path -Value $Text -Encoding UTF8
}
function Search-FileContent {
    param([string]$FilePath,[string]$Pattern,[bool]$CaseSensitive = $false)
    try {
        $p = @{LiteralPath=$FilePath;Pattern=$Pattern;AllMatches=$true;ErrorAction='SilentlyContinue'}
        if ($CaseSensitive) { $p.CaseSensitive = $true }
        Select-String @p
    } catch { @() }
}

Write-Banner
if ($Version) { Write-Host "SMB DUMP GRABBER v$ToolVersion"; exit 0 }
if (-not (Test-Path -LiteralPath $Share -PathType Container)) { throw "Share dump directory not found: $Share" }

$Root = (Resolve-Path -LiteralPath $Share).Path
$ShareName = Split-Path -Leaf $Root
$SafeShare = ($ShareName -replace '[^A-Za-z0-9._-]', '_')
if (-not $Output) { $Output = "smbgrab_${SafeShare}_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
$Out = [System.IO.Path]::GetFullPath($Output)
@($Out,"$Out\hits","$Out\lists","$Out\meta","$Out\priority","$Out\optional") | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }

$CustomKeywords = [System.Collections.Generic.List[string]]::new()
foreach ($k in $Keyword) { if (-not [string]::IsNullOrWhiteSpace($k)) { [void]$CustomKeywords.Add($k) } }

if (-not $NoPrompt) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗"
    Write-Host "║                 CUSTOM KEYWORD SEARCH                       ║"
    Write-Host "╠══════════════════════════════════════════════════════════════╣"
    if ($IgnoreCaseCustom) { Write-Host "║ Search mode: CASE-INSENSITIVE                               ║" }
    else { Write-Host "║ Search mode: CASE-SENSITIVE                                 ║" }
    Write-Host "║ Wildcard: '*' = any number of characters                   ║"
    Write-Host "║ Examples: svc_*   *password*   C:\Users\*\Desktop\*        ║"
    Write-Host "║                                                              ║"
    Write-Host "║ Press x and ENTER to start the grabber.                     ║"
    Write-Host "╚══════════════════════════════════════════════════════════════╝"
    Write-Host ""
    while ($true) {
        $UserKeyword = Read-Host "keyword"
        if ($UserKeyword -eq 'x') { Write-Host ""; Write-Good "Starting SMB Grabber..."; break }
        if ([string]::IsNullOrWhiteSpace($UserKeyword)) { continue }
        [void]$CustomKeywords.Add($UserKeyword)
        Write-Good "Added keyword: $UserKeyword"
    }
}

Write-Host ""
Write-Info "Share     : $ShareName"
Write-Info "Root      : $Root"
Write-Info "Output    : $Out"
Write-Info "Context   : $Context line(s)"
Write-Info "Strings   : <= $MaxBinMB MB"
Write-Info ("Archives  : " + $(if ($Archives) { 'enabled' } else { 'disabled' }))
Write-Info ("Git       : " + $(if ($GitHistory) { 'enabled' } else { 'disabled' }))

$CriticalPattern = 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|cpassword|DefaultPassword|AutoAdminLogon|ANSIBLE_VAULT|vault_password|client_secret|secret_access_key|aws_secret_access_key|AccountKey=|SharedAccessSignature|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]'
$HighPattern = 'credential|passphrase|api[_-]?key|access[_-]?key|secret[_-]?key|token|bearer|authorization:|connectionstring|connection string|bind_password|ldap_password|ansible_password|become_pass|private[_-]?key|PSCredential|ConvertTo-SecureString|User ID=|UID=|PWD=|Password='
$AdPattern = 'sAMAccountName|userPrincipalName|memberOf|servicePrincipalName|msDS-|distinguishedName|Domain Admins|Enterprise Admins|Administrators|Remote Management Users|Remote Desktop Users|Backup Operators|Account Operators|Server Operators|DnsAdmins|GenericAll|GenericWrite|WriteDACL|WriteOwner|AllowedToActOnBehalfOfOtherIdentity|DONT_REQ_PREAUTH|TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION'
$DevOpsPattern = 'ansible_user|ansible_password|vault_password_file|VAULT_PASSWORD|remote_user|become_pass|docker login|registry_password|KUBECONFIG|client-certificate-data|client-key-data|AWS_|AZURE_|ARM_|GOOGLE_APPLICATION_CREDENTIALS|terraform|tenant|subscription|client_secret|servicePrincipal'
$DbPattern = 'jdbc:(mysql|postgresql|sqlserver|oracle)|mongodb(\+srv)?://|redis://|postgres(ql)?://|mysql://|Server=.*Database=.*(User|UID)|Data Source=.*Initial Catalog|Integrated Security|Trusted_Connection|User ID=|UID=|Password=|PWD='
$WindowsPattern = 'cpassword|AutoAdminLogon|DefaultPassword|DefaultUserName|DefaultDomainName|RunAs|runas /user|net use|cmdkey|New-PSDrive|ConvertTo-SecureString|PSCredential|ScheduledTask|schtasks|WinRM|WSMan|CredSSP|NTLM|Kerberos'

$AllFiles = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue)
$AllDirs  = @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force -ErrorAction SilentlyContinue)

Write-Info "1/12  Building inventory..."
$AllFiles | Sort-Object FullName | ForEach-Object { "{0}`t{1}`t{2}" -f $_.FullName,$_.Length,$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } | Set-Content "$Out\meta\files.tsv" -Encoding UTF8
$AllDirs | Sort-Object FullName | Select-Object -ExpandProperty FullName | Set-Content "$Out\meta\dirs.txt" -Encoding UTF8
$AllFiles.Count | Set-Content "$Out\meta\file_count.txt" -Encoding UTF8

Write-Info "2/12  Hunting interesting filenames..."
$interestingNameRegex = '(?i)(password|passwd|secret|credential|creds|token|vault|backup)|\.(bak|old|orig|save|env|kdbx|pfx|p12|pem|key|rdp|ovpn|ppk|ps1|bat|cmd|sql|sqlite|db|zip|7z|rar|tar|gz|vhd|vhdx)$|^(web\.config|appsettings.*\.json|application.*\.(properties|yml|yaml)|settings.*\.xml|config.*\.(xml|ini)|ansible\.cfg|inventory.*|unattend\.xml|sysprep.*\.xml|groups\.xml|services\.xml|scheduledtasks\.xml|registry\.xml|ntds\.dit|id_rsa|id_ed25519)$'
$AllFiles | Where-Object { $_.Name -match $interestingNameRegex } | Select-Object -ExpandProperty FullName | Sort-Object -Unique | Set-Content "$Out\lists\interesting_files.txt" -Encoding UTF8
Get-ChildItem -LiteralPath $Root -Directory -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('.git','.svn','.hg') } | Select-Object -ExpandProperty FullName | Sort-Object -Unique | Set-Content "$Out\lists\repos.txt" -Encoding UTF8

Write-Info "3/12  Building high-value shortlist..."
$highValueRegex = '(?i)^(unattend\.xml|unattended\.xml|sysprep.*\.xml|groups\.xml|services\.xml|scheduledtasks\.xml|registry\.xml|web\.config|\.env|appsettings.*\.json|pwmconfiguration\.xml|id_rsa|id_ed25519|ntds\.dit|sam|system)$|\.(kdbx|pfx|p12|ppk|rdp)$'
$AllFiles | Where-Object { $_.Name -match $highValueRegex } | Select-Object -ExpandProperty FullName | Sort-Object -Unique | Set-Content "$Out\lists\high_value_artifacts.txt" -Encoding UTF8

Write-Info "4/12  Running severity-based content hunt..."
$CriticalFile="$Out\priority\CRITICAL.txt"; $HighFile="$Out\priority\HIGH.txt"; $MediumFile="$Out\priority\MEDIUM.txt"
'' | Set-Content $CriticalFile; '' | Set-Content $HighFile; '' | Set-Content $MediumFile
foreach ($file in $AllFiles) {
    foreach ($m in (Search-FileContent $file.FullName $CriticalPattern)) { Add-TextResult $CriticalFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    foreach ($m in (Search-FileContent $file.FullName $HighPattern)) { Add-TextResult $HighFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    foreach ($m in (Search-FileContent $file.FullName "$AdPattern|$DevOpsPattern|$DbPattern|$WindowsPattern")) { Add-TextResult $MediumFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
}

Write-Info "5/12  Building category reports..."
$CredFile="$Out\hits\credentials_secrets.txt"; $AdFile="$Out\hits\ad_privilege_indicators.txt"; $WinFile="$Out\hits\windows_auth_deployment.txt"; $DevFile="$Out\hits\devops_cloud.txt"; $DbFile="$Out\hits\database_connections.txt"
foreach ($p in @($CredFile,$AdFile,$WinFile,$DevFile,$DbFile)) { '' | Set-Content $p }
foreach ($file in $AllFiles) {
    foreach ($m in (Search-FileContent $file.FullName "$CriticalPattern|$HighPattern")) { Add-TextResult $CredFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    foreach ($m in (Search-FileContent $file.FullName $AdPattern)) { Add-TextResult $AdFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    foreach ($m in (Search-FileContent $file.FullName $WindowsPattern)) { Add-TextResult $WinFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    foreach ($m in (Search-FileContent $file.FullName $DevOpsPattern)) { Add-TextResult $DevFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    foreach ($m in (Search-FileContent $file.FullName $DbPattern)) { Add-TextResult $DbFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
}

Write-Info "6/12  Extracting identities / emails / UPN-like strings..."
$IdentitySet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($file in $AllFiles) {
    try { $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop } catch { continue }
    foreach ($m in [regex]::Matches($content,'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) { [void]$IdentitySet.Add($m.Value) }
    foreach ($m in [regex]::Matches($content,'(CN|OU|DC)=[^,\r\n]+')) { [void]$IdentitySet.Add($m.Value) }
}
$IdentitySet | Sort-Object | Set-Content "$Out\hits\identities.txt" -Encoding UTF8

Write-Info "7/12  Classifying high-value artifacts..."
$AllFiles | Where-Object { $_.Extension -match '(?i)^\.(pem|key|crt|cer|der|pfx|p12|jks|keystore)$' -or $_.Name -in @('id_rsa','id_ed25519') } | Select-Object -ExpandProperty FullName | Sort-Object -Unique | Set-Content "$Out\lists\key_cert_material.txt" -Encoding UTF8
$AllFiles | Where-Object { $_.Extension -match '(?i)^\.(zip|7z|rar|tar|tgz|gz|bz2|xz|bak|old|orig)$' -or $_.Name -match '(?i)backup' } | Select-Object -ExpandProperty FullName | Sort-Object -Unique | Set-Content "$Out\lists\archives_backups.txt" -Encoding UTF8
$AllFiles | Where-Object { $_.Extension -match '(?i)^\.(kdbx|sqlite|sqlite3|db|mdb|accdb)$' } | Select-Object -ExpandProperty FullName | Sort-Object -Unique | Set-Content "$Out\lists\databases.txt" -Encoding UTF8

Write-Info "8/12  Running custom keyword searches..."
$CustomFile="$Out\hits\custom_keywords.txt"; '' | Set-Content $CustomFile; $CustomKeywords | Set-Content "$Out\meta\custom_keywords.txt"
$idx=0
foreach ($kw in $CustomKeywords) {
    $idx++; $regex=Convert-WildcardToRegex $kw
    Add-TextResult $CustomFile '================================================================'
    Add-TextResult $CustomFile "KEYWORD $idx : $kw"
    Add-TextResult $CustomFile "REGEX      : $regex"
    Add-TextResult $CustomFile ('MODE       : ' + $(if ($IgnoreCaseCustom) {'CASE-INSENSITIVE / * WILDCARD'} else {'CASE-SENSITIVE / * WILDCARD'}))
    Add-TextResult $CustomFile '================================================================'
    Add-TextResult $CustomFile '--- CONTENT MATCHES ---'
    foreach ($file in $AllFiles) {
        foreach ($m in (Search-FileContent -FilePath $file.FullName -Pattern $regex -CaseSensitive:(-not $IgnoreCaseCustom))) { Add-TextResult $CustomFile ("{0}:{1}:{2}" -f $file.FullName,$m.LineNumber,$m.Line.Trim()) }
    }
    Add-TextResult $CustomFile ''; Add-TextResult $CustomFile '--- PATH / FILENAME MATCHES ---'
    foreach ($entry in @($AllFiles)+@($AllDirs)) {
        $relative=$entry.FullName.Substring($Root.Length).TrimStart('\')
        if ($IgnoreCaseCustom) { if ($relative -match "(?i)^$regex$") { Add-TextResult $CustomFile $entry.FullName } }
        elseif ($relative -cmatch "^$regex$") { Add-TextResult $CustomFile $entry.FullName }
    }
    Add-TextResult $CustomFile ''
}

Write-Info "9/12  Running bounded strings-like pass..."
$BinaryFile="$Out\hits\binary_strings_hits.txt"; '' | Set-Content $BinaryFile
$InterestingPaths = @(Get-Content "$Out\lists\interesting_files.txt" -ErrorAction SilentlyContinue)
foreach ($path in $InterestingPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $item=Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (($item.Length/1MB) -gt $MaxBinMB) { continue }
    try {
        $bytes=[IO.File]::ReadAllBytes($path); $text=[Text.Encoding]::ASCII.GetString($bytes)
        $matches=[regex]::Matches($text,"$CriticalPattern|$HighPattern|$AdPattern|$DevOpsPattern|$DbPattern",'IgnoreCase')
        if ($matches.Count -gt 0) { Add-TextResult $BinaryFile "===== $path ====="; $matches | Select-Object -First 250 | ForEach-Object { Add-TextResult $BinaryFile $_.Value }; Add-TextResult $BinaryFile '' }
    } catch {}
}

Write-Info "10/12 Archive inspection..."
$ArchiveFile="$Out\optional\archive_contents.txt"; '' | Set-Content $ArchiveFile
if ($Archives) {
    foreach ($path in @(Get-Content "$Out\lists\archives_backups.txt" -ErrorAction SilentlyContinue)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        Add-TextResult $ArchiveFile "===== $path ====="
        $ext=[IO.Path]::GetExtension($path).ToLowerInvariant()
        try {
            if ($ext -eq '.zip') {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                $zip=[IO.Compression.ZipFile]::OpenRead($path)
                foreach ($entry in $zip.Entries) { Add-TextResult $ArchiveFile $entry.FullName }
                $zip.Dispose()
            } elseif ($ext -in @('.7z','.rar')) {
                $seven=Get-Command 7z.exe -ErrorAction SilentlyContinue
                if ($seven) { & $seven.Source l $path 2>$null | Add-Content $ArchiveFile }
                else { Add-TextResult $ArchiveFile '[!] 7z.exe not installed' }
            } else { Add-TextResult $ArchiveFile '[i] Listing unsupported for this archive type.' }
        } catch { Add-TextResult $ArchiveFile "[!] Failed to inspect archive: $($_.Exception.Message)" }
        Add-TextResult $ArchiveFile ''
    }
} else { 'Archive inspection disabled. Use -Archives.' | Set-Content $ArchiveFile }

Write-Info "11/12 Git history inspection..."
$GitFile="$Out\optional\git_history.txt"; '' | Set-Content $GitFile
if ($GitHistory) {
    $git=Get-Command git.exe -ErrorAction SilentlyContinue
    if (-not $git) { '[!] git.exe not installed' | Set-Content $GitFile }
    else {
        foreach ($gitDir in (Get-ChildItem -LiteralPath $Root -Directory -Force -Recurse -ErrorAction SilentlyContinue | Where-Object Name -eq '.git')) {
            $repo=$gitDir.Parent.FullName
            Add-TextResult $GitFile '================================================================'; Add-TextResult $GitFile "REPOSITORY: $repo"; Add-TextResult $GitFile '================================================================'
            & $git.Source -C $repo status --short 2>$null | Add-Content $GitFile
            Add-TextResult $GitFile ''; Add-TextResult $GitFile '--- RECENT COMMITS ---'
            & $git.Source -C $repo log --all --decorate --oneline -n 50 2>$null | Add-Content $GitFile
            Add-TextResult $GitFile ''; Add-TextResult $GitFile '--- SECRET-RELEVANT HISTORY ---'
            (& $git.Source -C $repo log --all -p --no-color 2>$null | Select-String -Pattern "$CriticalPattern|$HighPattern|$DevOpsPattern|$DbPattern" | Select-Object -First 2000).Line | Add-Content $GitFile
            Add-TextResult $GitFile ''
        }
    }
} else { 'Git history inspection disabled. Use -GitHistory.' | Set-Content $GitFile }

Write-Info "12/12 Building summary..."
$CritCount=Get-LineCount $CriticalFile; $HighCount=Get-LineCount $HighFile; $MedCount=Get-LineCount $MediumFile
$SummaryFile="$Out\SUMMARY.txt"
@"
SMB DUMP GRABBER SUMMARY
========================
Version : $ToolVersion
Share   : $ShareName
Root    : $Root

Files total:              $($AllFiles.Count)
Interesting filenames:    $(Get-LineCount "$Out\lists\interesting_files.txt")
High-value artifacts:     $(Get-LineCount "$Out\lists\high_value_artifacts.txt")
Key/cert material:        $(Get-LineCount "$Out\lists\key_cert_material.txt")
Databases:                $(Get-LineCount "$Out\lists\databases.txt")
Archives/backups:         $(Get-LineCount "$Out\lists\archives_backups.txt")

Priority hit lines:
  CRITICAL : $CritCount
  HIGH     : $HighCount
  MEDIUM   : $MedCount

Review first:
  $CriticalFile
  $HighFile
  $Out\lists\high_value_artifacts.txt
  $CustomFile
  $CredFile
  $AdFile
  $GitFile
  $ArchiveFile
"@ | Set-Content $SummaryFile -Encoding UTF8

$ReportFile="$Out\REPORT.md"
@"
# SMB Dump Grabber Report

- **Version:** $ToolVersion
- **Share:** ``$ShareName``
- **Root:** ``$Root``
- **Generated:** $(Get-Date -Format 'o')

## Priority overview

| Priority | Hit lines |
|---|---:|
| CRITICAL | $CritCount |
| HIGH | $HighCount |
| MEDIUM | $MedCount |

## Artifact overview

| Category | Count |
|---|---:|
| Total files | $($AllFiles.Count) |
| Interesting files | $(Get-LineCount "$Out\lists\interesting_files.txt") |
| High-value artifacts | $(Get-LineCount "$Out\lists\high_value_artifacts.txt") |
| Keys / certificates | $(Get-LineCount "$Out\lists\key_cert_material.txt") |
| Databases | $(Get-LineCount "$Out\lists\databases.txt") |
| Archives / backups | $(Get-LineCount "$Out\lists\archives_backups.txt") |

## Recommended review order

1. ``priority/CRITICAL.txt``
2. ``priority/HIGH.txt``
3. ``lists/high_value_artifacts.txt``
4. ``hits/custom_keywords.txt``
5. ``hits/credentials_secrets.txt``
6. ``hits/ad_privilege_indicators.txt``
7. ``optional/git_history.txt``
8. ``optional/archive_contents.txt``
"@ | Set-Content $ReportFile -Encoding UTF8

Write-Host ""
Write-Good "Finished."
Write-Good "Summary : $SummaryFile"
Write-Good "Report  : $ReportFile"
Write-Good "Results : $Out"
