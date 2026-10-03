# SMB Dump Grabber

`SMB Dump Grabber` is a Bash-based local analysis tool for reviewing previously dumped SMB shares.

It helps identify potentially interesting files, credentials, secrets, Active Directory indicators, configuration files, certificates, databases, backups, and other high-value artifacts.

## Features

- File and directory inventory
- Interesting filename detection
- Credential and secret hunting
- Active Directory privilege indicators
- Windows authentication and deployment artifacts
- DevOps / Cloud configuration detection
- Database connection strings
- Email and identity extraction
- Key and certificate discovery
- Archive and backup detection
- Optional archive inspection
- Optional Git history analysis
- Custom keyword search with wildcard support
- Severity-based output: `CRITICAL`, `HIGH`, and `MEDIUM`
- Markdown and text summary reports

## Usage

```bash
chmod +x smbgrabber.sh

./smbgrabber.sh -s <share_dump>
```

Example:

```bash
./smbgrabber.sh -s ./Department_Shares
```

## Interactive Keyword Search

When the program starts, you can optionally define custom keywords before the scan begins.

```text
╔══════════════════════════════════════════════════════════════╗
║                 CUSTOM KEYWORD SEARCH                        ║
╠══════════════════════════════════════════════════════════════╣
║ Search mode: CASE-SENSITIVE                                  ║
║ Wildcard: '*' = any number of characters                     ║
║ Other special characters are searched literally.             ║
║ Examples: svc_*   *password*   C:\Users\*\Desktop\*          ║
║                                                              ║
║ Press x and ENTER to start the grabber.                      ║
╚══════════════════════════════════════════════════════════════╝

keyword>
```

You can enter multiple keywords:

```text
keyword> svc_*
[+] Added keyword: svc_*

keyword> *password*
[+] Added keyword: *password*

keyword> C:\Users\*\Desktop\*
[+] Added keyword: C:\Users\*\Desktop\*

keyword> x

[+] Starting SMB Grabber...
```

The `*` character works as a wildcard.

By default, custom keyword searches are case-sensitive.

Use `-i` to make custom keyword searches case-insensitive:

```bash
./smbgrabber.sh -s ./Department_Shares -i
```

You can also supply keywords directly from the command line:

```bash
./smbgrabber.sh -s ./Department_Shares -k '*password*'
```

Multiple keywords can be supplied:

```bash
./smbgrabber.sh \
  -s ./Department_Shares \
  -k 'svc_*' \
  -k '*password*' \
  -k 'C:\Users\*\Desktop\*'
```

## Optional Archive and Git Analysis

Enable archive inspection:

```bash
./smbgrabber.sh -s ./Department_Shares -a
```

Enable Git history inspection:

```bash
./smbgrabber.sh -s ./Department_Shares -g
```

Enable both:

```bash
./smbgrabber.sh -s ./Department_Shares -a -g
```

## Output

Results are written into a timestamped directory:

```text
smbgrab_Department_Shares_YYYYMMDD_HHMMSS/
├── hits/
├── lists/
├── meta/
├── optional/
├── priority/
├── REPORT.md
└── SUMMARY.txt
```

Start your review with:

```text
priority/CRITICAL.txt
priority/HIGH.txt
lists/high_value_artifacts.txt
hits/custom_keywords.txt
hits/credentials_secrets.txt
hits/ad_privilege_indicators.txt
```

## Requirements

Recommended tools:

```text
bash
find
grep
strings
ripgrep
git
unzip
7z
tar
```

Most features work with standard Linux utilities. Optional functionality depends on the corresponding tools being installed.

## Disclaimer

This tool only analyzes files already present in the supplied local directory.

Use it only on systems, data, and environments you are authorized to assess.
