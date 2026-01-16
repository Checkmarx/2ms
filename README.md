# 2ms (Too Many Secrets)

[![Latest Release](https://img.shields.io/github/v/release/checkmarx/2ms)](https://github.com/checkmarx/2ms/releases)
[![Homebrew](https://img.shields.io/badge/homebrew-2ms-blue?logo=homebrew)](https://formulae.brew.sh/formula/2ms)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Trivy](https://github.com/Checkmarx/2ms/actions/workflows/trivy-vulnerability-scan.yaml/badge.svg)](https://github.com/Checkmarx/2ms/actions/workflows/trivy-vulnerability-scan.yaml)

![2ms Mascot](https://github.com/Checkmarx/2ms/assets/1287098/3a543045-9c6a-4a35-9bf8-f41919e7b03e)

> Modern secrets discovery CLI for code, content, and collaboration platforms.

2ms is an open-source CLI from Checkmarx that helps teams surface credentials, API keys, tokens, and other sensitive data before it leaks. It builds on the gitleaks detection engine, adds Checkmarx expertise, CVSS-based scoring, and optional secret validation so you can triage the riskiest findings first.

## Table of Contents
- [Quick Start](#quick-start)
- [Highlights](#highlights)
- [Installation](#installation)
  - [Homebrew (macOS/Linux)](#homebrew-macoslinux)
  - [Prebuilt Binaries](#prebuilt-binaries)
  - [Build from Source](#build-from-source)
  - [Docker](#docker)
- [Scan Targets](#scan-targets)
  - [Local File System](#local-file-system)
  - [Git Repositories](#git-repositories)
  - [Confluence Cloud](#confluence-cloud)
  - [Slack](#slack)
  - [Discord](#discord)
  - [Paligo](#paligo)
- [Configuration & Tuning](#configuration--tuning)
  - [Global Flags](#global-flags)
  - [Configuration Files & Environment Variables](#configuration-files--environment-variables)
  - [Rules, Validation, and Custom Detection](#rules-validation-and-custom-detection)
- [Reports & Outputs](#reports--outputs)
- [CI/CD & Automation](#cicd--automation)
- [Contributing](#contributing)
- [Community](#community)

## Quick Start

Install, scan your local workspace, and review the findings in seconds:

```bash
brew install 2ms
2ms filesystem --path .
```

Scan recent Git history instead:

```bash
2ms git . --depth 50
```

`2ms` prints a YAML summary by default and returns a non-zero exit code when secrets are detected.

## Highlights

- Unified scanning for local directories, Git history, Slack, Discord, Confluence Cloud, and Paligo — each exposed as a dedicated subcommand.
- Hundreds of tuned detection rules curated by Checkmarx on top of gitleaks, enriched with CVSS-based scoring in every finding.
- Optional live secret validation (`--validate`) to confirm whether discovered credentials are still active.
- Flexible filtering and noise reduction: `--rule`, `--ignore-rule`, `--add-special-rule`, `--ignore-result`, `--regex`, `--allowed-values`, `--max-target-megabytes`, `--max-findings`, `--max-rule-matches-per-fragment`, and `--max-secret-size`.
- Rich reporting for developers and pipelines with JSON, YAML, and SARIF outputs, multiple `--report-path` destinations, and CI-aware exit handling via `--ignore-on-exit`.
- Automation ready: configuration files, `2MS_*` environment variables, Docker images, and GitHub Actions templates.
- Extensible plugin architecture — contributions for new data sources are welcome.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install 2ms
```

Upgrade with `brew upgrade 2ms`. Confirm the install:

```bash
2ms --version
```

### Prebuilt Binaries

Download the latest release for your platform from the [releases page](https://github.com/checkmarx/2ms/releases):

- [Windows (amd64)](https://github.com/checkmarx/2ms/releases/latest/download/windows-amd64.zip)
- [macOS (amd64)](https://github.com/checkmarx/2ms/releases/latest/download/macos-amd64.zip)
- [Linux (amd64)](https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip)

Unzip the archive and place the `2ms` binary somewhere on your `PATH` (for example `/usr/local/bin/2ms`).

### Build from Source

```bash
git clone https://github.com/checkmarx/2ms.git
cd 2ms
go build -o dist/2ms ./...
./dist/2ms --version
```

Refer to `go.mod` for the minimum Go toolchain version.

### Docker

Run 2ms from the published container image:

```bash
docker run --rm checkmarx/2ms
```

Mount a workspace to scan it:

```bash
docker run --rm -v "$(pwd)":/repo checkmarx/2ms git /repo --stdout-format json
```

Provide tokens and other secrets through environment variables (`-e SLACK_TOKEN=...`) or mounted config files.

## Scan Targets

| Command | Surface | Typical Use |
|---------|---------|-------------|
| `2ms filesystem` | Local directories | Scan any type of source file. |
| `2ms git <path>` | Git repositories | Inspect commit history to find any secret exposed. |
| `2ms confluence <URL>` | Confluence Cloud | Crawl spaces and pages. |
| `2ms discord` | Discord servers | Audit server message history. |
| `2ms slack` | Slack workspaces | Review channels for exposed credentials. |
| `2ms paligo` | Paligo instances | Scrape documentation components delivered via Paligo. |

### Local File System

```bash
2ms filesystem --path . --ignore-pattern "*.log"
```

| Flag | Type | Description |
|------|------|-------------|
| `--path` | string (required) | Directory to scan. |
| `--project-name` | string | Optional label to distinguish multiple filesystem scans. |
| `--ignore-pattern` | string slice | Glob patterns to exclude (matched against the file or folder name). |

### Git Repositories

```bash
2ms git /path/to/repo --depth 200 --project-name api-service
```

| Flag | Type | Description |
|------|------|-------------|
| `--depth` | int | Limit how many commits from `HEAD` are analyzed. |
| `--all-branches` | bool | Scan every branch instead of the checked-out branch. |
| `--base-commit` | string | Only scan commits between the base commit and `HEAD`. |
| `--project-name` | string | Optional label to differentiate results. |

### Confluence Cloud

```bash
2ms confluence https://<org>.atlassian.net/wiki --space-keys ENG,SEC --history \
  --username alice@example.com --token "$ATLASSIAN_TOKEN"
```

| Flag | Type | Description                                             |
|------|------|---------------------------------------------------------|
| `--space-keys` | string slice | Comma-separated space keys to crawl.                    |
| `--space-ids` | string slice | Comma-separated space IDs to crawl.                     |
| `--page-ids` | string slice | Specific page IDs to scan.                              |
| `--history` | bool | Include all revisions (page history).                   |
| `--username` | string | Confluence user/email for authentication.               |
| `--token` | string | Authentication token (Confluence API token or scoped API token). |
| `--max-api-response-megabytes` | int  | Soft per-response size limit (MB). `0` disables it. Exceeded batches are skipped.      |
| `--max-page-body-megabytes`    | int  | Soft per-page body size limit (MB). `0` disables it. Oversized pages are skipped.      |
| `--max-total-scan-megabytes`   | int  | Global download limit (MB). `0` disables it. If exceeded, the scan stops early.        |

URLs must be HTTPS. Without credentials 2ms scans only public content.

#### Authentication
- To scan **private spaces**, provide `--username` and `--token` (API token).
- How to create a Confluence API token: https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/

#### Examples

- Scan **all public pages** (no auth):
    ```bash
    2ms confluence https://<org>.atlassian.net/wiki
    ```

- Scan **private pages with an api token or a scoped api token** (requires auth):
    ```bash
    2ms confluence https://<org>.atlassian.net/wiki --username <USERNAME> --token <API_TOKEN>
    ```

- Scan specific **spaces by ID**:
    ```bash
    2ms confluence https://<org>.atlassian.net/wiki --space-ids 1234567890,9876543210
    ```

- Scan specific **pages by ID**:
    ```bash
    2ms confluence https://<org>.atlassian.net/wiki --page-ids 11223344556,99887766554
    ```

### Slack

```bash
2ms slack --token "$SLACK_TOKEN" --team my-workspace --duration 30d --channel secure-chat
```

| Flag | Type | Description |
|------|------|-------------|
| `--token` | string (required) | Slack token with permission to read conversations. |
| `--team` | string (required) | Workspace name or ID. |
| `--channel` | string slice | Channel names or IDs to target. Defaults to all channels. |
| `--duration` | duration | Look back interval (default `14d`). Use values like `24h`, `7d`, `1M`. |
| `--messages-count` | int | Upper bound on messages per channel (0 = all). |

### Discord

```bash
2ms discord --token "$DISCORD_TOKEN" --server 1097814317077897307 --duration 9999h
```

| Flag | Type | Description |
|------|------|-------------|
| `--token` | string (required) | Discord bot or user token. |
| `--server` | string slice (required) | Server (guild) names or IDs to scan. |
| `--channel` | string slice | Channel names or IDs to restrict the scan. Defaults to all channels. |
| `--duration` | duration | Look back interval (default `14d`). |
| `--messages-count` | int | Maximum messages per channel (0 = scan until duration is met). |

### Paligo

```bash
2ms paligo --instance your-instance --username alice --token "$PALIGO_TOKEN"
```

| Flag | Type | Description |
|------|------|-------------|
| `--instance` | string (required) | Paligo instance name (subdomain). |
| `--username` | string | Paligo username (use with `--token`). |
| `--token` | string | API token for authentication. |
| `--auth` | string | Base64-encoded `username:password` alternative to `--username/--token`. |
| `--folder` | int | Folder ID to scope the scan; scans the whole instance when omitted. |

## Configuration & Tuning

Global flags work with every subcommand. Combine them with configuration files and environment variables to automate 2ms in large environments.

### Global Flags

| Flag                              | Type         | Default | Description                                                                                                     |
|-----------------------------------|--------------|---------|-----------------------------------------------------------------------------------------------------------------|
| `--config`                        | string       |         | Path to a YAML or JSON configuration file.                                                                      |
| `--log-level`                     | string       | `info`  | Logging level: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, or `none`.                                   |
| `--stdout-format`                 | string       | `yaml`  | `yaml`, `json`, or `sarif` output on stdout.                                                                    |
| `--report-path`                   | string slice |         | Write findings to one or more files; format is inferred from the extension.                                     |
| `--ignore-on-exit`                | enum         | `none`  | Control exit codes: `all`, `results`, `errors`, or `none`.                                                      |
| `--max-target-megabytes`          | int          | `0`     | Skip files larger than the threshold (0 disables the check).                                                    |
| `--max-findings`                  | int          | `0`     | Caps the total number of results. Scan stops early if limit is reached. Omit or set to 0 to disable.            |
| `--max-rule-matches-per-fragment` | int          | `0`     | Caps the number of results per rule per fragment (e.g., file, chunked file, page). Omit or set to 0 to disable. |
| `--max-secret-size`               | int          | `0`     | Secrets larger than this size (in bytes) will be ignored. Omit or set to 0 to disable this check.               |
| `--validate`                      | bool         | `false` | Enrich results by verifying secrets when supported.                                                             |

### Configuration Files & Environment Variables

Pass `--config` to load shared defaults:

```yaml
# .2ms.yaml
log-level: debug
stdout-format: json
report-path:
  - reports/2ms.json

filesystem:
  path: .
  ignore-pattern:
    - "*.log"
```

You can still override values via CLI flags; the CLI always wins over config values.

### Rules, Validation, and Custom Detection

- List the available detection rules (and whether they support validation) with `2ms rules`.
- The full rule catalog lives in [`docs/list-of-rules.md`](docs/list-of-rules.md).
- Focus on specific checks with `--rule <rule-id>` or exclude noisy ones with `--ignore-rule`.
- Enable opt-in detections via `--add-special-rule <rule-id>` and tailor searches using custom `--regex` patterns.
- Suppress individual findings with `--ignore-result <secret-id>` or whitelist known safe secrets using `--allowed-values`.
- `--validate` asks 2ms to contact the upstream service (when available) to confirm a secret is still active. Validation outcomes feed into the CVSS-derived score in each result.

## Reports & Outputs

2ms prints YAML summaries by default. Switch formats or emit multiple artifacts:

```bash
2ms git . \
  --stdout-format json \
  --report-path build/2ms.sarif \
  --report-path build/2ms.yaml
```

SARIF reports plug directly into GitHub Advanced Security or other code-scanning dashboards. All outputs include rule metadata, severity scores, file locations, and (when enabled) validation status.

## CI/CD & Automation

Run 2ms in pipelines, scheduled jobs, or security gates:

```yaml
name: secret-scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0
      - name: Run 2ms
        run: |
          docker run --rm -v "$PWD":/repo checkmarx/2ms \
            git /repo --stdout-format sarif \
            --report-path /repo/artifacts/2ms.sarif \
            --ignore-on-exit results
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: artifacts/2ms.sarif
```

Use `--ignore-on-exit results` to keep pipelines green when only findings (not errors) are present, or leave it at the default `none` to fail on detected secrets.

## Custom Rules File

We support custom rules, which are user defined rules that can be passed via a custom rules file using the `--custom-rules-path` flag. The custom rules file format and extension can be YAML or JSON.

Custom rules can be:

- **Overrides** - if a rule present in the file shares the same ruleId as a default rule of 2ms, the rule present in the file will replace (override) the default rule in the scan.
  - Note: If a rule is overridden, it will simply take all fields from the rule as defined in the file. You must include all fields that you want to be defined, otherwise they will be nil/empty.

- **New rules** - if a rule does not share ruleId with a default rule, it will be appended to the list of rules used in the scan.

Custom rules work properly with --rule and --ignore-rule flags. Rules can be selected/ignored by ruleId, ruleName and tag

Regardless of being an override or new rule, a custom rule has the following required fields:
- ruleId - unique identifier of the rule
- ruleName - human readable name of the rule
- regex - regex pattern used to identify the secret

Other fields are optional and can be seen in the example bellow of a file with a custom rule

**YAML Example:**
```yaml
- ruleId: 01ab7659-d25a-4a1c-9f98-dee9d0cf2e70 # REQUIRED: unique id, must match default rule id to override that default rule. Rule ids can be used as values in --rule and --ignore-rule flags
  ruleName: Custom-Api-Key # should be human-readable name. If left empty for new rule, ruleName will take the value of ruleId. If left empty for override, default rule name will be considered. Rule names can be used as values in --rule and --ignore-rule flags 
  description: Custom rule
  regex: (?i)\b\w*secret\w*\b\s*:?=\s*["']?([A-Za-z0-9/_+=-]{8,150})["']? # REQUIRED: golang regular expression used to find secrets. For regexes, if enclosed in "", make sure to escape backslashes (\\, \\b, etc.). If capture group is present in regex, it's used to find the secret, otherwise whole regex is used. Which group is considered the secret can be defined with secretGroup
  keywords: # Keywords are used for pre-regex check filtering. Rules that contain keywords will perform a quick string compare check to make sure the keyword(s) are in the content being scanned.
    - access
    - api
  entropy: 3.5 # shannon entropy, measures how random a string is. The value will be higher the more random a string is. Default rules that use entropy have values between 2.0 and 4.5. Leave empty to consider matches regardless of entropy
  secretGroup: 1 # defines which capture group of regex match is considered the secret. Is also used as the group that will have its entropy checked if `entropy` is set. Can be left empty, in which case the first capture group to match will be considered the secret
  path: "(?i)\\.(?:tf|hcl)$" # regex to limit the rule to specific file paths, for example, only .tf and .hcl files. For regexes, if enclosed in "", make sure to escape backslashes (\\, \\b, etc.)
  severity: High # severity, can only be one of [Critical, High, Medium, Low, Info]
  tags: # identifiers for the rule, tags can be used as values of --rule and --ignore-rule flags
    - api-key
  category: General # category of the rule, should be a string of type ruledefine.RuleCategory. Can be omitted in custom rule, but if omitted and ruleId matches a default rule, the category will take the value of the category of that defaultRule. Impacts cvss score
  scoreRuleType: 4 # can go from 1 to 4, 4 being most severe. If omitted in rule it will take the value of 1. Impacts cvss score
  disableValidation: false # if true, disables validity check for this rule, regardless of --validate flag
  deprecated: false # if true, the rule will not be used in the scan, regardless of --rule flag
  allowLists: # allowed values to ignore if matched
    - description: Allowlist for Custom Rule
      matchCondition: OR # Can be AND or OR. determines whether all criteria in the allowList must match. Defaults to OR if not specified
      regexTarget: match - # Can be match or line. Determines whether the regexes in allowList are tested against the rule.Regex match or the full line being scanned. Defaults to "match" if not specified
      regexes: # allowed regex patterns
        - (?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|KeyVault(?:[A-Za-z]*?(?:Administrator|Reader|Contributor|Owner|Operator|User|Officer))\s*[:=]\s*['"]?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}['"]?|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?-i:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\.jsonwebtoken[
          \t]?:[
          \t]?[\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z)))
      stopWords:  # stop words that if found in the secret, will discard the finding. Stop words are searched on the secret, which can be either the full regex match or the capture group if any is defined in the rule regex
        - 000000,
        - 6fe4476ee5a1832882e326b506d14126
      paths: # paths that can be ignored for this allowList
        - \.bb$
        - \.bbappend$
        - \.bbclass$
        - \.inc$
    - matchCondition: AND
      regexTarget: line
      regexes:
        - LICENSE[^=]*=\s*"[^"]+
        - LIC_FILES_CHKSUM[^=]*=\s*"[^"]+
        - SRC[^=]*=\s*"[a-zA-Z0-9]+
```

## Contributing

2ms is built around a plugin system so new targets and enhancements are easy to add. Check out [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding guidelines, and how to propose new rules or plugins.

## Community

- [Report issues or feature requests](https://github.com/Checkmarx/2ms/issues/new)

2ms is maintained by Checkmarx and released under the [Apache 2.0 License](LICENSE) — contributions and feedback are always welcome.
