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
- Flexible filtering and noise reduction: `--rule`, `--ignore-rule`, `--add-special-rule`, `--ignore-result`, `--regex`, `--allowed-values`, and `--max-target-megabytes`.
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

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | | Path to a YAML or JSON configuration file. |
| `--log-level` | string | `info` | Logging level: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, or `none`. |
| `--stdout-format` | string | `yaml` | `yaml`, `json`, `sarif`, or `human` output on stdout. |
| `--report-path` | string slice | | Write findings to one or more files; format is inferred from the extension. |
| `--ignore-on-exit` | enum | `none` | Control exit codes: `all`, `results`, `errors`, or `none`. |
| `--max-target-megabytes` | int | `0` | Skip files larger than the threshold (0 disables the check). |
| `--validate` | bool | `false` | Enrich results by verifying secrets when supported. |

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

Set `--stdout-format human` for a terse, human-friendly summary on the console (great for local runs), while still writing machine-readable reports via `--report-path`.
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

## Contributing

2ms is built around a plugin system so new targets and enhancements are easy to add. Check out [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding guidelines, and how to propose new rules or plugins.

## Community

- [Report issues or feature requests](https://github.com/Checkmarx/2ms/issues/new)

2ms is maintained by Checkmarx and released under the [Apache 2.0 License](LICENSE) — contributions and feedback are always welcome.
