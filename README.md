# 2ms (Too many secrets)

[![Latest Release](https://img.shields.io/github/v/release/checkmarx/2ms)](https://github.com/checkmarx/2ms/releases)
[![Homebrew](https://img.shields.io/badge/homebrew-2ms-blue?logo=homebrew)](https://formulae.brew.sh/formula/2ms)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Discussions](https://img.shields.io/badge/chat-discussions-blue.svg?style=flat-square&logo=github)](https://github.com/Checkmarx/2ms/discussions)
[![Discord Server](https://img.shields.io/discord/1116626376674521169?logo=discord)](https://discord.gg/uYVhfSGG)
[![Trivy](https://github.com/Checkmarx/2ms/actions/workflows/trivy-vulnerability-scan.yaml/badge.svg)](https://github.com/Checkmarx/2ms/actions/workflows/trivy-vulnerability-scan.yaml)

![2ms Mascot](https://github.com/Checkmarx/2ms/assets/1287098/3a543045-9c6a-4a35-9bf8-f41919e7b03e)

**Too many secrets (`2ms`)** is an open source CLI tool, powered by Checkmarx, that enables you to identify sensitive data such as secrets, authentication keys and passwords that are stored in your system in unencrypted text. This tool supports scanning of internal communication platforms (Slack, Discord), content management (Confluence, Paligo) and source code storage locations (Git repo, local directory).  
This application is written in Go language and is based on the framework provided by [gitleaks](https://github.com/gitleaks/gitleaks).

The tool checks the content using a series of rules that are designed to identify a wide range of sensitive items such as AWS access token, Bitbucket Client ID, GitHub PAT etc. For a complete list of rules, see [docs/list-of-rules.md](docs/list-of-rules.md).

Additionally, the tool incorporates a scoring system based on the Common Vulnerability Scoring System (CVSS) to help prioritize remediation efforts.

# Installation

The following sections explain how to install 2ms using the following methods:

- [Homebrew (macOS/Linux)](#homebrew-macoslinux)
- [Download and Install Precompiled Binaries](#download-and-install-precompiled-binaries)
- [Compile from Source](#compile-from-source)
- [Run From Docker Container](#run-from-docker-container)
- [CI/CD Integrations](#cicd-integrations)

## Homebrew (macOS/Linux)

You can now install **2ms** directly via [Homebrew](https://brew.sh):

```bash
brew install 2ms
````

Once installed, verify the installation with:

```bash
2ms --version
```

## Download and Install Precompiled Binaries

You can download 2ms precompiled binaries for amd64 architecture from our [releases page](https://github.com/Checkmarx/2ms/releases).
The following links can be used to download the "latest" version, for each supported OS.

* [Download for Windows](https://github.com/checkmarx/2ms/releases/latest/download/windows-amd64.zip)
* [Download for MacOS](https://github.com/checkmarx/2ms/releases/latest/download/macos-amd64.zip)
* [Download for Linux](https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip)

### Install Globally

Install 2ms globally on your local machine by placing the compiled binary on your path. For example, on Linux you can place `2ms` binary in `/usr/local/bin/` or create a symbolic link.

**Example:**

```bash
cd /opt
mkdir 2ms
cd 2ms
wget https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip
unzip linux-amd64.zip
sudo ln -s /opt/2ms/2ms /usr/local/bin/2ms
```

[![asciicast](https://asciinema.org/a/zkgwRn5fF7JG8uUG3MGJy6UGT.svg)](https://asciinema.org/a/zkgwRn5fF7JG8uUG3MGJy6UGT)

## Compile from source

You can compile the project from its source using the following commands:

```bash
git clone https://github.com/checkmarx/2ms.git
cd 2ms
go build -o dist/2ms main.go
./dist/2ms
```

## Run From Docker Container

We publish container image releases of `2ms` to [checkmarx/2ms](https://hub.docker.com/r/checkmarx/2ms) .
To run `2ms` from a docker container use the following command:

```
docker run checkmarx/2ms
```

### Mounting a Local Directory

You can also mount a local directory by using the`-v` flag with the following syntax `-v <local-dir-path>:<container-dir-path>`

**Example:**

```bash
docker run -v /home/user/workspace/git-repo:/repo checkmarx/2ms git /repo
```

- For `git` command, you need to mount your git repository to `/repo` inside the container

## CI/CD Integrations

### GitHub Actions

The following is a template for creating a GitHub Action that runs 2ms from a Docker image to scan your GitHub repo.  
**Note:** Make sure that in the `actions/checkout` step you access the full history by setting the depth as follows `fetch-depth: 0`

```yaml
name: Pipeline Example With 2MS

on:
  pull_request:
    workflow_dispatch:
    push:
      branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
        with:
          # Required for 2ms to have visibility to all commit history
          fetch-depth: 0

      # ...

      - name: Run 2ms Scan
        run: docker run -v $(pwd):/repo checkmarx/2ms:2.8.1 git /repo
```

- This example uses version to `2.8.1` of 2ms. Make sure to check for the latest version.
- 💡 Take a look at [2ms GitHub Actions pipeline](https://github.com/Checkmarx/2ms/blob/master/.github/workflows/release.yml) as 2ms scans itself using 2ms.

### Azure DevOps Pipeline

To use 2ms in Azure DevOps Pipeline, create a new pipeline ([see this tutorial](https://learn.microsoft.com/en-us/azure/devops/pipelines/create-first-pipeline) for getting started with Azure DevOps Pipelines). Then, use the following template to create a `yml` file `azure-pipelines.yml` to run `2ms`:

```yaml
trigger:
  - master

pool:
  vmImage: ubuntu-latest

steps:
  - script: docker run -v $(pwd):/repo checkmarx/2ms:2.8.1 git /repo
    displayName: Run 2ms
```

- This example uses version to `2.8.1` of 2ms. Make sure to check for the latest version.

# Running 2ms Scans

## Overview

2ms has dedicated commands for scanning each of the supported platforms. To run a scan, you need to enter the command for the platform that you are scanning, along with all of the arguments that are relevant for that platform. The scan command arguments are used for authentication as well as to provide details about the locations that will be scanned. These arguments differ for each platform. In addition, you can add global flags to customize the scan configuration.  
The fundamental structure of a scan command is:

```text
2ms <scan command> [scan command arguments] [global flags]
```

Scan command arguments and global flags can be passed either as flags in the scan command or via a config file.

### Command Line Help

We've built the `2ms` command line interface to be as self-descriptive as possible. This is the help message that is shown when you execute `2ms` without args:

<!-- command-line:start -->

```text
2ms Secrets Detection: A tool to detect secrets in public websites and communication services.

Usage:
  2ms [command]

Scan Commands
  confluence  Scan Confluence Cloud
  discord     Scan Discord server
  filesystem  Scan local folder
  git         Scan local Git repository
  paligo      Scan Paligo instance
  slack       Scan Slack team

Additional Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  rules       List all rules

Flags:
      --add-special-rule strings      special (non-default) rules to apply.
                                      This list is not affected by the --rule and --ignore-rule flags.
      --allowed-values strings        allowed secrets values to ignore
      --config string                 config file path
      --custom-rules-path string      Path to a custom rules file (JSON or YAML). Rules should be a list of ruledefine.Rule objects. --rule, --ignore-rule still apply to custom rules
  -h, --help                          help for 2ms
      --ignore-on-exit ignoreOnExit   defines which kind of non-zero exits code should be ignored
                                      accepts: all, results, errors, none
                                      example: if 'results' is set, only engine errors will make 2ms exit code different from 0 (default none)
      --ignore-result strings         ignore specific result by id
      --ignore-rule strings           ignore rules by name or tag
      --log-level string              log level (trace, debug, info, warn, error, fatal, none) (default "info")
      --max-target-megabytes int      files larger than this will be skipped.
                                      Omit or set to 0 to disable this check.
      --regex stringArray             custom regexes to apply to the scan, must be valid Go regex
      --report-path strings           path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)
      --rule strings                  select rules by name or tag to apply to this scan
      --stdout-format string          stdout output format, available formats are: json, yaml, sarif (default "yaml")
      --validate                      trigger additional validation to check if discovered secrets are valid or invalid
  -v, --version                       version for 2ms

Use "2ms [command] --help" for more information about a command.
```

<!-- command-line:end -->

### Configuration File

You can pass `--config [path to config file]` argument to specify a configuration file. The configuration file format can be YAML or JSON.

**Example:**

```yaml
log-level: info

regex:
  - password\=

report-path:
  - ./report.yaml
  - ./report.json
  - ./report.sarif

paligo:
  instance: your-instance
  username: your-username
```

#### Hybrid Configuration Mode

You can pass a combination of command line arguments **and** a configuration file. In this case, the 2ms merges the values from the file and the explicit arguments.

`.2ms.yml` config file:

```yaml
ignore-result:
  - b0a735b7b0a2bc6fb1cd69824a9afd26f0f7ebc8
  - 51c76691792d9f6efe8af1c89c678386349f48a9
  - 81318f7350a4c42987d78c99eacba2c5028636cc
  - 8ea22c1e010836b9b0ee84e14609b574c9965c3c
```

Command: The `--spaces` flag is provided in the CLI command (outside of config file):

**Example:**

```yaml
docker run -v $(pwd)/.2ms.yml:/app/.2ms.yml checkmarx/2ms \
    confluence --url https://checkmarx.atlassian.net/wiki \
    --spaces secrets --config /app/.2ms.yml
```

[![asciicast](https://asciinema.org/a/n8RHL4v6vI87uiUPZ9I7CgfYy.svg)](https://asciinema.org/a/n8RHL4v6vI87uiUPZ9I7CgfYy)

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
  ruleName: Custom-Api-Key # human-readable name. Can be left empty for overrides, in which case the respective default rule name will be considered. Rule names can be used as values in --rule and --ignore-rule flags 
  description: Custom rule 
  regex: (?i)\b\w*secret\w*\b\s*:?=\s*["']?([A-Za-z0-9/_+=-]{8,150})["']? # REQUIRED: golang regular expression used to find secrets. If capture group is present in regex, it used to find the secret, otherwise whole regex is used. which group is considered the secret can be defined with secretGroup
  keywords: # Keywords are used for pre-regex check filtering. Rules that contain keywords will perform a quick string compare check to make sure the keyword(s) are in the content being scanned.
    - access
    - api
  entropy: 3.5 # shannon entropy, measures how random a string is. The value will be higher the more random a string is. Default rules that use entropy have values between 2.0 and 4.5. Leave empty to consider matches regardless of entropy
  secretGroup: 1 # defines which capture group of regex match is considered the secret. Is also used as the group that will have its entropy checked if `entropy` is set. Can be left empty, in which case the first capture group to match will be considered the secret
  path: (?i)\.(?:tf|hcl)$ # regex to limit the rule to specific file paths. For example, only .tf and .hcl files
  severity: High # severity, can only be one of [Critical, High, Medium, Low, Info]
  tags: # identifiers for the rule, tags can be used as values of --rule and --ignore-rule flags
    - api-key
  scoreParameters: # scoreParameters can be omitted for overrides, in which case the respective default rule scoreParameters will be considered
    category: General # category of the rule, should be a string of type ruledefine.RuleCategory. Impacts cvss score
    ruleType: 4 # can go from 4 to 0, 4 being most severe. For overrides, if Category is defined, ruleType also needs to be defined, or otherwise it will be considered 0. Impacts cvss score
  allowLists: # allowed values to ignore if matched
    - description: Allowlist for Custom Rule
      matchCondition: OR # determines whether all criteria in the allowList must match. Can be AND or OR. Defaults to OR if not specified
      regexTarget: match - # determines whether the regexes in allowList are tested against the rule.Regex match or the full line being scanned. Can be 'match' or 'line'. Defaults to 'match' if not specified
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


## Scan Commands

The following sections describe the arguments used for scanning each of the supported platforms.

### Confluence

This command is used to scan a [Confluence](https://www.atlassian.com/software/confluence) instance.

```text
2ms confluence <URL> [flags]
```

| Flag            | Type        | Default | Description                                                                      |
| --------------- | ----------- | ------- |----------------------------------------------------------------------------------|
| `--space-keys`  | string list | (all)   | Comma-separated list of space **keys** to scan.                                  |
| `--space-ids`   | string list | (all)   | Comma-separated list of space **IDs** to scan.                                   |
| `--page-ids`    | string list | (all)   | Comma-separated list of **page IDs** to scan.                                    |
| `--history`     | bool        | `false` | Also scan **all versions** of each page (page history).                          |
| `--username`    | string      |         | Confluence username/email (used for HTTP Basic Auth).                            |
| `--token-type`  | string      |         | Token type for Confluence API. Accepted values: `api-token`, `scoped-api-token`. |
| `--token-value` | string      |         | The API token value. **Required** when `--token-type` is set.                    |

#### Authentication
- To scan **private spaces**, provide `--username`, `--token-type` and `--token-value` (API token).
- How to create a Confluence API token: https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/

#### Examples

- Scan **all public pages** (no auth):
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki
    ```

- Scan **private pages with an api token** (requires auth):
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki --username <USERNAME> --token-type api-token --token-value <API_TOKEN>
    ```

- Scan **private pages with a scoped api token** (requires auth):
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki --username <USERNAME> --token-type scoped-api-token --token-value <API_TOKEN>
    ```

- Scan specific **spaces by key**:
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki --space-keys Key1,Key2
    ```

- Scan specific **spaces by ID**:
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki --space-ids 1234567890,9876543210
    ```

- Scan specific **pages by ID**:
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki --page-ids 11223344556,99887766554
    ```

- Include **page history** (all revisions):
    ```bash
    2ms confluence https://<company id>.atlassian.net/wiki --history
    ```

### Paligo

Scans [Paligo](https://paligo.net/) content management system instance.

| Flag         | Value  | Default                         | Description                                      |
| ------------ | ------ | ------------------------------- | ------------------------------------------------ |
| `--instance` | string | -                               | Instance name                                    |
| `--token`    | string | -                               | API token for authentication                     |
| `--username` | string | -                               | Paligo username |
| `--folder`   | string | scanning all instance's folders | Folder ID                                        |
| `--auth`     | string | -                               | Base64 auth header encoded username:password     |

### Discord

Scans [Discord](https://discord.com/) chat application history.

| Flag               | Value    | Default                          | Description                                                                                            |
| ------------------ | -------- | -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `--token`          | string   | -                                | Discord token                                                                                          |
| `--channel`        | strings  | all channels will be scanned     | Discord channel IDs to scan                                                                            |
| `--messages-count` | int      | 0 = all messages will be scanned | The number of messages to scan                                                       |
| `--duration`       | duration | 14 days                          | The time interval to scan from the current time. For example, 24h for 24 hours or 336h0m0s for 14 days |
| `--server`         | strings  | -                                | Discord servers IDs to scan                                                                            |

[How to get a Discord token](https://www.geeksforgeeks.org/how-to-get-discord-token/).

Example:

```bash
2ms discord --token <YOUR_TOKEN> --server 1097814317077897307 --duration 9999h
```

### Slack

Scans [Slack](https://slack.com/) chat application history.

| Flag               | Value    | Default                          | Description                                                                                            |
| ------------------ | -------- | -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `--token`          | string   | -                                | Slack token                                                                                            |
| `--channel`        | strings  | all channels will be scanned     | Slack channel IDs to scan                                                                              |
| `--messages-count` | int      | 0 = all messages will be scanned | The number of messages to scan                                                       |
| `--duration`       | duration | 14 days                          | The time interval to scan from the current time. For example, 24h for 24 hours or 336h0m0s for 14 days |
| `--team`           | string   | -                                | Slack team name or ID                                                                                  |

### Git Repository

Scans a local git repository

```text
2ms git <Git Repo Local Path> [flags]
```

| Flag             | Value | Default                                | Description                                              |
| ---------------- | ----- | -------------------------------------- | -------------------------------------------------------- |
| `--all-branches` | -     | false - only current checked in branch | scan all branches                                        |
| `--depth`        | int   | no limit                               | limit the number of historical commits to scan from HEAD |
| `--base-commit`  | string| -                                      | base commit to scan commits between base and HEAD        |

For example

```bash
git clone https://github.com/my-account/my-repo.git
cd my-repo
2ms git .
```

### Local Directory

Scans a local repository

```bash
2ms filesystem --path PATH [flags]
```

| Flag               | Value   | Default | Description                                            |
| ------------------ | ------- | ------- | ------------------------------------------------------ |
| `--path`           | string  | -       | Local directory path                                   |
| `--project-name`   | string  | -       | Project name to differentiate between filesystem scans |
| `--ignore-pattern` | strings | -       | Patterns to ignore                                     |

Example:

```bash
2ms filesystem --path .
```

## Global Flags

The following table describes the global flags that can be used together with any of the scan commands.
| Flag | Type | Default | Description |
|------|------|---------|-------------|
|--add-special-rule | string |  | Add special (non-default) rules to apply. This list is not affected by the --rule and --ignore-rule flags. SEE BELOW |
|--config | string |  | Path to the config file |
|-h, --help | string |  | Help for 2ms commands |
|--ignore-on-exit |  | None | Defines which kind of non-zero exits code should be ignored. Options are: all, results, errors, none. For example, if 'results' is set, only engine errors will make 2ms exit code different from 0. |
|--ignore-result | strings |  | Ignore specific result by ID |
|--ignore-rule | strings |  | Ignore rules by name or tag. |
|--log-level | string | info | Type of log to return. Options are: trace, debug, info, warn, error, fatal, none |
|--max-target-megabytes | int |  | Files larger than than the specified threshold will be skipped. Omit or set to 0 to disable this check. |
|--regex | stringArray |  | Custom regexes to apply to the scan. Must be valid Go regex. |
|--report-path | strings |  | Path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif) |
|--rule | strings |  | Select rules by name or tag to apply to this scan. |
|--stdout-format | string | yaml | Stdout output format, available formats are: json, yaml, sarif |
|--validate |  |  | Trigger additional validation to check if discovered secrets are valid or invalid. SEE BELOW |
|-v, --version |  |  | Version of 2ms that is running. |

### Validity Check

Adding the `--validate` flag checks the validity of the secrets found. For example, if a Github token is found, it will check if the token is valid by making a request to the Github API. We will use the least intrusive method possible to check the validity of the secret.

The list of services that support the Validity Check feature can be found in the [List of Rules](docs/list-of-rules.md) document.

The result of the validation can be:

- `valid` - The secret is valid
- `invalid` - The secret is invalid
- `unknown` - We failed to check, or we are not checking the validity of the secret at all

If the `--validate` flag is not provided, the validation field will be omitted from the output, or its value will be an empty string.

> **Note:** The validity check also impacts the score field. If the flag is not provided, the validity is assumed to be "unknown" in the score formula.

### Special Rules

Special rules are rules that are configured in 2ms but are not run as part of the default ruleset, usually because they are too noisy or too specific. You can use the `--add-special-rule` flag to add special rules by rule ID.

For example:

```bash
2ms git . --add-special-rule hardcoded-password
```

#### List of Special Rules

| Rule ID              | Description                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `hardcoded-password` | Detects strings that are assigned to variables that contain the word `password`, `access`, `key`, etc. |

## Custom Regex Rules

You may specify one or more custom regex rules with the optional argument `--regex`. The value provided will be parsed as a regular expression and will be matched against the target items.

my-file.txt

```bash
password=1234567
username=admin
```

```bash
2ms filesystem --path . --regex username= --regex password=
```

[![asciicast](https://asciinema.org/a/607198.svg)](https://asciinema.org/a/607198)

## Contributing

`2ms` is extendable with the concept of plugins. We designed it like this so anyone can easily contribute, improve and extend `2ms`. Read more about contributing in our [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Contact

Want to report a problem or suggest an idea for improvement? Create an [Issue](https://github.com/Checkmarx/2ms/issues/new), create a [Discussion thread](https://github.com/Checkmarx/2ms/discussions), or Join our [Discord Server](https://discord.gg/9uFqFDWPyz) (seek for `#2ms` channel)

This project was made and maintained by Checkmarx with :heart:
