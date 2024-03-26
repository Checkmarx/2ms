[![Latest Release](https://img.shields.io/github/v/release/checkmarx/2ms)](https://github.com/checkmarx/2ms/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Discussions](https://img.shields.io/badge/chat-discussions-blue.svg?style=flat-square&logo=github)](https://github.com/Checkmarx/2ms/discussions)
[![Discord Server](https://img.shields.io/discord/1116626376674521169?logo=discord)](https://discord.gg/uYVhfSGG)

![2ms Mascot](https://github.com/Checkmarx/2ms/assets/1287098/3a543045-9c6a-4a35-9bf8-f41919e7b03e)

**Too many secrets (`2ms`)** is an open source CLI tool, powered by Checkmarx, that enables you to identify sensitive data such as secrets, authentication keys and passwords that are stored in your system in unencrypted text. This tool supports scanning of internal communication platforms (Slack, Discord), content management (Confluence, Paligo) and source code storage locations (Git repo, local directory).  
This application is written in Go language and is based on the framework provided by [gitleaks](https://github.com/gitleaks/gitleaks).

The tool checks the content using a series of rules that are designed to identify a wide range of sensitive items such as AWS access token, Bitbucket Client ID, GitHub PAT etc. For a complete list of rules, see [docs/list-of-rules.md](docs/list-of-rules.md).

# Installation

The following sections explain how to install 2ms using the following methods:

- [Download and Install Precompiled Binaries](#download-and-install-precompiled-binaries)
- [Compile from Source Code](#compile-from-source-code)
- [Run From Docker Container](#run-from-docker-container)

## Download and Install Precompiled Binaries

You can download 2ms precompiled binaries for amd64 architecture from our [releases page](https://github.com/Checkmarx/2ms/releases).  
The following links can be used to download the "latest" version, for each supported OS.

- [Download for Windows](https://github.com/checkmarx/2ms/releases/latest/download/windows-amd64.zip)
- [Download for MacOS](https://github.com/checkmarx/2ms/releases/latest/download/macos-amd64.zip)
- [Download for Linux](https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip)

### Install Globally

Install 2ms globally on your local machine by placing the compiled binary on your path. For example, on Linux you can place `2ms` binary in `/usr/local/bin/` or create a symbolic link.

**Example:**

```
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
        uses: actions/checkout@v4
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
  confluence  Scan Confluence server
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
      --config string                 config file path
  -h, --help                          help for 2ms
      --ignore-on-exit ignoreOnExit   defines which kind of non-zero exits code should be ignored
                                      accepts: all, results, errors, none
                                      example: if 'results' is set, only engine errors will make 2ms exit code different from 0 (default none)
      --ignore-result strings         ignore specific result by id
      --ignore-rule strings           ignore rules by name or tag
      --log-level string              log level (trace, debug, info, warn, error, fatal) (default "info")
      --max-target-megabytes int      files larger than this will be skipped.
                                      Omit or set to 0 to disable this check.
      --regex stringArray             custom regexes to apply to the scan, must be valid Go regex
      --report-path strings           path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)
      --rule strings                  select rules by name or tag to apply to this scan
      --stdout-format string          stdout output format, available formats are: json, yaml, sarif (default "yaml")
      --validate                      trigger additional validation to check if discovered secrets are active or revoked
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

## Scan Commands

The following sections describe the arguments used for scanning each of the supported platforms.

### Confluence

This command is used to scan a [Confluence](https://www.atlassian.com/software/confluence) instance.

```text
2ms confluence <URL> [flags]
```

| Flag         |Config   |Required| Type  | Default                        | Description                                                                      |
| ------------ |----------| ------|----- | ------------------------------ | -------------------------------------------------------------------------------- |
| `<url>`      ||v|string | -                              | Confluence instance URL, in the following format: `https://<company id>.atlassian.net/wiki` |
| `--history`  || |-      | Doesn't scan history revisions | Scans pages history revisions                                                    |
| `--spaces`   ||| string | all spaces                     | The names or IDs of the Confluence spaces to scan                                |
| `--token`    | |v|string | -                              | The Confluence API token for authentication                                      |
| `--username` | |v|string | -                              | Confluence user name or email for authentication                                 |

For example:

```bash
2ms confluence https://checkmarx.atlassian.net/wiki --spaces secrets
```

- 💡 [The `secrets` Confluence site](https://checkmarx.atlassian.net/wiki/spaces/secrets) purposely created with plain example secrets as a test subject for this demo

[![asciicast](https://asciinema.org/a/607179.svg)](https://asciinema.org/a/607179)

### Paligo

Scans [Paligo](https://paligo.net/) content management system instance.

| Flag         | Value  | Default                         | Description                                      |
| ------------ | ------ | ------------------------------- | ------------------------------------------------ |
| `--instance` | string | -                               | Instance name                                    |
| `--token`    | string | -                               | API token for authentication                     |
| `--username` | string | -                               | Confluence user name or email for authentication |
| `--folder`   | string | scanning all instance's folders | Folder ID                                        |
| `--auth`     | string | -                               | Base64 auth header encoded username:password     |

### Discord

Scans [Discord](https://discord.com/) chat application history.

| Flag               | Value    | Default                          | Description                                                                                            |
| ------------------ | -------- | -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `--token`          | string   | -                                | Discord token                                                                                          |
| `--channel`        | strings  | all channels will be scanned     | Discord channel IDs to scan                                                                            |
| `--messages-count` | int      | 0 = all messages will be scanned | Confluence user name or email for authentication                                                       |
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
| `--messages-count` | int      | 0 = all messages will be scanned | Confluence user name or email for authentication                                                       |
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

| Flag | Config |Type| Default|Description |
|--|--|--|--|--|
|--add-special-rule  |  | string |  | Add special (non-default) rules to apply. This list is not affected by the --rule and --ignore-rule flags. SEE BELOW|  
|--config |  | string |  |Path to the config file|
|-h, --help|  | string  |  | Help for 2ms commands |
|--ignore-on-exit  |  |  |None  |Defines which kind of non-zero exits code should be ignored. Options are: all, results, errors, none. For example, if 'results' is set, only engine errors will make 2ms exit code different from 0.|
|--ignore-result  |  |strings  |  |Ignore specific result by ID  |
|--ignore-rule  | |strings  |  |Ignore rules by name or tag.|
|--log-level  |  |string  |info |Type of log to return. Options are: trace, debug, info, warn, error, fatal|
|--max-target-megabytes  |  |int  |  |Files larger than than the specified threshold will be skipped. Omit or set to 0 to disable this check.|
|--regex  |  |stringArray  |  |Custom regexes to apply to the scan.  Must be valid Go regex.|
|--report-path  |  |strings  |  |Path to generate report files.The output format will be determined by the file extension (.json, .yaml, .sarif)|
|--rule|  |strings  |  |Select rules by name or tag to apply to this scan.|
|--stdout-format  |  |string  |yaml  |Stdout output format, available formats are: json, yaml, sarif|
|--validate |  |  |  | Trigger additional validation to check if discovered secrets are active or revoked. SEE BELOW   |
|-v, --version |  |  |  | Version of 2ms that is running. |

### Validity Check

From the help message: `--validate    trigger additional validation to check if discovered secrets are active or revoked`.

The `--validate` flag will check the validity of the secrets found. For example, if it is a Github token, it will check if the token is valid by making a request to the Github API. We will use the less intrusive method to check the validity of the secret.

The list of services that support the Validity Check feature can be found in the [List of Rules](docs/list-of-rules.md) document.

The result of the validation can be:

- `valid` - The secret is valid
- `revoked` - The secret is revoked
- `unknown` - We failed to check, or we are not checking the validity of the secret at all

If the `--validate` flag is not provided, the validation field will be omitted from the output, or its value will be an empty string.

### Special Rules

Special rules are rules that are not part of the default ruleset, usually because they are too noisy or too specific. You can use the `--add-special-rule` flag to add special rules by rule ID.

For example:

```bash
2ms git . --add-special-rule hardcoded-password
```

#### List of Special Rules

| Rule ID              | Description                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `hardcoded-password` | Detects strings that assigned to variables that contain the word `password`, `access`, `key`, etc. |

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
