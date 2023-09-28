[![Latest Release](https://img.shields.io/github/v/release/checkmarx/2ms)](https://github.com/checkmarx/2ms/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Discussions](https://img.shields.io/badge/chat-discussions-blue.svg?style=flat-square&logo=github)](https://github.com/Checkmarx/2ms/discussions)
[![Discord Server](https://img.shields.io/discord/1116626376674521169?logo=discord)](https://discord.gg/uYVhfSGG)

![2ms Mascot](https://github.com/Checkmarx/2ms/assets/1287098/3a543045-9c6a-4a35-9bf8-f41919e7b03e)

**Too many secrets (`2ms`)** is a command line tool written in Go language and built over [gitleaks](https://github.com/gitleaks/gitleaks). `2ms` is capable of finding secrets such as login credentials, API keys, SSH keys and more hidden in code, content systems, chat applications and more.

# Installation

### Download Precompiled Binaries

2ms precompiled binaries for amd64 architecture are attached as assets in our [releases page](https://github.com/Checkmarx/2ms/releases)

- [Download for Windows](https://github.com/checkmarx/2ms/releases/latest/download/windows-amd64.zip)
- [Download for MacOS](https://github.com/checkmarx/2ms/releases/latest/download/macos-amd64.zip)
- [Download for Linux](https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip)
- [Other](https://github.com/Checkmarx/2ms/releases)

#### Install Globally

You may place the compiled binary on your path. On Linux for example you can place `2ms` binary in `/usr/local/bin/` or create a symbolic link. For example:

```
cd /opt
mkdir 2ms
cd 2ms
wget https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip
unzip linux-amd64.zip
sudo ln -s /opt/2ms/2ms /usr/local/bin/2ms
```

[![asciicast](https://asciinema.org/a/zkgwRn5fF7JG8uUG3MGJy6UGT.svg)](https://asciinema.org/a/zkgwRn5fF7JG8uUG3MGJy6UGT)

### Compiling from source

If you wish to compile the project from its source use the following commands

```bash
git clone https://github.com/checkmarx/2ms.git
cd 2ms
go build -o dist/2ms main.go
./dist/2ms
```

### Run From Docker Container

We publish container image releases of `2ms` to [checkmarx/2ms](https://hub.docker.com/r/checkmarx/2ms) . To run `2ms` from a docker container use the following command:

```
docker run checkmarx/2ms
```

You may also mount a local directory with the `-v <local-dir-path>:<container-dir-path>` argument. For instance:

```
docker run -v /home/user/workspace/git-repo:/repo checkmarx/2ms git /repo
```

- For `git` command, you have to mount your git repository to `/repo` inside the container

### GitHub Actions

To use in GitHub actions, make sure you tell `actions/checkout` step to go full history depth by setting `fetch-depth: 0`

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
        uses: actions/checkout@v3
        with:
          # Required for 2ms to have visibility to all commit history
          fetch-depth: 0

      # ...

      - name: Run 2ms Scan
        run: docker run -v $(pwd):/repo checkmarx/2ms:2.8.1 git /repo
```

- In this example we've pinned the version to `2.8.1`. Make sure to check out if there's a newer version
- 💡 Take a look at [2ms GitHub Actions pipeline](https://github.com/Checkmarx/2ms/blob/master/.github/workflows/release.yml) as 2ms scans itself using 2ms.

# Command Line Interface

We've built `2ms` command line interface to be as self-descriptive as possible. This is the help message that you will see if you executed `2ms` without args:

<!-- command-line:start -->

```
2ms Secrets Detection: A tool to detect secrets in public websites and communication services.

Usage:
  2ms [command]

Commands
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
      --regex stringArray             custom regexes to apply to the scan, must be valid Go regex
      --report-path strings           path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)
      --rule strings                  select rules by name or tag to apply to this scan
      --stdout-format string          stdout output format, available formats are: json, yaml, sarif (default "yaml")
  -v, --version                       version for 2ms

Use "2ms [command] --help" for more information about a command.
```

<!-- command-line:end -->

## Special Rules

Special rules are rules that are not part of the default ruleset, usually because they are too noisy or too specific. You can use the `--add-special-rule` flag to add special rules by rule ID.

For example:

```
2ms git . --add-special-rule hardcoded-password
```

### List of Special Rules

| Rule ID              | Description                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `hardcoded-password` | Detects strings that assigned to variables that contain the word `password`, `access`, `key`, etc. |

## Custom Regex Rules

You may specify one or more custom regex rules with the optional argument `--regex`. The value provided will be parsed as a regular expression and will be matched against the target items.

my-file.txt

```
password=1234567
username=admin
```

```
2ms filesystem --path . --regex username= --regex password=
```

[![asciicast](https://asciinema.org/a/607198.svg)](https://asciinema.org/a/607198)

## Plugins

We offer the following list of integrations in the form of plugins

### Confluence

scans a [Confluence](https://www.atlassian.com/software/confluence) instance

```
2ms confluence <URL> [flags]
```

| Flag         | Value  | Default                        | Description                                                                      |
| ------------ | ------ | ------------------------------ | -------------------------------------------------------------------------------- |
| `--url`      | string | -                              | Confluence instance URL in the form of `https://<company id>.atlassian.net/wiki` |
| `--history`  | -      | not scanning history revisions | Scans pages history revisions                                                    |
| `--spaces`   | string | all spaces                     | The names or IDs of the Confluence spaces to scan                                |
| `--token`    | string | -                              | The Confluence API token for authentication                                      |
| `--username` | string | -                              | Confluence user name or email for authentication                                 |

For example:

```
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

```
2ms git <Git Repo Local Path> [flags]
```

| Flag             | Value | Default                                | Description                                              |
| ---------------- | ----- | -------------------------------------- | -------------------------------------------------------- |
| `--all-branches` | -     | false - only current checked in branch | scan all branches                                        |
| `--depth`        | int   | no limit                               | limit the number of historical commits to scan from HEAD |

For example

```
git clone https://github.com/my-account/my-repo.git
cd my-repo
2ms git .
```

### Local Directory

Scans a local repository

```
2ms filesystem --path PATH [flags]
```

| Flag               | Value   | Default | Description                                            |
| ------------------ | ------- | ------- | ------------------------------------------------------ |
| `--path`           | string  | -       | Local directory path                                   |
| `--project-name`   | string  | -       | Project name to differentiate between filesystem scans |
| `--ignore-pattern` | strings | -       | Patterns to ignore                                     |

## Configuration File

You can pass `--config [path to config file]` argument to specify a configuration file. The configuration file format can be in YAML or JSON.

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

### Hybrid Configuration Mode

You may pass a combination of command line arguments **and** a configuration file, the result is going to merge the values from the file and the explicit arguments

`.2ms.yml` config file:

```yaml
ignore-result:
  - b0a735b7b0a2bc6fb1cd69824a9afd26f0f7ebc8
  - 51c76691792d9f6efe8af1c89c678386349f48a9
  - 81318f7350a4c42987d78c99eacba2c5028636cc
  - 8ea22c1e010836b9b0ee84e14609b574c9965c3c
```

command, `--space` is provided outside of config file:

```yaml
docker run -v $(pwd)/.2ms.yml:/app/.2ms.yml checkmarx/2ms confluence --url https://checkmarx.atlassian.net/wiki --spaces secrets --config /app/.2ms.yml
```

[![asciicast](https://asciinema.org/a/n8RHL4v6vI87uiUPZ9I7CgfYy.svg)](https://asciinema.org/a/n8RHL4v6vI87uiUPZ9I7CgfYy)

## Contributing

`2ms` is extendable with the concept of plugins. We designed it like this so anyone can easily contribute, improve and extend `2ms`. Read more about contributing in our [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Contact

Want to report a problem or suggest an idea for improvement? Create an [Issue](https://github.com/Checkmarx/2ms/issues/new), create a [Discussion thread](https://github.com/Checkmarx/2ms/discussions), or Join our [Discord Server](https://discord.gg/9uFqFDWPyz) (seek for `#2ms` channel)

This project was made and maintained by Checkmarx with :heart:
