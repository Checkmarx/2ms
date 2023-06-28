[![Latest Release](https://img.shields.io/github/v/release/checkmarx/2ms)](https://github.com/checkmarx/2ms/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Discussions](https://img.shields.io/badge/chat-discussions-blue.svg?style=flat-square)](https://github.com/Checkmarx/2ms/discussions)

![2ms Mascot](https://github.com/Checkmarx/2ms/assets/1287098/3a543045-9c6a-4a35-9bf8-f41919e7b03e)

Too many secrets (2MS) is an open source project dedicated to helping people protect their sensitive information like passwords, API keys from appearing in public websites and communication services.

During the software development lifecycle (SDLC), developers ofen communicate and exchange secret data in various ways. While there are tools available for detecting secrets in source code and Git repositories, there are few options for identifying secrets in plain text documents, emails, chat logs, content managment systems and more. Some of them are public, or have a mixture of private / public, meaning it's easy to make an onest mistake and publish secret data to the world wide web.

2ms is built over a secret detection engine (currently [gitleaks](https://github.com/gitleaks/gitleaks)) and includes various plugins to interact with popular platforms. This means anyone can contribute, improve and extend 2ms quite easily. We believe that by working together, we can create a more secure digital world. You're welcome to join our [community](https://github.com/Checkmarx/2ms/discussions).

## Supported Platforms

- Confluence
- Discord
- Slack
- Git
- Paligo
- Local directory / files

## Getting 2ms

```
go install github.com/checkmarx/2ms@latest
```

### Docker

```
docker run -v path/to/my/repo:/repo checkmarx/2ms git /repo
```

(For `git` command, you have to mount your git repository to `/repo` inside the container)

## Getting started

<!-- command-line:start -->

```
2ms Secrets Detection: A tool to detect secrets in public websites and communication services.

Usage:
  2ms [command]

Commands
  confluence  Scan Confluence server
  discord     Scan Discord server
  filesystem  Scan local folder
  git         Scan Git repository
  paligo      Scan Paligo instance
  slack       Scan Slack team

Additional Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command

Flags:
      --config string          YAML config file path
  -h, --help                   help for 2ms
      --log-level string       log level (trace, debug, info, warn, error, fatal) (default "info")
      --regex stringArray      custom regexes to apply to the scan, must be valid Go regex
      --report-path strings    path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)
      --stdout-format string   stdout output format, available formats are: json, yaml, sarif (default "yaml")
      --tags strings           select rules to be applied (default [all])
  -v, --version                version for 2ms

Use "2ms [command] --help" for more information about a command.
```

<!-- command-line:end -->

| :warning: Using configuration env or file                                                                                                                                                      |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Please note that even using configuration file or environment variables, you still need to specify the subcommand name in the CLI arguments. Also, positional arguments are not yet supported. |

### Environment Variables

To use a flag as an environment variable, see the following rules:

- Replace `-` with `_`
- Start with `2MS_`
- Prefer uppercase
- Append the subcommand name(s) (if any) with `_`

Examples:

- `--log-level` -> `2MS_LOG_LEVEL`
- `paligo instance` -> `2MS_PALIGO_INSTANCE`

### Configuration File

You can use `--config` flag to specify a configuration file. The configuration file is a YAML/JSON file with the following structure:

```yaml
# global flags that will be applied to all commands
log-level: info
report-path:
  - ./report.yaml
  - ./report.json
  - ./report.sarif

# the subcommand will be selected from the CLI arguments
# the flags below will be applied to the selected subcommand
paligo:
  instance: your-instance
  username: your-username
  # you can combine config file and Environment Variables
  # token: your-token
```

---

Made by Checkmarx with :heart:
