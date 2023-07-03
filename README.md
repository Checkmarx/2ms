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

```bash
curl -LO https://github.com/Checkmarx/2ms/releases/latest/download/2ms && chmod +x 2ms
./2ms
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
  git         Scan local Git repository
  paligo      Scan Paligo instance
  slack       Scan Slack team

Additional Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  rules       List all rules

Flags:
      --config string          config file path
      --exclude-rule strings   exclude rules by name or tag to apply to the scan (removes from list, starts from all)
  -h, --help                   help for 2ms
      --include-rule strings   include rules by name or tag to apply to the scan (adds to list, starts from empty)
      --log-level string       log level (trace, debug, info, warn, error, fatal) (default "info")
      --regex stringArray      custom regexes to apply to the scan, must be valid Go regex
      --report-path strings    path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)
      --stdout-format string   stdout output format, available formats are: json, yaml, sarif (default "yaml")
  -v, --version                version for 2ms

Use "2ms [command] --help" for more information about a command.
```
<!-- command-line:end -->

---

Made by Checkmarx with :heart:
