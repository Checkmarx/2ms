[![Latest Release](https://img.shields.io/github/v/release/checkmarx/2ms)](https://github.com/checkmarx/2ms/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Discussions](https://img.shields.io/badge/chat-discussions-blue.svg?style=flat-square&logo=github)](https://github.com/Checkmarx/2ms/discussions)
[![Discord Server](https://img.shields.io/discord/1116626376674521169?logo=discord)](https://discord.gg/uYVhfSGG)

![2ms Mascot](https://github.com/Checkmarx/2ms/assets/1287098/3a543045-9c6a-4a35-9bf8-f41919e7b03e)

**Too many secrets (`2ms`)** is a command line tool written in Go language and built over [gitleaks](https://github.com/gitleaks/gitleaks). `2ms` is capable of finding secrets such as login credentials, API keys, SSH keys and more hidden in code, content systems, chat applications and more.

# Installation

## Download Precompiled Binaries

2ms precompiled binaries for amd64 architecture are attached as assets in our [releases page](https://github.com/Checkmarx/2ms/releases)

- [Download for Windows](https://github.com/checkmarx/2ms/releases/latest/download/windows-amd64.zip)
- [Download for MacOS](https://github.com/checkmarx/2ms/releases/latest/download/macos-amd64.zip)
- [Download for Linux](https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip)
- [Other](https://github.com/Checkmarx/2ms/releases)

### Install Globally

You may place the compiled binary on your path. On Linux for example you can place `2ms` binary in `/usr/local/bin/`

```
chmod +x 2ms
sudo cp 2ms /usr/local/bin/ 
```

## Compiling from source

If you wish to compile the project from its source use the following commands

```bash
git clone https://github.com/checkmarx/2ms.git
cd 2ms
go build -o dist/2ms main.go 
./dist/2ms
```

## Docker Container

We publish container image releases of `2ms` to [checkmarx/2ms](https://hub.docker.com/r/checkmarx/2ms) . To run `2ms` from a docker container use the following command:

```
docker run checkmarx/2ms 
```

You may also mount a local directory with the `-v <local-dir-path>:<container-dir-path>` argument. For instance:

```
docker run -v /home/user/workspace/git-repo:/repo checkmarx/2ms git /repo
```

- For `git` command, you have to mount your git repository to `/repo` inside the container

# Usage

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
      --config string           config file path
      --exclude-rule strings    exclude rules by name or tag to apply to the scan (removes from list, starts from all)
  -h, --help                    help for 2ms
      --ignore-result strings   ignore specific result by id
      --include-rule strings    include rules by name or tag to apply to the scan (adds to list, starts from empty)
      --log-level string        log level (trace, debug, info, warn, error, fatal) (default "info")
      --regex stringArray       custom regexes to apply to the scan, must be valid Go regex
      --report-path strings     path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)
      --stdout-format string    stdout output format, available formats are: json, yaml, sarif (default "yaml")
  -v, --version                 version for 2ms

Use "2ms [command] --help" for more information about a command.
```
<!-- command-line:end -->

## Plugins

We offer the following list of integrations in the form of plugins

### Confluence

scans a [Confluence](https://www.atlassian.com/software/confluence) instance

```
2ms confluence <URL> [flags]
```

| Flag         | Value  | Default                        | Description                                                                      |
|--------------|--------|--------------------------------|----------------------------------------------------------------------------------|
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

### Paligo

`<TBD Add Reference>`

### Discord

`<TBD Add Reference>`

### Slack

`<TBD Add Reference>`

### Git Repository
Scans a local git repository
```
2ms git <Git Repo Local Path> [flags]
```

| Flag             | Value | Default                                | Description                                              |
|------------------|-------|----------------------------------------|----------------------------------------------------------|
| `--all-branches` | -     | false - only current checked in branch | scan all branches                                        | 
| `--depth`        | int   | no limit                               | limit the number of historical commits to scan from HEAD |

For example

```
git clone https://github.com/my-account/my-repo.git
cd my-repo
2ms git .
```

### Local Directory

`<TBD Add Reference>`

## Contributing

`2ms` is extendable with the concept of plugins. We designed it like this so anyone can easily contribute, improve and extend `2ms`

## Contact

Want to report a problem or suggest an idea for improvement? Create an [Issue](https://github.com/Checkmarx/2ms/issues/new), create a [Discussion thread](https://github.com/Checkmarx/2ms/discussions), or Join our [Discord Server](https://discord.gg/9uFqFDWPyz) (seek for `#2ms` channel)

This project was made and maintained by Checkmarx with :heart:
