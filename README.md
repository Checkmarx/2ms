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
- Git
- Paligo
- Local directory / files
  
## Getting 2ms

```
# git clone https://github.com/Checkmarx/2ms.git
# cd 2ms
# go build
# ./2ms (linux / mac)
```

### Docker

```
docker run -v path/to/my/repo:/repo checkmarx/2ms git /repo
```

(For `git` command, you have to mount your git repository to `/repo` inside the container)

## Getting started

### Command line arguments (wip, see [#20](https://github.com/Checkmarx/2ms/discussions/20))

- `--confluence` The URL of the Confluence instance to scan.
- `--confluence-spaces` A comma-separated list of Confluence spaces to scan.
- `--confluence-username` confluence username or email
- `--confluence-token` confluence token

---

Made by Checkmarx with :heart:
