# Welcome to the 2ms club!

> [!NOTE]  
> This is the first version of the document, we will rewrite it on the fly.

## Test

Along with the regular unit tests, we also have a set of other tests:

- `tests/cli` - e2e tests that build the CLI, run it, and check the output.  
  To skip these tests, run `go test -short ./...`.
- `tests/lint` - linter, to verify we are not using our forbidden functions (for example, using `fmt.Print` instead of `log.Info`)
- `.ci/check_new_rules.go` - compares the list of rules in the [latest _gitleaks_ release](https://github.com/gitleaks/gitleaks/releases/latest) with our list of rules, and fails if there are rules in the release that are not in our list.
- `.ci/update-readme.sh` - auto update the `help` message in the [README.md](README.md#command-line-interface) file.
