# 2MS
TODO fill in the gaps

### Command line arguments (wip)

- `--confluence` The URL of the Confluence instance to scan.
- `--confluence-spaces` A comma-separated list of Confluence spaces to scan.
- `--confluence-user` confluence username or email
- `--confluence-token` confluence token
- `--log-level` log level (trace, debug, info, warn, error, fatal) (default "info")


## Contributing
TODO @kaplan

### Run Linter
```bash
docker run --rm -v $(pwd):/app -w /app golangci/golangci-lint:v1.52.0 golangci-lint run -v -E gofmt --timeout=5m
```

### Run Unit Tests
```bash
go test ./...
```

### Run Benchmarks
```bash
go test -bench . -run NONE -cpuprofile=cpu.prof
go tool pprof -http:8080 cpu.prof
```
