# 2MS Benchmarks

## Build Tag Setup

These benchmarks are excluded from regular test runs using the `//go:build bench` build tag. This prevents the heavy benchmark setup (which creates 10,000 test files) from running during normal `go test` executions.

- **Regular tests**: `go test` (benchmarks won't run)
- **Run benchmarks**: Use the `-tags=bench` flag as shown below

## Process Items Benchmark

This benchmark (`BenchmarkProcessItems`) tests the performance of secret detection processing across different configurations.

### What it Tests

1. **Worker Pool Scaling**
   - Tests different worker pool sizes based on CPU count
   - Ranges from half the CPU count up to 32x CPU count
   - Example for 8-core machine: tests 4, 8, 16, 32, 64, 128, and 256 workers

2. **Input Load Testing**
   - Tests various input sizes: 50, 100, 500, 1000, and 10000 items

3. **Realistic Content**
   - Simulates different file types:
     - JavaScript configurations
     - Python scripts
     - Shell scripts
     - YAML configurations
     - JSON configurations
   - Includes actual secret patterns:
     - GitHub Personal Access Tokens
     - API keys
     - JWTs
   - Varies file sizes (1KB, 10KB, 50KB)
   - Maintains a 60/40 ratio of files with/without secrets

### Running the Benchmark

```bash
go test -tags=bench -timeout 0 -bench BenchmarkProcessItems -count 5 -run=^$
```

#### Command Flags Explained
- `-tags=bench`: Enables compilation of benchmark code (required due to build tag)
- `-timeout 0`: Disables test timeout (needed for long benchmarks)
- `-bench BenchmarkProcessItems`: Runs only this specific benchmark
- `-count 5`: Runs the benchmark 5 times for better statistical significance
- `-run=^$`: Skips regular tests (only runs benchmarks)
