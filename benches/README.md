# 2MS Benchmarks

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
go test -timeout 0 -bench BenchmarkProcessItems -count 5 -run=^$
```

#### Command Flags Explained
- `-timeout 0`: Disables test timeout (needed for long benchmarks)
- `-bench BenchmarkProcessItems`: Runs only this specific benchmark
- `-count 5`: Runs the benchmark 5 times for better statistical significance
- `-run=^$`: Skips regular tests (only runs benchmarks)