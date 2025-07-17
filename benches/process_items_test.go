package benches

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/v3/engine"
	"github.com/checkmarx/2ms/v3/internal/workerpool"
	"github.com/checkmarx/2ms/v3/lib/reporting"
	"github.com/checkmarx/2ms/v3/lib/secrets"
	"github.com/checkmarx/2ms/v3/plugins"
)

type mockItem struct {
	content *string
	id      string
	source  string
}

func (i *mockItem) GetContent() *string {
	return i.content
}

func (i *mockItem) GetID() string {
	return i.id
}

func (i *mockItem) GetSource() string {
	return i.source
}

func (i *mockItem) GetGitInfo() *plugins.GitInfo {
	return nil
}

// BenchmarkProcessItems benchmarks ProcessItems with realistic content that includes actual secrets
//
// Note: This benchmark will produce logging output because the worker pool logs at Info level.
// To run without log spam, put somewhere zerolog.SetGlobalLevel(zerolog.Disabled)
func BenchmarkProcessItems(b *testing.B) {
	nCPU := runtime.GOMAXPROCS(0)
	fmt.Println("nCPU", nCPU)
	workerSizes := []int{nCPU / 2, nCPU, nCPU * 2, nCPU * 4, nCPU * 8, nCPU * 16, nCPU * 32}
	itemSizes := []int{50, 100, 500, 1000, 10000}

	// Secret patterns that will trigger detection
	secretPatterns := []string{
		"github_pat_11ABCDEFG1234567890abcdefghijklmnopqrstuvwxyz123456",
		"sk-1234567890abcdefghijklmnopqrstuvwxyz",
		"ghp_abcdefghijklmnopqrstuvwxyz1234567890",
		"AIzaSyC1234567890abcdefghijklmnopqrstuv",
		"xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}

	// Content templates simulating different file types
	contentTemplates := []string{
		// JavaScript config file
		`const config = {
  apiKey: '%s',
  endpoint: 'https://api.example.com',
  timeout: 5000,
  retries: 3,
  debug: process.env.NODE_ENV === 'development'
};

module.exports = config;`,
		// Python script
		`import requests
import os

API_KEY = '%s'
BASE_URL = 'https://api.service.com/v1'

def make_request(endpoint):
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    return requests.get(f'{BASE_URL}/{endpoint}', headers=headers)

if __name__ == '__main__':
    response = make_request('users')
    print(response.json())`,
		// Shell script
		`#!/bin/bash

# Configuration
export API_TOKEN='%s'
export SERVICE_URL="https://service.example.com"
export ENVIRONMENT="production"

# Function to call API
call_api() {
    curl -H "Authorization: Bearer $API_TOKEN" \
         -H "Content-Type: application/json" \
         "$SERVICE_URL/api/$1"
}

# Main execution
call_api "status"`,
		// YAML config
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: postgresql://user:pass@localhost/db
  api_key: %s
  redis_url: redis://localhost:6379
  log_level: info`,
		// JSON config
		`{
  "name": "production-app",
  "version": "1.0.0",
  "config": {
    "api": {
      "key": "%s",
      "endpoint": "https://api.production.com",
      "timeout": 30000
    },
    "database": {
      "host": "db.production.com",
      "port": 5432
    }
  }
}`,
		// No secret - regular code
		`package utils

import (
    "fmt"
    "strings"
    "time"
)

func ProcessData(input string) (string, error) {
    if input == "" {
        return "", fmt.Errorf("input cannot be empty")
    }
    
    processed := strings.ToUpper(input)
    timestamp := time.Now().Format(time.RFC3339)
    
    return fmt.Sprintf("%s - %s", processed, timestamp), nil
}

func ValidateInput(data []byte) bool {
    return len(data) > 0 && len(data) < 1048576
}`,
	}

	for _, workers := range workerSizes {
		for _, items := range itemSizes {
			b.Run(fmt.Sprintf("realistic_workers_%d_items_%d", workers, items), func(b *testing.B) {
				// Pre-create realistic mock items
				mockItems := make([]*mockItem, items)
				for j := 0; j < items; j++ {
					var content string

					// 60% of files contain secrets, 40% don't
					if j%10 < 6 {
						// Select a random template and secret
						template := contentTemplates[j%len(contentTemplates)]
						secret := secretPatterns[j%len(secretPatterns)]
						content = fmt.Sprintf(template, secret)
					} else {
						// Use non-secret content
						content = contentTemplates[len(contentTemplates)-1]
					}

					// Add some padding to simulate larger files
					padding := generateRealisticPadding(j)
					content += padding

					mockItems[j] = &mockItem{
						content: &content,
						id:      fmt.Sprintf("file_%d", j),
						source:  fmt.Sprintf("/mock/path/file_%d.js", j),
					}
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Create engine for each iteration
					engineTest, err := engine.Init(&engine.EngineConfig{
						DetectorWorkerPoolSize: workers,
					})
					if err != nil {
						b.Fatal(err)
					}

					// Create fresh channels
					itemsChan := make(chan plugins.ISourceItem, items)
					secretsChan := make(chan *secrets.Secret, items*2) // Larger buffer for found secrets
					report := reporting.Init()
					wg := &sync.WaitGroup{}
					wg.Add(1)

					go func() {
						defer wg.Done()
						processItemsLocal(engineTest, "mockPlugin", itemsChan, secretsChan, report)
						engineTest.GetFileWalkerWorkerPool().Wait()
						close(secretsChan)
					}()

					// Send items
					for _, item := range mockItems {
						itemsChan <- item
					}
					close(itemsChan)

					wg.Wait()

					secretsFound := 0
					for range secretsChan {
						secretsFound++
					}

					_ = engineTest.Shutdown()
				}
			})
		}
	}
}

// generateRealisticPadding generates padding content to simulate realistic file sizes
func generateRealisticPadding(seed int) string {
	// Size categories: small (1KB), medium (10KB), large (50KB)
	sizes := []int{1024, 10240, 51200}
	sizeIndex := seed % len(sizes)
	targetSize := sizes[sizeIndex]

	// Common code patterns for padding
	patterns := []string{
		"\n\n// Helper functions\n",
		"function helper() { return true; }\n",
		"const data = { id: 1, name: 'test' };\n",
		"if (condition) { console.log('debug'); }\n",
		"// TODO: refactor this later\n",
		"/* eslint-disable no-unused-vars */\n",
		"import { util } from './utils';\n",
		"export default class Component {}\n",
	}

	var builder strings.Builder
	currentSize := 0
	patternIndex := 0

	for currentSize < targetSize {
		pattern := patterns[patternIndex%len(patterns)]
		builder.WriteString(pattern)
		currentSize += len(pattern)
		patternIndex++
	}

	return builder.String()
}

// Local version of processItems that doesn't use global variables
func processItemsLocal(eng engine.IEngine, pluginName string, items chan plugins.ISourceItem, secrets chan *secrets.Secret, report *reporting.Report) {
	ctx := context.Background()
	pool := eng.GetFileWalkerWorkerPool()

	for item := range items {
		report.TotalItemsScanned++

		var task workerpool.Task
		switch pluginName {
		case "filesystem":
			task = func(context.Context) error {
				return eng.DetectFile(ctx, item, secrets)
			}
		default:
			task = func(context.Context) error {
				return eng.DetectFragment(item, secrets, pluginName)
			}
		}

		if err := pool.Submit(task); err != nil {
			// Handle error appropriately
			break
		}
	}
	pool.CloseQueue()
}
