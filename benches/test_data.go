package benches

// SecretPatterns contains realistic secret patterns that will trigger detection
var SecretPatterns = []string{
	"github_pat_11ABCDEFG1234567890abcdefghijklmnopqrstuvwxyz123456",
	"sk-1234567890abcdefghijklmnopqrstuvwxyz",
	"ghp_abcdefghijklmnopqrstuvwxyz1234567890",
	"AIzaSyC1234567890abcdefghijklmnopqrstuv",
	"xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", //nolint:lll
}

// ContentTemplates contains realistic file content templates simulating different file types
// Templates 0-4 contain secrets, template 5 is clean code
var ContentTemplates = []string{
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

	// No secret - regular Go code
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

// FileExtensions maps content template indices to appropriate file extensions
var FileExtensions = []string{
	".js",   // JavaScript config
	".py",   // Python script
	".sh",   // Shell script
	".yml",  // YAML config
	".json", // JSON config
	".go",   // Go code (no secret)
}

// PaddingPatterns contains common code patterns used for generating realistic file padding
var PaddingPatterns = []string{
	"\n\n// Helper functions\n",
	"function helper() { return true; }\n",
	"const data = { id: 1, name: 'test' };\n",
	"if (condition) { console.log('debug'); }\n",
	"// TODO: refactor this later\n",
	"/* eslint-disable no-unused-vars */\n",
	"import { util } from './utils';\n",
	"export default class Component {}\n",
}
