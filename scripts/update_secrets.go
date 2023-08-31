package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

// Check if all the rules that exist in "gitleaks" are included in our list of rules (in secret.go file)
func main() {

	//Find the latest release of "gitleaks"
	release, err := fetchLatestRelease()
	if err != nil {
		fmt.Printf("Error fetching latest release: %s\n", err)
		return
	}

	// Import the rules from "gitleaks"
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/zricethezav/gitleaks/%s/cmd/generate/config/main.go", release.TagName)
	content, err := fetchRemoteContent(rawURL)
	if err != nil {
		fmt.Printf("Error fetching remote content: %s\n", err)
		return
	}
	reGitleaks := regexp.MustCompile(`configRules\s*=\s*append\(configRules,\s*rules\.([a-zA-Z0-9_]+)\(`)
	matchesGitleaks := reGitleaks.FindAllStringSubmatch(string(content), -1)

	//Import the rules from our project "2ms"
	localContent, err := fetchLocalContent("secrets/secrets.go")
	if err != nil {
		fmt.Printf("Error fetching local content: %s\n", err)
		return
	}
	reLocal := regexp.MustCompile(`allRules\s*=\s*append\(allRules,\s*Rule{Rule:\s*\*rules\.([a-zA-Z0-9_]+)\(\),`)
	matchLocal := reLocal.FindAllStringSubmatch(string(localContent), -1)

	//Insert the rules in map for good run time in search
	localRulesMap := make(map[string]bool)
	for _, match := range matchLocal {
		localRulesMap[match[1]] = true
	}

	// Compare the rules and check if missing rules in our list of rules
	missingInLocal := []string{}
	for _, rule := range matchesGitleaks {
		if _, found := localRulesMap[rule[1]]; !found {
			missingInLocal = append(missingInLocal, rule[1])
		}
	}

	if len(missingInLocal) > 0 {
		fmt.Printf("%d differences between our rules and the rules in the new version in 'gitleaks' were found: \n \n", len(missingInLocal))
		for index, rule := range missingInLocal {
			fmt.Printf("%d %s \n", index+1, rule)
		}
		os.Exit(1)
	} else {
		fmt.Printf("No differences found.")
		os.Exit(0)
	}
}

type Release struct {
	TagName string `json:"tag_name"`
}

func fetchLatestRelease() (Release, error) {
	var release Release

	resp, err := http.Get("https://api.github.com/repos/zricethezav/gitleaks/releases/latest")
	if err != nil {
		return release, fmt.Errorf("failed to get latest release: %w", err)
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&release); err != nil {
		return release, fmt.Errorf("failed to decode latest release JSON: %w", err)
	}

	return release, nil
}

func fetchRemoteContent(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote file: %w", err)
	}
	defer response.Body.Close()

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote file content: %w", err)
	}

	return content, nil
}

func fetchLocalContent(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return content, nil
}
