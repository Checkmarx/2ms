package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

//Scripts to Check if all the rules that exist in
// the latest version "gitleaks" are included in our list of rules (in secret.go file)

func main() {

	latestGitleaksRelease, err := fetchGitleaksLatestRelease()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	rawURLGitleaksrules := fmt.Sprintf("https://raw.githubusercontent.com/zricethezav/gitleaks/%s/cmd/generate/config/main.go", latestGitleaksRelease)
	gitleaksRules, err := fetchGitleaksRules(rawURLGitleaksrules)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	regexGitleaksRules := regexp.MustCompile(`configRules\s*=\s*append\(configRules,\s*rules\.([a-zA-Z0-9_]+)\(`)
	matchesGitleaksRules := regexGitleaksRules.FindAllStringSubmatch(string(gitleaksRules), -1)

	ourRules, err := fetchOurRules("secrets/secrets.go")
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	regexOurRules := regexp.MustCompile(`allRules\s*=\s*append\(allRules,\s*Rule{Rule:\s*\*rules\.([a-zA-Z0-9_]+)\(\),`)
	matchOurRules := regexOurRules.FindAllStringSubmatch(string(ourRules), -1)

	MapOurRules := make(map[string]bool)
	for _, match := range matchOurRules {
		MapOurRules[match[1]] = true
	}

	missingRules := []string{}
	for _, rule := range matchesGitleaksRules {
		if _, found := MapOurRules[rule[1]]; !found {
			missingRules = append(missingRules, rule[1])
		}
	}

	if len(missingRules) > 0 {
		fmt.Printf("%d differences between our rules and the rules in the new version in 'gitleaks' were found: \n\n", len(missingRules))
		for index, rule := range missingRules {
			fmt.Printf("%d %s \n", index+1, rule)
		}

		fmt.Printf("\nLink to Gitleaks main.go file of version: %s:\n", latestGitleaksRelease)
		fmt.Printf("https://raw.githubusercontent.com/zricethezav/gitleaks/%s/cmd/generate/config/main.go\n\n", latestGitleaksRelease)

		os.Exit(1)
	} else {
		fmt.Printf("No differences found.")
		os.Exit(0)
	}
}

type Release struct {
	TagName string `json:"tag_name"`
}

func fetchGitleaksLatestRelease() (string, error) {
	var release Release

	response, err := http.Get("https://api.github.com/repos/zricethezav/gitleaks/releases/latest")
	if err != nil {
		return "", fmt.Errorf("failed to get latest release: %w", err)
	}
	defer response.Body.Close()

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode latest release JSON: %w", err)
	}

	return release.TagName, nil
}

func fetchGitleaksRules(url string) ([]byte, error) {
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

func fetchOurRules(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read our file content: %w", err)
	}
	return content, nil
}
