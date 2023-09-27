// Scripts to check if all the rules that exist in the latest version of "gitleaks" are included in our list of rules (in secret.go file)
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

var (
	regexGitleaksRules = regexp.MustCompile(`configRules\s*=\s*append\(configRules,\s*rules\.([a-zA-Z0-9_]+)\(`)
	regex2msRules      = regexp.MustCompile(`allRules\s*=\s*append\(allRules,\s*Rule{Rule:\s*\*rules\.([a-zA-Z0-9_]+)\(\),`)
)

func main() {

	latestGitleaksRelease, err := fetchGitleaksLatestRelease()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	gitleaksRules, err := fetchGitleaksRules(latestGitleaksRelease)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	matchesGitleaksRules := regexGitleaksRules.FindAllStringSubmatch(string(gitleaksRules), -1)

	ourRules, err := fetchOurRules()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	match2msRules := regex2msRules.FindAllStringSubmatch(string(ourRules), -1)

	map2msRules := make(map[string]bool)
	for _, match := range match2msRules {
		map2msRules[match[1]] = true
	}

	missingRulesIn2ms := []string{}
	for _, rule := range matchesGitleaksRules {
		if _, found := map2msRules[rule[1]]; !found {
			missingRulesIn2ms = append(missingRulesIn2ms, rule[1])
		}
	}

	if len(missingRulesIn2ms) > 0 {
		fmt.Printf("%d rules exist in the latest version of Gitleaks but missing on 2ms: \n\n", len(missingRulesIn2ms))
		for _, rule := range missingRulesIn2ms {
			fmt.Printf("%s \n", rule)
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

func fetchGitleaksRules(version string) ([]byte, error) {
	rawURLGitleaksRules := fmt.Sprintf("https://raw.githubusercontent.com/zricethezav/gitleaks/%s/cmd/generate/config/main.go", version)
	response, err := http.Get(rawURLGitleaksRules)
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

func fetchOurRules() ([]byte, error) {
	content, err := os.ReadFile("secrets/rules/rules.go")
	if err != nil {
		return nil, fmt.Errorf("failed to read our file content: %w", err)
	}
	return content, nil
}
