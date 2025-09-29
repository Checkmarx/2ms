package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

func main() {
	inputDir := "./oldRules"
	outputDir := "./output"

	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		panic(err)
	}

	files, err := ioutil.ReadDir(inputDir)
	if err != nil {
		panic(err)
	}

	// Regex to match Rule definitions
	ruleBlockRe := regexp.MustCompile(`config\.Rule\s*{([^}]*)}`)
	ruleIDRe := regexp.MustCompile(`RuleID:\s*"([^"]+)"`)
	regexLineRe := regexp.MustCompile(`Regex:\s*(utils\.[^,]+),?`)

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") {
			continue
		}

		path := filepath.Join(inputDir, file.Name())
		contentBytes, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}
		content := string(contentBytes)

		matches := ruleBlockRe.FindAllStringSubmatch(content, -1)
		if len(matches) == 0 {
			fmt.Println("No rules found in", file.Name())
			continue
		}

		for _, match := range matches {
			block := match[1]
			ruleIDMatch := ruleIDRe.FindStringSubmatch(block)
			regexMatch := regexLineRe.FindStringSubmatch(block)

			if len(ruleIDMatch) < 2 {
				fmt.Println("No RuleID found in block in", file.Name())
				continue
			}

			ruleID := ruleIDMatch[1]
			regexExpr := "nil"
			if len(regexMatch) >= 2 {
				regexExpr = regexMatch[1]
			}

			descLine := extractLine(block, "Description:")
			keywordsLine := extractLine(block, "Keywords:")

			funcName := toCamel(ruleID)
			filename := fmt.Sprintf("%s.go", strings.ToLower(strings.ReplaceAll(ruleID, "-", "_")))
			outputPath := filepath.Join(outputDir, filename)

			newContent := fmt.Sprintf(`package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var %sRegex = %s

func %s() *NewRule {
	return &NewRule{
		%s
		RuleID: "%s",
		Regex: %sRegex,
		%s
	}
}
`, funcName, regexExpr, funcName, descLine, ruleID, funcName, keywordsLine)

			err := ioutil.WriteFile(outputPath, []byte(newContent), 0644)
			if err != nil {
				panic(err)
			}
			fmt.Println("✅ Created:", outputPath)
		}
	}
}

// Extracts a line starting with a key (e.g. "Description:") and trims it
func extractLine(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			return line
		}
	}
	return ""
}

//// Converts "airtable-api-key" → "AirtableApiKey"
//func toCamel(s string) string {
//	parts := strings.Split(s, "-")
//	for i, p := range parts {
//		if len(p) > 0 {
//			parts[i] = strings.ToUpper(p[:1]) + p[1:]
//		}
//	}
//	return strings.Join(parts, "")
//}
