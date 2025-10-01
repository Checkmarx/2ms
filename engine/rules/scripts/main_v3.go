package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func main() {
	inputDir := "oldRules" // folder with original rules
	outputDir := "output"  // folder for generated rules

	// runtime.Caller(0) returns info about the current file (main_v3.go)
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("Cannot get current file info")
	}

	// Get the directory where this file is located
	currentDir := filepath.Dir(currentFile)

	inputDir = filepath.Join(currentDir, inputDir)
	outputDir = filepath.Join(currentDir, outputDir)

	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		log.Fatalf("creating output dir: %v", err)
	}

	files, err := ioutil.ReadDir(inputDir)
	if err != nil {
		log.Fatalf("reading input dir: %v", err)
	}

	fset := token.NewFileSet()

	for _, fi := range files {
		if fi.IsDir() || !strings.HasSuffix(fi.Name(), ".go") {
			continue
		}

		path := filepath.Join(inputDir, fi.Name())
		astFile, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			log.Printf("❌ parse %s: %v", path, err)
			continue
		}
		previousFileName := ""
		// Find all config.Rule{...}
		ast.Inspect(astFile, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || cl.Type == nil {
				return true
			}

			se, ok := cl.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			xIdent, ok := se.X.(*ast.Ident)
			if !ok {
				return true
			}
			if xIdent.Name != "config" || se.Sel.Name != "Rule" {
				return true
			}

			// We found a config.Rule{...}
			var ruleID, regexExpr, descLine, keywordsLine, entropyLine, pathLine string

			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				keyIdent, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}

				switch keyIdent.Name {
				case "RuleID":
					ruleID = literalOrSource(fset, kv.Value)
				case "Regex":
					regexExpr = nodeSource(fset, kv.Value)
				case "Description":
					descLine = fmt.Sprintf("Description: %s,", nodeSource(fset, kv.Value))
				case "Keywords":
					keywordsLine = fmt.Sprintf("Keywords: %s,", nodeSource(fset, kv.Value))
				case "Entropy":
					entropyLine = fmt.Sprintf("Entropy: %s,", nodeSource(fset, kv.Value))
				case "Path":
					pathLine = fmt.Sprintf("Path: %s,", nodeSource(fset, kv.Value))
				}

			}

			if ruleID == "" {
				fmt.Printf("⚠️  No RuleID found in %s\n", path)
				return true
			}

			ruleIDStr, _ := strconv.Unquote(ruleID)
			funcName := toCamel(ruleIDStr)
			fileName := ""
			if fi.Name() == previousFileName {
				fileName = fmt.Sprintf("%s.go", strings.ToLower(strings.ReplaceAll(ruleIDStr, "-", "_")))
			} else {
				fileName = fi.Name()
			}
			outputPath := filepath.Join(outputDir, fileName)

			previousFileName = fi.Name()

			if regexExpr == "" {
				regexExpr = "nil"
			}

			// Create a new uuid4
			baseRuleID := uuid.New()

			newContent := fmt.Sprintf(`package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var %sRegex = %s

func %s() *NewRule {
	return &NewRule{
		BaseRuleID: "%s",
		%s
		RuleID: %s,
		Regex: %sRegex,%s
		%s%s
		Severity: "High",
	}
}
`, funcName, regexExpr, funcName, baseRuleID, descLine, ruleID, funcName, conditionalLine(entropyLine), keywordsLine, conditionalLine(pathLine))

			err = ioutil.WriteFile(outputPath, []byte(newContent), 0644)
			if err != nil {
				log.Fatalf("writing file %s: %v", outputPath, err)
			}

			fmt.Println("✅ Created:", outputPath)

			newContentTest := fmt.Sprintf(`package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test%s(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "%s validation",
			truePositives: []string{},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%%q,\n", s) // %%q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%%q,\n", s) // %%q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(%s())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %%s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %%s", falsePositive))
			}
		})
	}
}`, funcName, strings.TrimSuffix(funcName, "()"), funcName)

			testOutputPath := strings.TrimSuffix(outputPath, ".go") + "_test.go"
			// write an empty test file
			err = ioutil.WriteFile(testOutputPath, []byte(newContentTest), 0644)
			if err != nil {
				log.Fatalf("writing file %s: %v", outputPath, err)
			}

			return true
		})
	}
}

//
// --- Helper functions ---
//

// Returns Go source of an AST node
func nodeSource(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, n)
	return buf.String()
}

// Returns string literal value or the source code
func literalOrSource(fset *token.FileSet, n ast.Node) string {
	if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
		return bl.Value // keeps quotes
	}
	return nodeSource(fset, n)
}

func toCamel(s string) string {
	// List of known acronyms to keep in all caps
	acronyms := map[string]bool{
		"api": true,
		"pat": true,
		"id":  true,
	}

	parts := strings.Split(s, "-")
	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		lower := strings.ToLower(p)
		if acronyms[lower] {
			parts[i] = strings.ToUpper(p) // make the whole acronym uppercase
		} else {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

func conditionalLine(line string) string {
	if line == "" {
		return ""
	}
	return "\n\t\t" + line
}
