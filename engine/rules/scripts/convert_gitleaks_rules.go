package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/ioutil" //nolint:staticcheck
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/iancoleman/strcase"
)

// This script converts gitleaks v8 rules to the new format used in 2ms.
// It is not a perfect script and could be improved significantly.
// Rules to be converted need to be in their own folder
// If a file contains multiple rules, each rule will be saved in its file.
//
//	The name of the first file will be the same as the name of the original,
//	with the remaining files being named after their specific rule. this could be improved
//
// Test files are generated, but they don't have the tps and fps filled out
func main() { //nolint:gocyclo,funlen
	inputDir := "old_rules" // folder with original rules
	outputDir := "output"   // folder for generated rules

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
		currentFuncName := ""
		// Find all config.Rule{...}
		ast.Inspect(astFile, func(n ast.Node) bool {
			switch node := n.(type) {
			// Capture the current function name
			case *ast.FuncDecl:
				if node.Name != nil {
					currentFuncName = node.Name.Name
				}
				return true

			// Look for config.Rule composite literals
			case *ast.CompositeLit:

				se, ok := node.Type.(*ast.SelectorExpr)
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
				var RuleName, regexExpr, descLine, keywordsLine, entropyLine, pathLine string

				for _, elt := range node.Elts {
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
						RuleName = literalOrSource(fset, kv.Value)
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

				if RuleName == "" {
					fmt.Printf("⚠️  No RuleName found in %s\n", path)
					return true
				}

				fileName := ""
				if fi.Name() == previousFileName {
					fileName = toSnakeWithAcronyms(currentFuncName)
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
		RuleID: "%s",
		%s
		RuleName: %s,
		Regex: %sRegex,%s
		%s%s
		Severity: "High",
	}
}
`, currentFuncName, regexExpr, currentFuncName, baseRuleID, descLine,
					RuleName, currentFuncName, conditionalLine(entropyLine), keywordsLine, conditionalLine(pathLine))

				err = ioutil.WriteFile(outputPath, []byte(newContent), 0600)
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
}`, currentFuncName, strings.TrimSuffix(currentFuncName, "()"), currentFuncName)

				testOutputPath := strings.TrimSuffix(outputPath, ".go") + "_test.go"
				// write an empty test file
				err = ioutil.WriteFile(testOutputPath, []byte(newContentTest), 0600)
				if err != nil {
					log.Fatalf("writing file %s: %v", outputPath, err)
				}
				return true
			}
			return true
		})
	}
}

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

func toSnakeWithAcronyms(name string) string {
	// Handle common acronyms first
	acronyms := []string{"API", "ID", "PAT", "OAuth"}
	for _, ac := range acronyms {
		// Replace acronym with placeholder to preserve boundaries
		name = strings.ReplaceAll(name, ac, strings.ToTitle(strings.ToLower(ac)))
	}
	snake := strcase.ToSnake(name)
	return strings.Trim(snake, "_") + ".go"
}

func conditionalLine(line string) string {
	if line == "" {
		return ""
	}
	return "\n\t\t" + line
}
