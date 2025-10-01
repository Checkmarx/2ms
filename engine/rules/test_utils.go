package rules

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// UpdateTestFileSlices replaces the RHS of any `truePositives:` and `falsePositives:`
// key/value in the caller's Go source file with an explicit []string literal built
// from the provided slices. Call this from inside your test (so runtime.Caller(1) finds it).
func UpdateTestFileSlices(truePos []string, falsePos []string) error {
	// Get the calling file (the test file that invoked this function)
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("could not determine caller file")
	}

	src, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file %s: %w", filename, err)
	}

	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse %s: %w", filename, err)
	}

	// Helper to build a []string composite literal AST node
	buildStringSliceLit := func(vals []string) ast.Expr {
		if len(vals) == 0 {
			// Return empty slice
			return &ast.CompositeLit{
				Type: &ast.ArrayType{Elt: &ast.Ident{Name: "string"}},
				Elts: []ast.Expr{},
			}
		}

		elts := make([]ast.Expr, 0, len(vals))
		for _, s := range vals {
			// Each string as a BasicLit, with trailing comma handled by CompositeLit
			elts = append(elts, &ast.BasicLit{
				Kind:  token.STRING,
				Value: strconv.Quote(s),
			})
		}

		// Multi-line slice literal with elts separated by newlines
		return &ast.CompositeLit{
			Type: &ast.ArrayType{
				Elt: &ast.Ident{Name: "string"},
			},
			Elts:       elts,
			Incomplete: true, // forces multi-line formatting
		}
	}

	// Inspect AST and replace KeyValueExpr values for the target keys
	ast.Inspect(astFile, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}

		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}

		switch ident.Name {
		case "truePositives":
			kv.Value = buildStringSliceLit(truePos)
		case "falsePositives":
			kv.Value = buildStringSliceLit(falsePos)
		}
		return true
	})

	// Print AST back to source
	var printed bytes.Buffer
	cfg := &printer.Config{Mode: printer.TabIndent | printer.UseSpaces, Tabwidth: 8}
	if err := cfg.Fprint(&printed, fset, astFile); err != nil {
		return fmt.Errorf("print ast: %w", err)
	}

	// gofmt the result
	formatted, err := format.Source(printed.Bytes())
	if err != nil {
		// If gofmt fails, still write the unformatted AST output (but report the error)
		if writeErr := os.WriteFile(filename, printed.Bytes(), 0644); writeErr != nil {
			return fmt.Errorf("gofmt failed: %v, write failed: %v", err, writeErr)
		}
		return fmt.Errorf("gofmt failed, wrote unformatted output: %w", err)
	}

	// Write formatted source back to file
	if err := os.WriteFile(filename, formatted, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// UpdateTestFileSecretsWithAST updates truePositives and falsePositives slices
// using AST parsing (no regex) and writes back formatted code.
func UpdateTestFileSecretsWithAST(truePositives, falsePositives []string) error {
	// Get the calling file (the test file that invoked this function)
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("could not determine caller file")
	}

	src, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file %s: %w", filename, err)
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	// Build slice expression with multiline formatting
	buildStringSlice := func(values []string) *ast.CompositeLit {
		elts := []ast.Expr{}
		for _, v := range values {
			elts = append(elts, &ast.BasicLit{
				Kind:  token.STRING,
				Value: fmt.Sprintf("%q", v),
			})
		}
		return &ast.CompositeLit{
			Type: &ast.ArrayType{
				Elt: &ast.Ident{Name: "string"},
			},
			Elts: elts,
		}
	}

	// Walk the AST to find truePositives / falsePositives assignments
	ast.Inspect(node, func(n ast.Node) bool {
		assign, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}

		keyIdent, ok := assign.Key.(*ast.Ident)
		if !ok {
			return true
		}

		switch keyIdent.Name {
		case "truePositives":
			assign.Value = buildStringSlice(truePositives)
		case "falsePositives":
			assign.Value = buildStringSlice(falsePositives)
		}
		return true
	})

	// Write formatted output with multi-line slice formatting
	var buf bytes.Buffer
	cfg := printer.Config{
		Mode:     printer.TabIndent | printer.UseSpaces,
		Tabwidth: 4,
	}
	if err := cfg.Fprint(&buf, fset, node); err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	formatted := formatMultilineSlices(buf.String())

	// Write back
	if err := os.WriteFile(filename, []byte(formatted), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// formatMultilineSlices indents string slices to one value per line.
func formatMultilineSlices(code string) string {
	lines := strings.Split(code, "\n")
	var result []string

	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[]string{") && !strings.Contains(trim, "\n") {
			// start block
			result = append(result, strings.Replace(line, "[]string{", "[]string{", 1))
			continue
		}
		// Split inline slice values like []string{"a", "b"} into new lines
		if strings.Contains(trim, "[]string{") && strings.Contains(trim, ",") && strings.Contains(trim, "\"") {
			prefix := line[:strings.Index(line, "[]string{")+len("[]string{")]
			itemsBlock := line[strings.Index(line, "{")+1 : strings.LastIndex(line, "}")]
			items := strings.Split(itemsBlock, ",")
			result = append(result, prefix)
			for _, item := range items {
				val := strings.TrimSpace(item)
				if val != "" {
					result = append(result, fmt.Sprintf("\t\t%s,", val))
				}
			}
			result = append(result, "\t}")
			continue
		}
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func UpdateTestFileSecrets(truePositives, falsePositives []string) error {
	// Get the calling file (the test file that invoked this function)
	_, filePath, _, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("could not determine caller file")
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	content := string(contentBytes)

	// Format slice values into properly indented multi-line Go syntax
	formatSlice := func(values []string) string {
		if len(values) == 0 {
			return "[]string{}"
		}
		var b strings.Builder
		b.WriteString("[]string{\n")
		for _, v := range values {
			b.WriteString(fmt.Sprintf("\t\t%q,\n", v))
		}
		b.WriteString("\t}")
		return b.String()
	}

	truePositivesBlock := formatSlice(truePositives)
	falsePositivesBlock := formatSlice(falsePositives)

	// Regex to find truePositives and falsePositives assignments
	truePositivesRegex := regexp.MustCompile(`(?m)truePositives:\s*\[\]string\s*{[^}]*},?`)
	falsePositivesRegex := regexp.MustCompile(`(?m)falsePositives:\s*\[\]string\s*{[^}]*},?`)

	content = truePositivesRegex.ReplaceAllString(content, "truePositives: "+truePositivesBlock+",")
	content = falsePositivesRegex.ReplaceAllString(content, "falsePositives: "+falsePositivesBlock+",")

	// Write back to file
	err = os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
