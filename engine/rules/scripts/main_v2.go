package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	inputDir := "./oldRules" // adjust as needed
	files, err := ioutil.ReadDir(inputDir)
	if err != nil {
		log.Fatalf("read dir: %v", err)
	}

	fset := token.NewFileSet()
	for _, fi := range files {
		if fi.IsDir() || !strings.HasSuffix(fi.Name(), ".go") {
			continue
		}
		path := filepath.Join(inputDir, fi.Name())
		astFile, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			log.Printf("parse %s: %v", path, err)
			continue
		}

		// Walk AST and find composite literals of type config.Rule
		ast.Inspect(astFile, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || cl.Type == nil {
				return true
			}

			// Expect Type == config.Rule (a SelectorExpr with X=ident "config", Sel=ident "Rule")
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

			// Now we have a config.Rule{ ... } composite literal
			var ruleID string
			var regexExpr string
			var desc string
			var keywords string

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
					// Usually a BasicLit string; but handle any expression
					if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						unq, err := unquote(bl.Value)
						if err == nil {
							ruleID = unq
						} else {
							ruleID = bl.Value
						}
					} else {
						ruleID = nodeSource(fset, kv.Value)
					}
				case "Regex":
					regexExpr = nodeSource(fset, kv.Value)
				case "Description":
					if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						unq, err := unquote(bl.Value)
						if err == nil {
							desc = fmt.Sprintf(`Description: "%s",`, unq)
						} else {
							desc = fmt.Sprintf("Description: %s,", nodeSource(fset, kv.Value))
						}
					} else {
						desc = fmt.Sprintf("Description: %s,", nodeSource(fset, kv.Value))
					}
				case "Keywords":
					// keep the entire RHS as source (e.g., []string{"a", "b"})
					keywords = fmt.Sprintf("Keywords: %s,", nodeSource(fset, kv.Value))
				}
			}

			fmt.Printf("File: %s\n", path)
			fmt.Printf("  RuleID: %s\n", ruleID)
			fmt.Printf("  Regex : %s\n", regexExpr)
			fmt.Printf("  %s\n", desc)
			fmt.Printf("  %s\n", keywords)
			fmt.Println("----")
			return true
		})
	}
}

func unquote(s string) (string, error) {
	// s is like "\"text\"" (a Go string literal). Use strconv.Unquote if needed.
	return strconvUnquote(s)
}

// small wrapper for strconv.Unquote with fallback
func strconvUnquote(s string) (string, error) {
	// avoid importing strconv at top; implement here:
	// but we'll import strconv: easier — below I'll add the import
	return strconv.Unquote(s)
}
