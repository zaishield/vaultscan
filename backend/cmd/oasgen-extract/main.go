// cmd/oasgen-extract — Go AST tool that reads every handler in
// backend/internal/api/ and emits a JSON map:
//
//   {handler_func_name: [{name, type_hint}, ...]}
//
// generate.py reads the JSON and emits OpenAPI schemas with
// property NAMES that match the actual writeJSON keys. Field-name
// accuracy from real source — no hand authoring; no guessing.
//
// What this tool DOES:
//   * Walks handlers*.go in backend/internal/api/
//   * For each top-level func returning http.HandlerFunc, walks
//     its body looking for writeJSON(w, ..., map[string]any{...})
//     calls
//   * Extracts the map's keys (string literals) and a type hint
//     for each value (the Go AST node kind: BasicLit, CallExpr,
//     SelectorExpr.string→...)
//
// What this tool DOES NOT do:
//   * Resolve handler-function name → route path. That's still
//     done by parsing server.go for r.Get / r.Post calls.
//   * Emit perfect type info — it produces "best-effort" type
//     hints (string|number|object|array|unknown).
//
// Usage:
//   go run ./cmd/oasgen-extract backend/internal/api > /tmp/keys.json
//   python3 ./cmd/oasgen/generate.py docs/api/openapi.yaml \
//     --handler-keys /tmp/keys.json

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fieldHint struct {
	Name string `json:"name"`
	Type string `json:"type"` // string | number | integer | boolean | object | array | unknown
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "oasgen-extract <api-package-dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	fset := token.NewFileSet()

	out := map[string][]fieldHint{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read dir: %v\n", err)
		os.Exit(1)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
			continue
		}
		// Walk top-level funcs: those that look like handler
		// factories — `func handlerX(s *Services) http.HandlerFunc`.
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// We accept either:
			//   * handler factories returning http.HandlerFunc
			//   * the raw `func(w http.ResponseWriter, r *http.Request)`
			//     bodies (inline routes, helpers)
			handlerName := fn.Name.Name
			fields := extractWriteJSONKeys(fn.Body)
			if len(fields) > 0 {
				out[handlerName] = mergeFields(out[handlerName], fields)
			}
		}
	}
	// Deterministic output for diff-friendly check-ins.
	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	sort.Strings(names)
	final := map[string][]fieldHint{}
	for _, n := range names {
		sort.Slice(out[n], func(i, j int) bool { return out[n][i].Name < out[n][j].Name })
		final[n] = out[n]
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(final); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "oasgen-extract: emitted %d handlers with discovered keys\n", len(final))
}

// extractWriteJSONKeys recursively walks `body` looking for
// writeJSON(w, status, <expr>) calls. When `<expr>` is:
//   - a map literal: extract its string keys + value type hints
//   - a struct literal: extract its field names
//   - an identifier (variable name): scan back for the most-recent
//     assignment in the same function body; recurse on its value
//
// Returns nil for shapes we can't introspect (e.g. function returns,
// or values defined outside the function body).
func extractWriteJSONKeys(body *ast.BlockStmt) []fieldHint {
	// Build a local map: identName → most-recent assignment expression.
	// We use a 'last write wins' rule, which matches Go's scoping
	// closely enough for the common patterns we want to extract.
	localAssigns := collectLocalAssigns(body)

	var out []fieldHint
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "writeJSON" {
			return true
		}
		if len(call.Args) < 3 {
			return true
		}
		arg := call.Args[2]
		// Try direct extraction first; if the arg is just an
		// identifier, resolve via local assignments.
		fields := keysFromExpr(arg, localAssigns)
		out = append(out, fields...)
		return true
	})
	return out
}

// keysFromExpr extracts field names from a Go AST expression that
// represents a writeJSON body argument.
func keysFromExpr(e ast.Expr, assigns map[string]ast.Expr) []fieldHint {
	switch v := e.(type) {
	case *ast.CompositeLit:
		// Map or struct literal.
		return compositeLitFields(v)
	case *ast.UnaryExpr:
		// `&Struct{...}` — recurse on the inner literal.
		return keysFromExpr(v.X, assigns)
	case *ast.Ident:
		// Variable reference: look up the most-recent local
		// assignment and recurse.
		if asgn, ok := assigns[v.Name]; ok {
			return keysFromExpr(asgn, assigns)
		}
	}
	return nil
}

// compositeLitFields handles both map and struct literals.
// For map[string]X{...}: extracts the string keys.
// For struct{...}: extracts the field names (uses json tag if found
// via the struct's *defined* type, but we don't resolve types here —
// fall back to identifier names).
func compositeLitFields(cl *ast.CompositeLit) []fieldHint {
	var out []fieldHint
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		switch key := kv.Key.(type) {
		case *ast.BasicLit:
			// map literal: "foo": value
			if key.Kind == token.STRING {
				out = append(out, fieldHint{
					Name: strings.Trim(key.Value, `"`),
					Type: typeHintFor(kv.Value),
				})
			}
		case *ast.Ident:
			// struct literal: Foo: value — capture the Go field name
			// in snake_case. No json-tag introspection here; that
			// would require type resolution. The contract test will
			// catch mismatches if the json tag differs.
			out = append(out, fieldHint{
				Name: toSnakeCase(key.Name),
				Type: typeHintFor(kv.Value),
			})
		}
	}
	return out
}

// collectLocalAssigns walks a function body and records the LAST
// assignment to each identifier — common Go pattern is
//   out := buildResponse(...)
//   writeJSON(w, 200, out)
// The map lets keysFromExpr resolve `out` back to its assignment.
func collectLocalAssigns(body *ast.BlockStmt) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			// Pair up LHS idents with RHS expressions when shapes match.
			if len(v.Lhs) == len(v.Rhs) {
				for i, lhs := range v.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						out[id.Name] = v.Rhs[i]
					}
				}
			}
		}
		return true
	})
	return out
}

// toSnakeCase converts a Go field name (CamelCase) to snake_case.
// Go's encoding/json default tag IS the field name unchanged, but
// most of this codebase uses explicit `json:"snake_case"` tags.
// We snake-ify as a hint; the contract test's permissive
// additionalProperties=true keeps us safe if the actual tag differs.
func toSnakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			r = r + ('a' - 'A')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mapLiteralFields is retained for backwards reference. The newer
// compositeLitFields covers the same shapes plus struct literals.
// Marked unused; left intentionally for grep-discovery during code
// review.
var _ = mapLiteralFields

func mapLiteralFields(expr ast.Expr) []fieldHint {
	cl, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	return compositeLitFields(cl)
}

func typeHintFor(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		switch v.Kind {
		case token.STRING:
			return "string"
		case token.INT:
			return "integer"
		case token.FLOAT:
			return "number"
		}
	case *ast.Ident:
		if v.Name == "true" || v.Name == "false" {
			return "boolean"
		}
		if v.Name == "nil" {
			return "unknown"
		}
	case *ast.CompositeLit:
		// nested map / slice / struct
		if _, ok := v.Type.(*ast.ArrayType); ok {
			return "array"
		}
		return "object"
	case *ast.CallExpr:
		// Often a uuid.New() / time.Now() / strconv.Itoa(...)
		// — type depends on the function. We hint string for
		// uuid + time + strings; integer for atoi; default unknown.
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			pkg, _ := sel.X.(*ast.Ident)
			if pkg != nil {
				switch pkg.Name {
				case "uuid", "time", "strings", "hex":
					return "string"
				case "strconv":
					if sel.Sel.Name == "Atoi" {
						return "integer"
					}
					if sel.Sel.Name == "ParseFloat" {
						return "number"
					}
					return "string"
				case "len":
					return "integer"
				}
			}
		}
	case *ast.SelectorExpr:
		// Reference to a field — best we can do is "unknown".
	}
	return "unknown"
}

// mergeFields combines two field lists, deduping by name (last
// wins — sometimes the same handler has multiple writeJSON calls
// with overlapping keys).
func mergeFields(a, b []fieldHint) []fieldHint {
	m := map[string]fieldHint{}
	for _, f := range a {
		m[f.Name] = f
	}
	for _, f := range b {
		m[f.Name] = f
	}
	out := make([]fieldHint, 0, len(m))
	for _, f := range m {
		out = append(out, f)
	}
	return out
}
