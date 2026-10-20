package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// Read the checkout being compiled, rather than an older anqu-build binary's
// own version. Never execute a cross-compiled Agent to discover its version.
func sourceVersion(root string) (string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "cmd", "anqu", "main.go"), nil, 0)
	if err != nil {
		return "", err
	}
	for _, decl := range f.Decls {
		g, ok := decl.(*ast.GenDecl)
		if !ok || (g.Tok != token.CONST && g.Tok != token.VAR) {
			continue
		}
		for _, spec := range g.Specs {
			v, ok := spec.(*ast.ValueSpec)
			if !ok || len(v.Names) != 1 || v.Names[0].Name != "version" || len(v.Values) != 1 {
				continue
			}
			literal, ok := v.Values[0].(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err == nil && value != "" {
					return value, nil
				}
			}
		}
	}
	return "", errors.New("Agent source must declare a nonempty literal version for update metadata")
}

func executableManifest(path, version, goos, goarch string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, f)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(struct {
		Version string `json:"version"`
		GOOS    string `json:"goos"`
		GOARCH  string `json:"goarch"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size"`
	}{version, goos, goarch, hex.EncodeToString(hash.Sum(nil)), size}, "", "  ")
}
