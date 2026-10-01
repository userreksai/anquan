// anqu-build reads YAML on the build machine and embeds only encrypted bytes
// into a standalone agent. The encryption key is necessarily in that agent too:
// this raises extraction cost, but cannot promise protection from its owner.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"anqu/internal/audit"
	"anqu/internal/sealed"
)

const maxConfigBytes = 4 << 20

type options struct {
	config, output, goos, goarch, goCommand string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "build failed:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	var opts options
	flags := flag.NewFlagSet("anqu-build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.config, "config", "config.yaml", "YAML file on the build machine (relative to current directory)")
	flags.StringVar(&opts.output, "output", "", "agent output file (default ./anqu, or ./anqu.exe for windows)")
	flags.StringVar(&opts.goos, "goos", "linux", "target operating system")
	flags.StringVar(&opts.goarch, "goarch", runtime.GOARCH, "target architecture, for example amd64 or arm64")
	flags.StringVar(&opts.goCommand, "go", "go", "Go compiler command or path")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if opts.output == "" {
		opts.output = "anqu"
		if opts.goos == "windows" {
			opts.output += ".exe"
		}
	}
	if err := build(opts, stdout, stderr); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "agent=%s target=%s/%s\n", opts.output, opts.goos, opts.goarch)
	fmt.Fprintln(stdout, "Configuration embedded; deploy only the agent executable.")
	fmt.Fprintln(stdout, "Embedded encryption increases extraction cost; administrators and reverse engineers can still recover it.")
	return nil
}

func readYAML(path string) ([]byte, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return nil, errors.New("configuration must use .yaml or .yml; JSON configuration is unsupported")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open build configuration: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("build configuration must be a regular file")
	}
	if info.Size() > maxConfigBytes {
		return nil, errors.New("build configuration exceeds 4 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read build configuration: %w", err)
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("build configuration exceeds 4 MiB")
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(trimmed) == 0 {
		return nil, errors.New("build configuration is empty")
	}
	if json.Valid(trimmed) {
		return nil, errors.New("JSON configuration is unsupported; use a YAML mapping")
	}
	return data, nil
}

func build(opts options, stdout, stderr io.Writer) error {
	data, err := readYAML(opts.config)
	if err != nil {
		return err
	}
	if err := audit.ValidateEmbeddedYAML(data, opts.goos); err != nil {
		return fmt.Errorf("validate embedded YAML: %w", err)
	}
	defer clear(data)
	root, err := projectRoot()
	if err != nil {
		return err
	}
	compiler, err := exec.LookPath(opts.goCommand)
	if err != nil {
		return fmt.Errorf("find Go compiler: %w", err)
	}
	compiler, err = filepath.Abs(compiler)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(opts.output)
	if err != nil {
		return err
	}
	if err := protectConfigOutput(opts.config, output); err != nil {
		return err
	}

	// All generated source and configuration-bearing build cache entries stay
	// in this private temporary tree, never in source or the user's Go cache.
	work, err := os.MkdirTemp("", "anqu-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := os.Chmod(work, 0700); err != nil {
		return err
	}
	for _, name := range []string{"cache", "tmp"} {
		if err := os.Mkdir(filepath.Join(work, name), 0700); err != nil {
			return err
		}
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate encryption key: %w", err)
	}
	ciphertext, err := sealed.Seal(key, data, []byte(sealed.ConfigAAD))
	if err != nil {
		return err
	}
	payloadPath := filepath.Join(work, "payload.go")
	if err := os.WriteFile(payloadPath, payloadSource(key, ciphertext), 0600); err != nil {
		return err
	}
	overlay := struct {
		Replace map[string]string
	}{Replace: map[string]string{filepath.Join(root, "internal", "sealed", "payload.go"): payloadPath}}
	overlayData, err := json.Marshal(overlay)
	if err != nil {
		return err
	}
	overlayPath := filepath.Join(work, "overlay.json")
	if err := os.WriteFile(overlayPath, overlayData, 0600); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	staging, err := os.CreateTemp(filepath.Dir(output), ".anqu-output-*")
	if err != nil {
		return err
	}
	stagePath := staging.Name()
	defer os.Remove(stagePath)
	if err := staging.Close(); err != nil {
		return err
	}
	cmd := exec.Command(compiler, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-overlay", overlayPath, "-o", stagePath, "./cmd/anqu")
	cmd.Dir = root
	cmd.Env = buildEnv(os.Environ(), map[string]string{
		"CGO_ENABLED": "0", "GOOS": opts.goos, "GOARCH": opts.goarch,
		"GOCACHE": filepath.Join(work, "cache"), "GOTMPDIR": filepath.Join(work, "tmp"),
		"GOWORK": "off", "GOFLAGS": "", "GOENV": "off", "GOCACHEPROG": "",
	})
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compile agent: %w", err)
	}
	info, err := os.Stat(stagePath)
	if err != nil || info.Size() == 0 {
		return errors.New("compiler did not produce a nonempty agent executable")
	}
	if err := os.Chmod(stagePath, 0700); err != nil {
		return err
	}
	// The staging file shares the destination filesystem. A failed build never
	// opens or truncates a previously deployed executable.
	if err := os.Rename(stagePath, output); err != nil {
		return fmt.Errorf("replace agent executable: %w", err)
	}
	return nil
}

func payloadSource(key, ciphertext []byte) []byte {
	return []byte(fmt.Sprintf("package sealed\n\nfunc embeddedPayload() (key, ciphertext []byte) {\nreturn %#v, %#v\n}\n", key, ciphertext))
}

func protectConfigOutput(config, output string) error {
	configAbs, err := filepath.Abs(config)
	if err != nil {
		return err
	}
	if configAbs == output || (runtime.GOOS == "windows" && strings.EqualFold(configAbs, output)) {
		return errors.New("output must not overwrite the build configuration")
	}
	cfgInfo, cfgErr := os.Stat(config)
	outInfo, outErr := os.Stat(output)
	if cfgErr == nil && outErr == nil && os.SameFile(cfgInfo, outInfo) {
		return errors.New("output must not overwrite the build configuration")
	}
	return nil
}

func buildEnv(in []string, replacements map[string]string) []string {
	out := make([]string, 0, len(in)+len(replacements))
	for _, item := range in {
		name, _, _ := strings.Cut(item, "=")
		if _, replace := replacements[strings.ToUpper(name)]; !replace {
			out = append(out, item)
		}
	}
	for key, value := range replacements {
		out = append(out, key+"="+value)
	}
	return out
}

func projectRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	candidates := []string{cwd}
	if _, source, _, ok := runtime.Caller(0); ok && filepath.IsAbs(source) {
		candidates = append(candidates, filepath.Dir(source))
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(executable))
	}
	for _, start := range candidates {
		for dir := start; ; dir = filepath.Dir(dir) {
			mod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
			fields := strings.Fields(string(mod))
			if err == nil && len(fields) >= 2 && fields[0] == "module" && fields[1] == "anqu" {
				if _, err := os.Stat(filepath.Join(dir, "cmd", "anqu", "main.go")); err == nil {
					if _, err := os.Stat(filepath.Join(dir, "internal", "sealed", "payload.go")); err == nil {
						return dir, nil
					}
				}
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	return "", errors.New("cannot locate anqu source: run anqu-build from the repository checkout")
}
