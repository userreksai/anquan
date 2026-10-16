package security

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type releaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}
type releaseInfo struct {
	Assets []releaseAsset `json:"assets"`
}

func secureDownload(ctx context.Context, address string, limit int64) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("download must use HTTPS")
	}
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("refusing HTTPS downgrade")
		}
		if len(via) > 5 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "anquan-agent-security/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download %s: HTTP %d", u.Host, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("download exceeds configured limit")
	}
	return b, nil
}
func (m *Manager) installTetragon(ctx context.Context) error {
	t := m.Config.Tetragon
	if t.Version == "" {
		return errors.New("Tetragon automatic installation requires a pinned version (for example v1.7.0)")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("Tetragon package installation supports amd64/arm64 only")
	}
	if _, err := os.Stat(m.path("/sys/kernel/btf/vmlinux")); err != nil {
		return errors.New("Tetragon requires readable kernel BTF at /sys/kernel/btf/vmlinux; configure a supported host before enabling it")
	}
	assetName := "tetragon-" + t.Version + "-" + runtime.GOARCH + ".tar.gz"
	address := t.DownloadURL
	if address == "" {
		address = "https://github.com/cilium/tetragon/releases/download/" + t.Version + "/" + assetName
	}
	expected := strings.ToLower(t.SHA256)
	if expected == "" {
		b, err := secureDownload(ctx, "https://api.github.com/repos/cilium/tetragon/releases/tags/"+t.Version, 2*1024*1024)
		if err != nil {
			return fmt.Errorf("retrieve official release checksum: %w", err)
		}
		var release releaseInfo
		if err = json.Unmarshal(b, &release); err != nil {
			return err
		}
		for _, a := range release.Assets {
			if a.URL == address && a.Name == assetName && strings.HasPrefix(a.Digest, "sha256:") {
				expected = strings.TrimPrefix(a.Digest, "sha256:")
				break
			}
		}
		// Older releases do not expose an asset digest. Use the project's own
		// checksum asset when present; never silently install unverified bytes.
		if expected == "" {
			for _, a := range release.Assets {
				if a.Name == assetName+".sha256sum" || a.Name == assetName+".sha256" || a.Name == "checksums.txt" || a.Name == "sha256sums.txt" {
					sum, err := secureDownload(ctx, a.URL, 1024*1024)
					if err != nil {
						return err
					}
					for _, line := range strings.Split(string(sum), "\n") {
						parts := strings.Fields(line)
						if len(parts) > 0 && (len(parts) == 1 || strings.TrimPrefix(parts[len(parts)-1], "*") == assetName) {
							decoded, e := hex.DecodeString(parts[0])
							if e == nil && len(decoded) == 32 {
								expected = strings.ToLower(parts[0])
								break
							}
						}
					}
					if expected != "" {
						break
					}
				}
			}
		}
		if expected == "" {
			return errors.New("official release has no usable SHA256 digest; provide tetragon.sha256 explicitly")
		}
	}
	archive, err := secureDownload(ctx, address, 256*1024*1024)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(archive)
	if hex.EncodeToString(actual[:]) != expected {
		return errors.New("Tetragon SHA256 verification failed")
	}
	temp, err := os.MkdirTemp(m.OutputDir, "tetragon-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err = extractPackage(archive, temp); err != nil {
		return err
	}
	installer := ""
	err = filepath.WalkDir(temp, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && d.Name() == "install.sh" {
			if installer != "" {
				return errors.New("archive contains multiple install.sh files")
			}
			installer = p
		}
		return nil
	})
	if err != nil {
		return err
	}
	if installer == "" {
		return errors.New("official Tetragon package is missing install.sh")
	}
	// The upstream installer expects its package directory as working directory.
	// Execute the installer itself so its upstream shebang selects the correct
	// interpreter. A fixed wrapper supplies no user-controlled shell source.
	if _, err = m.Runner.Run(ctx, "sh", "-c", "cd -- \"$1\" && exec ./install.sh", "anquan-tetragon-installer", filepath.Dir(installer)); err != nil {
		return err
	}
	if _, err = m.Runner.LookPath("tetragon"); err != nil {
		return errors.New("Tetragon installer completed without installing tetragon")
	}
	return nil
}
func extractPackage(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	var total int64
	count := 0
	for {
		h, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		count++
		if count > 20000 {
			return errors.New("too many files in Tetragon package")
		}
		clean := filepath.Clean(filepath.FromSlash(h.Name))
		target := filepath.Join(dest, clean)
		rel, e := filepath.Rel(dest, target)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) || strings.Contains(h.Name, "\\") {
			return errors.New("unsafe archive path")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > 128*1024*1024 {
				return errors.New("Tetragon archive entry too large")
			}
			total += h.Size
			if total > 768*1024*1024 {
				return errors.New("Tetragon extracted size too large")
			}
			if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0755)
			if e != nil {
				return e
			}
			_, copyErr := io.Copy(f, reader)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeXGlobalHeader:
			continue
		default:
			return fmt.Errorf("unsupported archive entry type %d (links and devices are rejected)", h.Typeflag)
		}
	}
}
