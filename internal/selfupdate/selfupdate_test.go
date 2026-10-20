package selfupdate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func digest(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }

func signedOffer(t *testing.T) (Descriptor, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offer := Descriptor{SignedFields: SignedFields{JobID: "job-123", Version: "0.7.4", GOOS: "linux", GOARCH: runtime.GOARCH, SHA256: strings.Repeat("a", 64), Size: 100, BinarySHA256: strings.Repeat("b", 64), BinarySize: 64, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Token: strings.Repeat("c", 64)}}
	sign := func() {
		message, _ := json.Marshal(offer.SignedFields)
		offer.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))
	}
	sign()
	return offer, public, private
}

func TestDescriptorSignatureVersionPlatformAndBounds(t *testing.T) {
	offer, key, _ := signedOffer(t)
	if err := Verify(offer, key, "0.7.3", "linux", runtime.GOARCH, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, current := range []string{"0.7.4", "0.8.0", "1.0.0", "broken"} {
		if Verify(offer, key, current, "linux", runtime.GOARCH, time.Now()) == nil {
			t.Fatalf("accepted current %s", current)
		}
	}
	for name, mutate := range map[string]func(*Descriptor){
		"digest":   func(v *Descriptor) { v.SHA256 = strings.Repeat("f", 64) },
		"oversize": func(v *Descriptor) { v.Size = MaxArchiveSize + 1 },
		"expiry":   func(v *Descriptor) { v.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339) },
		"arch":     func(v *Descriptor) { v.GOARCH = "other" },
		"path":     func(v *Descriptor) { v.JobID = "../bad" },
		"version":  func(v *Descriptor) { v.Version = "0.7.4-beta" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := offer
			mutate(&bad)
			if Verify(bad, key, "0.7.3", "linux", runtime.GOARCH, time.Now()) == nil {
				t.Fatal("accepted modified or invalid descriptor")
			}
		})
	}
	for _, version := range []string{"0.7.3-beta", "0.7", "00.7.3", "0.7.3+build", "0.7.3.1", "18446744073709551616.0.0"} {
		if _, err := parseVersion(version); err == nil {
			t.Fatalf("accepted %s", version)
		}
	}
}

func TestVersionOutputUsesStrictVersionTokenWithOptionalVPrefix(t *testing.T) {
	for _, output := range []string{"anqu 0.7.4\n", "anqu v0.7.4\n"} {
		for _, target := range []string{"0.7.4", "v0.7.4"} {
			if !versionOutputMatches([]byte(output), target) {
				t.Fatalf("version %q did not match %q", output, target)
			}
		}
	}
	for _, output := range []string{"anqu 0.7.3", "anqu 0.7.4-beta", "anqu 00.7.4", "anqu 0.7.4 unexpected", "other 0.7.4", "anqu v0.7.4.1"} {
		if versionOutputMatches([]byte(output), "0.7.4") {
			t.Fatalf("accepted version output %q", output)
		}
	}
}

func TestSigningKeyPinCannotBeReplaced(t *testing.T) {
	_, key, _ := signedOffer(t)
	m := &Manager{directory: t.TempDir()}
	encoded := base64.StdEncoding.EncodeToString(key)
	if _, err := m.Pin("master:55556", encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Pin("master:55556", encoded); err != nil {
		t.Fatal(err)
	}
	_, other, _ := signedOffer(t)
	if _, err := m.Pin("master:55556", base64.StdEncoding.EncodeToString(other)); err == nil {
		t.Fatal("changed signing key replaced first pin")
	}
	if _, err := m.Pin("master:55556", encoded); err != nil {
		t.Fatal("failed key rotation damaged existing pin", err)
	}
	if _, err := m.Pin("second:55556", base64.StdEncoding.EncodeToString(other)); err != nil {
		t.Fatal(err)
	}
}

func elfBinary(arch string) []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(data[18:], machine)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	return data
}

func archiveBytes(t *testing.T, data []byte, headers ...tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gz)
	if len(headers) == 0 {
		headers = []tar.Header{{Name: "anquan", Typeflag: tar.TypeReg, Mode: 0700, Size: int64(len(data))}}
	}
	for _, header := range headers {
		if err := tarWriter.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tarWriter.Write(data[:header.Size]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestArchiveRejectsTraversalLinksExtraStreamsCorruptionAndWrongArchitecture(t *testing.T) {
	data := elfBinary("amd64")
	offer := Descriptor{SignedFields: SignedFields{GOARCH: "amd64", BinarySize: int64(len(data)), BinarySHA256: digest(data)}}
	valid := archiveBytes(t, data)
	cases := map[string][]byte{
		"valid":      valid,
		"traversal":  archiveBytes(t, data, tar.Header{Name: "../anquan", Typeflag: tar.TypeReg, Size: int64(len(data))}),
		"symlink":    archiveBytes(t, data, tar.Header{Name: "anquan", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		"hardlink":   archiveBytes(t, data, tar.Header{Name: "anquan", Typeflag: tar.TypeLink, Linkname: "elsewhere"}),
		"extra":      archiveBytes(t, data, tar.Header{Name: "anquan", Typeflag: tar.TypeReg, Size: int64(len(data))}, tar.Header{Name: "extra", Typeflag: tar.TypeReg, Size: int64(len(data))}),
		"gzipconcat": append(append([]byte{}, valid...), valid...),
		"trailing":   append(append([]byte{}, valid...), []byte("unexpected")...),
		"truncated":  valid[:len(valid)-5],
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "input.gz")
			if err := os.WriteFile(path, archive, 0600); err != nil {
				t.Fatal(err)
			}
			err := extract(path, filepath.Join(directory, "output"), offer)
			if name == "valid" && err != nil {
				t.Fatal(err)
			}
			if name != "valid" && err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "input.gz")
	_ = os.WriteFile(path, valid, 0600)
	bad := offer
	bad.BinarySHA256 = strings.Repeat("0", 64)
	if extract(path, filepath.Join(directory, "digest"), bad) == nil {
		t.Fatal("accepted mismatched binary digest")
	}
	bad = offer
	bad.GOARCH = "arm64"
	if extract(path, filepath.Join(directory, "arch"), bad) == nil {
		t.Fatal("accepted wrong ELF architecture")
	}
	bad = offer
	bad.BinarySize = MaxBinarySize + 1
	if extract(path, filepath.Join(directory, "oversize"), bad) == nil {
		t.Fatal("accepted oversized executable")
	}
}

func TestDownloadAuthenticatesAndChecksArchiveDigest(t *testing.T) {
	data := []byte("exact archive bytes")
	for _, badDigest := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "badDigest"}[badDigest], func(t *testing.T) {
			offer := Descriptor{SignedFields: SignedFields{JobID: "job-123", Size: int64(len(data)), SHA256: digest(data), Token: "private-token", ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}}
			if badDigest {
				offer.SHA256 = strings.Repeat("0", 64)
			}
			dial := func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					reader := bufio.NewReader(server)
					line, _ := reader.ReadBytes('\n')
					var hello map[string]any
					_ = json.Unmarshal(line, &hello)
					if hello["type"] != "update_download" || hello["token"] != "private-token" || hello["job_id"] != "job-123" {
						return
					}
					_ = json.NewEncoder(server).Encode(map[string]any{"version": 1, "type": "update_ready", "size": len(data)})
					_, _ = server.Write(data)
				}()
				return client, nil
			}
			err := download(context.Background(), dial, "master:55556", "192.0.2.1", offer, filepath.Join(t.TempDir(), "archive"))
			if (err != nil) != badDigest {
				t.Fatalf("digest check error=%v", err)
			}
		})
	}
}

func TestDownloadCancellationUnblocksNetworkRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	offer := Descriptor{SignedFields: SignedFields{Size: 100, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}}
	done := make(chan error, 1)
	go func() { done <- download(ctx, dial, "master", "ip", offer, filepath.Join(t.TempDir(), "download")) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded unexpectedly")
		}
	case <-time.After(time.Second):
		t.Fatal("download did not cancel")
	}
}

func TestWorkerSingleFlightAndQueuedJournalProtection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("installable descriptors target Linux")
	}
	offer, key, _ := signedOffer(t)
	m := &Manager{current: "0.7.3", directory: t.TempDir(), dial: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status := make(chan Result, 3)
	report := func(result Result) error { status <- result; return nil }
	if err := m.Start(ctx, "master", "ip", key, offer, report); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-status:
		if result.Status != "downloading" {
			t.Fatal(result)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if m.Start(ctx, "master", "ip", key, offer, report) == nil {
		t.Fatal("second worker accepted")
	}
	cancel()
	select {
	case result := <-status:
		if result.Status != "failed" {
			t.Fatal(result)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not report cancellation")
	}
	queued := journal{JobID: "older-job", Version: offer.Version, PreviousVersion: "0.7.3", BinarySHA256: offer.BinarySHA256, PreviousSHA256: offer.SHA256, Status: "queued"}
	if err := writeJournal(m.directory, queued); err != nil {
		t.Fatal(err)
	}
	if m.Start(context.Background(), "master", "ip", key, offer, report) == nil {
		t.Fatal("queued helper journal was overwritten")
	}
}

func TestArchiveRejectsExcessiveExpandedPadding(t *testing.T) {
	data := elfBinary("amd64")
	var plain bytes.Buffer
	writer := tar.NewWriter(&plain)
	if err := writer.WriteHeader(&tar.Header{Name: "anquan", Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(data)
	_ = writer.Close()
	plain.Write(make([]byte, 2<<20))
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write(plain.Bytes())
	_ = gz.Close()
	directory := t.TempDir()
	path := filepath.Join(directory, "bomb.gz")
	_ = os.WriteFile(path, compressed.Bytes(), 0600)
	offer := Descriptor{SignedFields: SignedFields{GOARCH: "amd64", BinarySize: int64(len(data)), BinarySHA256: digest(data)}}
	if extract(path, filepath.Join(directory, "candidate"), offer) == nil {
		t.Fatal("accepted unbounded expanded tar padding")
	}
}

func helperFixture(t *testing.T) (string, string, journal) {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "anquan")
	old, newBinary := []byte("old Agent"), []byte("new Agent")
	for path, data := range map[string][]byte{executable: old, filepath.Join(directory, "backup"): old, filepath.Join(directory, "candidate"): newBinary} {
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	state := journal{JobID: "job-123", Version: "0.7.4", PreviousVersion: "0.7.3", BinarySHA256: digest(newBinary), PreviousSHA256: digest(old), Status: "queued"}
	if err := writeJournal(directory, state); err != nil {
		t.Fatal(err)
	}
	return directory, executable, state
}

func TestHelperSuccessfulReadinessAndBoundedRollback(t *testing.T) {
	for _, outcome := range []string{"success", "startFailure", "timeout", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			directory, executable, state := helperFixture(t)
			starts, stops := 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := helperOperations{readyTimeout: 15 * time.Millisecond, poll: time.Millisecond, stop: func(context.Context) error { stops++; return nil }, start: func(context.Context) error {
				starts++
				if starts == 1 {
					if outcome == "startFailure" {
						return errors.New("start failed")
					}
					if outcome == "success" {
						state.Status = "applied"
						return writeJournal(directory, state)
					}
					if outcome == "cancel" {
						cancel()
					}
				} else {
					record, err := readJournal(directory)
					if err != nil || record.Status != "rolled_back" {
						return errors.New("rollback must be recorded before preserved Agent starts")
					}
				}
				return nil
			}}
			err := runHelper(ctx, directory, executable, ops)
			stored, readErr := readJournal(directory)
			if readErr != nil {
				t.Fatal(readErr)
			}
			data, _ := os.ReadFile(executable)
			if outcome == "success" {
				if err != nil || stored.Status != "applied" || string(data) != "new Agent" || starts != 1 || stops != 1 {
					t.Fatalf("successful helper: %v %+v starts=%d stops=%d binary=%s", err, stored, starts, stops, data)
				}
			} else {
				if err == nil || stored.Status != "rolled_back" || string(data) != "old Agent" || starts != 2 || stops != 2 {
					t.Fatalf("rollback helper: %v %+v starts=%d stops=%d binary=%s", err, stored, starts, stops, data)
				}
			}
		})
	}
}

func TestHelperRejectsChangedCandidateBeforeStoppingService(t *testing.T) {
	directory, executable, _ := helperFixture(t)
	_ = os.WriteFile(filepath.Join(directory, "candidate"), []byte("tampered"), 0700)
	ops := helperOperations{stop: func(context.Context) error { t.Fatal("stopped service for unverified binary"); return nil }}
	if runHelper(context.Background(), directory, executable, ops) == nil {
		t.Fatal("accepted modified candidate")
	}
}

func TestOldControlReconnectCannotDeclareRollback(t *testing.T) {
	directory, executable, state := helperFixture(t)
	state.Status = "restarting"
	_ = writeJournal(directory, state)
	m := &Manager{directory: directory, executable: executable, current: "0.7.3"}
	for _, confirm := range []bool{false, true} {
		if result, _ := m.IdentityResult(confirm); result != nil {
			t.Fatal("old process prematurely declared update outcome", result)
		}
	}
	stored, _ := readJournal(directory)
	if stored.Status != "restarting" {
		t.Fatal("old reconnect changed journal")
	}
	if err := os.Rename(filepath.Join(directory, "candidate"), executable); err != nil {
		t.Fatal(err)
	}
	m.current = "0.7.4"
	if result, _ := m.IdentityResult(false); result == nil || result.Status != "restarting" {
		t.Fatal("new hello lacks pending job")
	}
	stored, _ = readJournal(directory)
	if stored.Status != "restarting" {
		t.Fatal("new Agent became ready before identity")
	}
	if result, _ := m.IdentityResult(true); result == nil || result.Status != "applied" {
		t.Fatal("new Agent did not confirm readiness")
	}
}

func TestUnsupportedInvocationCannotStartHelper(t *testing.T) {
	if NewInstalled(filepath.Join(t.TempDir(), "anquan"), "0.7.3") != nil {
		t.Fatal("arbitrary root binary advertised updates")
	}
	if RunHelper(filepath.Join(t.TempDir(), "journal.json")) == nil {
		t.Fatal("helper accepted arbitrary journal")
	}
}
