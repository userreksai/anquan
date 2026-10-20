package selfupdate

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func download(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), endpoint, ip string, offer Descriptor, destination string) error {
	conn, err := dial(ctx, "tcp", endpoint)
	if err != nil {
		return fmt.Errorf("connect update download: %w", err)
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	expires, _ := time.Parse(time.RFC3339, offer.ExpiresAt)
	if deadline := time.Now().Add(10 * time.Minute); expires.After(deadline) {
		expires = deadline
	}
	_ = conn.SetDeadline(expires)
	hello := struct {
		Version int    `json:"version"`
		Type    string `json:"type"`
		IP      string `json:"ip"`
		Token   string `json:"token"`
		JobID   string `json:"job_id"`
	}{1, "update_download", ip, offer.Token, offer.JobID}
	if err := json.NewEncoder(conn).Encode(hello); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(conn, 16<<10)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return errors.New("invalid update download response")
	}
	var ready struct {
		Version int    `json:"version"`
		Type    string `json:"type"`
		Size    int64  `json:"size"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(line, &ready) != nil || ready.Version != 1 || ready.Type != "update_ready" || ready.Size != offer.Size {
		return errors.New("Master did not authorize the update download")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.CopyN(io.MultiWriter(file, hash), reader, offer.Size)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("incomplete update archive: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if hex.EncodeToString(hash.Sum(nil)) != offer.SHA256 {
		return errors.New("update archive SHA-256 mismatch")
	}
	return nil
}

// extract accepts exactly one regular member named anquan. Reading the gzip
// trailer and checking the underlying reader also rejects concatenated streams.
func extract(archive, destination string, offer Descriptor) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := bufio.NewReader(file)
	gz, err := gzip.NewReader(buffer)
	if err != nil {
		return errors.New("update archive is not gzip")
	}
	defer gz.Close()
	gz.Multistream(false)
	limited := &io.LimitedReader{R: gz, N: offer.BinarySize + (1 << 20)}
	reader := tar.NewReader(limited)
	header, err := reader.Next()
	if err != nil || header.Name != "anquan" || header.Typeflag != tar.TypeReg || header.Size != offer.BinarySize || header.Size <= 0 || header.Size > MaxBinarySize || len(header.PAXRecords) != 0 || header.Linkname != "" {
		return errors.New("update archive must contain one regular file named anquan")
	}
	stage, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.CopyN(io.MultiWriter(stage, hash), reader, offer.BinarySize)
	if err == nil {
		err = stage.Sync()
	}
	closeErr := stage.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot stage complete Agent executable")
	}
	if hex.EncodeToString(hash.Sum(nil)) != offer.BinarySHA256 {
		return errors.New("update binary SHA-256 mismatch")
	}
	if _, err := reader.Next(); err != io.EOF {
		return errors.New("update archive contains extra members or invalid padding")
	}
	// Consume only bounded tar padding and gzip trailer. Any nonzero trailing
	// bytes, excessive padding, corrupt checksum, or second gzip is invalid.
	tail, err := io.ReadAll(limited)
	if err != nil || limited.N <= 0 {
		return errors.New("invalid or oversized gzip stream")
	}
	for _, value := range tail {
		if value != 0 {
			return errors.New("unexpected data following update tar")
		}
	}
	if _, err := buffer.Peek(1); err != io.EOF {
		return errors.New("update archive contains trailing data or multiple gzip streams")
	}
	return verifyELF(destination, offer.GOARCH)
}

func verifyELF(path, architecture string) error {
	file, err := elf.Open(path)
	if err != nil {
		return errors.New("update executable is not ELF")
	}
	defer file.Close()
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
	machine, ok := machines[architecture]
	if !ok || file.Machine != machine || file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return errors.New("update ELF architecture does not match this Agent")
	}
	return nil
}
