package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"anqu/internal/security"
)

const nativeHashLimit = 64 << 20

type nativeUTF8Stream struct {
	tail    []byte
	invalid bool
}

func (s *nativeUTF8Stream) write(data []byte) {
	if s.invalid {
		return
	}
	for len(s.tail) > 0 && len(data) > 0 {
		s.tail = append(s.tail, data[0])
		data = data[1:]
		if utf8.FullRune(s.tail) {
			if !utf8.Valid(s.tail) {
				s.invalid = true
				return
			}
			s.tail = nil
		}
	}
	if len(data) == 0 || utf8.Valid(data) {
		return
	}
	for trim := 1; trim < utf8.UTFMax && trim <= len(data); trim++ {
		end := len(data) - trim
		if !utf8.FullRune(data[end:]) && utf8.Valid(data[:end]) {
			s.tail = append([]byte(nil), data[end:]...)
			return
		}
	}
	s.invalid = true
}

func nativeCaptureCreated(cfg *NativeFIMConfig) bool {
	return cfg.CaptureCreatedContent == nil || *cfg.CaptureCreatedContent
}

// Only unambiguous editor artifacts are ignored. Ordinary dotfiles and .tmp
// files remain monitored, and nativeExcluded preserves exact assigned roots.
func nativeEditorTemporary(path string) bool {
	n := filepath.Base(path)
	if n == "4913" || (strings.HasPrefix(n, ".#") && len(n) > 2) || (strings.HasPrefix(n, "#") && strings.HasSuffix(n, "#") && len(n) > 2) {
		return true
	}
	if strings.HasSuffix(n, "~") && len(n) > 1 {
		return true
	}
	if strings.HasPrefix(n, ".") {
		for _, suffix := range []string{".swp", ".swo", ".swx"} {
			if strings.HasSuffix(n, suffix) {
				return true
			}
		}
	}
	return false
}

func nativeContentLimit(cfg *NativeFIMConfig) int {
	limit := cfg.MaxDiffBytes
	if limit <= 0 {
		limit = 8192
	}
	if limit > 16384 {
		limit = 16384
	}
	return limit
}

func nativeUTF8Prefix(text string, limit int) string {
	if limit >= len(text) {
		return text
	}
	if limit < 0 {
		limit = 0
	}
	text = text[:limit]
	for len(text) > 0 && !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text
}

// The descriptor and byte count are bounded independently of the initial stat:
// a concurrently growing file must not create an unlimited read or text buffer.
func nativeReadFile(ctx context.Context, path string, cfg *NativeFIMConfig, capture, tracked bool) (nativeFile, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nativeFile{Type: "missing", ContentStatus: "not_applicable"}, nil
	}
	if err != nil {
		return nativeFile{}, err
	}
	uid, gid, inode := nativeOwnership(info)
	n := nativeFile{Type: "special", Mode: uint32(info.Mode()), UID: uid, GID: gid, Inode: inode, Size: info.Size(), Modified: info.ModTime().UnixNano(), ContentStatus: "not_applicable"}
	if info.Mode()&os.ModeSymlink != 0 {
		n.Type = "symlink"
		n.Link, err = os.Readlink(path)
		return n, err
	}
	if info.IsDir() {
		n.Type = "directory"
		n.Modified, n.Size = 0, 0
		return n, nil
	}
	if !info.Mode().IsRegular() {
		return n, nil
	}
	n.Type, n.ContentTracked = "file", tracked
	n.ContentStatus = "disabled"
	if nativeSensitivePath(path) {
		capture = false
		n.ContentStatus = "sensitive"
	}
	if info.Size() > nativeHashLimit {
		n.ContentStatus = "unavailable"
		return n, nil
	}
	f, err := os.Open(path)
	if err != nil {
		n.ContentStatus = "unavailable"
		return n, nil
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return n, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		n.ContentStatus = "unavailable"
		return n, nil
	}
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	limit := nativeContentLimit(cfg)
	text := make([]byte, 0, limit+utf8.UTFMax)
	var total int64
	binary := false
	var validation nativeUTF8Stream
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		count, readErr := f.Read(buffer)
		total += int64(count)
		if total > nativeHashLimit {
			n.ContentStatus = "unavailable"
			return n, nil
		}
		if count > 0 {
			_, _ = h.Write(buffer[:count])
			if capture {
				validation.write(buffer[:count])
				if bytes.IndexByte(buffer[:count], 0) >= 0 {
					binary = true
				}
				if remain := limit + utf8.UTFMax - len(text); remain > 0 {
					if remain > count {
						remain = count
					}
					text = append(text, buffer[:remain]...)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			n.ContentStatus = "unavailable"
			return n, nil
		}
	}
	// Deletion after open is safe: the pinned descriptor still identifies the
	// contents observed by CLOSE_WRITE. A replacement path is a later transition.
	after, err := f.Stat()
	if err != nil {
		return n, err
	}
	if info.Size() != after.Size() || total != after.Size() || !info.ModTime().Equal(after.ModTime()) || info.Mode() != after.Mode() {
		n.ContentStatus = "unavailable"
		return n, nil
	}
	n.SHA256 = hex.EncodeToString(h.Sum(nil))
	if !capture {
		return n, nil
	}
	if binary || validation.invalid || len(validation.tail) != 0 {
		n.ContentStatus = "binary"
		return n, nil
	}
	// Permit only an incomplete final rune caused by the capture limit. Invalid
	// UTF-8 elsewhere is binary and is never converted to replacement characters.
	valid := text
	if int64(len(text)) < total {
		for len(valid) > 0 && !utf8.Valid(valid) && len(text)-len(valid) < utf8.UTFMax {
			valid = valid[:len(valid)-1]
		}
	}
	if !utf8.Valid(valid) {
		n.ContentStatus = "binary"
		return n, nil
	}
	n.Text = nativeUTF8Prefix(string(valid), limit)
	n.TextTruncated = int64(len(n.Text)) < total
	switch {
	case n.TextTruncated:
		n.ContentStatus = "truncated"
	case total == 0:
		n.ContentStatus = "empty"
	default:
		n.ContentStatus = "captured"
	}
	return n, nil
}

func nativeSameMetadata(a, b nativeFile) bool {
	// An unavailable hash is not evidence of changed contents. Mode, inode,
	// size and mtime still report independently observable changes.
	if a.SHA256 == "" || b.SHA256 == "" {
		a.SHA256, b.SHA256 = "", ""
	}
	a.Text, b.Text = "", ""
	a.ContentStatus, b.ContentStatus = "", ""
	a.TextTruncated, b.TextTruncated = false, false
	a.ContentTracked, b.ContentTracked = false, false
	return a == b
}

func nativeScrubReservedContent(path string, details map[string]any, cfg *NativeFIMConfig) {
	for _, side := range []struct{ prefix, metadata string }{{"previous", "before"}, {"current", "after"}} {
		var n nativeFile
		if raw, err := json.Marshal(details[side.metadata]); err == nil {
			_ = json.Unmarshal(raw, &n)
		}
		if status, ok := details[side.prefix+"_content_status"].(string); ok {
			n.ContentStatus = status
		}
		if text, ok := details[side.prefix+"_text"].(string); ok {
			n.Text = text
			if n.ContentStatus == "" {
				n.ContentStatus = "captured"
				if text == "" {
					n.ContentStatus = "empty"
				}
			}
		}
		n = nativeContentPolicy(path, n, cfg)
		delete(details, side.prefix+"_text")
		details[side.prefix+"_content_status"] = n.ContentStatus
		details[side.prefix+"_text_truncated"] = n.ContentStatus == "truncated"
		if n.ContentStatus == "captured" || n.ContentStatus == "empty" || n.ContentStatus == "truncated" {
			details[side.prefix+"_text"] = n.Text
		}
	}
}

func nativeContentPolicy(path string, n nativeFile, cfg *NativeFIMConfig) nativeFile {
	if n.Type != "file" {
		n.Text = ""
		n.ContentStatus = "not_applicable"
		n.TextTruncated = false
		return n
	}
	if nativeSensitivePath(path) {
		n.Text = ""
		n.ContentStatus = "sensitive"
		n.TextTruncated = false
		return n
	}
	if !cfg.ReportChanges && (!nativeCaptureCreated(cfg) || !n.ContentTracked) {
		n.Text = ""
		n.ContentStatus = "disabled"
		n.TextTruncated = false
		return n
	}
	if n.ContentStatus == "" {
		if n.Text != "" {
			n.ContentStatus = "captured"
		} else {
			n.ContentStatus = "unavailable"
		}
	}
	if len(n.Text) > nativeContentLimit(cfg) {
		n.Text = nativeUTF8Prefix(n.Text, nativeContentLimit(cfg))
		n.ContentStatus = "truncated"
		n.TextTruncated = true
	}
	return n
}

func nativeContentDetails(details map[string]any, prefix, path string, n nativeFile, exists bool, cfg *NativeFIMConfig) {
	status := "not_applicable"
	if exists {
		n = nativeContentPolicy(path, n, cfg)
		status = n.ContentStatus
	}
	details[prefix+"_content_status"] = status
	details[prefix+"_text_truncated"] = status == "truncated"
	if status == "captured" || status == "empty" || status == "truncated" {
		details[prefix+"_text"] = n.Text
	}
}

func nativeBoundEvent(event *security.Event) error {
	details := event.Data["details"].(map[string]any)
	for {
		encoded, err := json.Marshal(event.Data)
		if err != nil {
			return err
		}
		if len(encoded) <= 48000 {
			return nil
		}
		longest := ""
		for _, key := range []string{"previous_text", "current_text"} {
			if v, ok := details[key].(string); ok && len(v) > len(longest) {
				longest = v
			}
		}
		if longest == "" {
			return fmt.Errorf("native FIM event metadata exceeds transport limit")
		}
		for _, prefix := range []string{"previous", "current"} {
			key := prefix + "_text"
			if v, ok := details[key].(string); ok && len(v) == len(longest) {
				details[key] = nativeUTF8Prefix(v, len(v)/2)
				details[prefix+"_content_status"] = "truncated"
				details[prefix+"_text_truncated"] = true
			}
		}
	}
}
