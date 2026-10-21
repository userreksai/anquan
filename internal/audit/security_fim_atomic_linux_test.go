//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"anqu/internal/security"
)

func TestNativeFIMLinuxVimBackupSaveIsOneModificationAcrossReconcile(t *testing.T) {
	for _, style := range []string{"backup-and-write", "atomic-rename"} {
		t.Run(style, func(t *testing.T) {
			c, p, original := nativeAtomicFixture(t)
			c.Security.NativeFIM.PollIntervalSeconds = 1
			events, errors, stop := nativeStartLinuxTest(t, c)
			defer stop()
			const final = "#!/bin/sh\necho single-vim-save\n"
			switch style {
			case "backup-and-write":
				if err := os.Rename(p, p+"~"); err != nil {
					t.Fatal(err)
				}
				// The backup artifact is ignored; recreating the actual target
				// within the quiet window is one replacement of its baseline.
				if err := os.WriteFile(p, []byte(final), 0700); err != nil {
					t.Fatal(err)
				}
			case "atomic-rename":
				staging := filepath.Join(t.TempDir(), "replacement")
				if err := os.WriteFile(staging, []byte(final), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(staging, p); err != nil {
					t.Fatal(err)
				}
			}
			first := nativeNextLinuxEvent(t, events, errors)
			nativeAssertAtomicModification(t, []security.Event{first}, p, original, final)
			// Wait beyond more than one full periodic scan, proving the
			// accepted replacement and baseline cannot emit a second record.
			select {
			case e := <-events:
				t.Fatalf("save emitted a second notification: %+v", e)
			case err := <-errors:
				t.Fatal(err)
			case <-time.After(1500 * time.Millisecond):
			}
		})
	}
}
