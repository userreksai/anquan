package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"anqu/internal/selfupdate"
)

func TestOneShotCannotAdvertiseSelfUpdateCapability(t *testing.T) {
	for _, once := range []bool{false, true} {
		t.Run(map[bool]string{false: "service", true: "oneShot"}[once], func(t *testing.T) {
			cfg, base := deliveryBootstrap(t)
			d := NewConfigDelivery(cfg, base, "0.7.3")
			// An empty manager is enough to test capability framing without any
			// privileges, update download, or host systemd interactions.
			d.SetSelfUpdater(&selfupdate.Manager{})
			client, server := net.Pipe()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- d.connection(ctx, client, controlEndpoint{"master:55556"}, once, commitAssignment) }()
			_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, err := bufio.NewReader(server).ReadBytes('\n')
			if err != nil {
				t.Fatal(err)
			}
			var hello configFrame
			if err := json.Unmarshal(line, &hello); err != nil {
				t.Fatal(err)
			}
			if hello.SelfUpdate == once {
				t.Fatalf("once=%t self_update=%t", once, hello.SelfUpdate)
			}
			if !once && (hello.GOOS == "" || hello.GOARCH == "") {
				t.Fatal("service hello lacks platform")
			}
			if once && (hello.GOOS != "" || hello.GOARCH != "") {
				t.Fatal("one-shot advertised an update platform")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("control connection did not cancel")
			}
		})
	}
}
