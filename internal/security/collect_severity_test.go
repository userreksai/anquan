package security

import (
	"context"
	"testing"
)

func TestOrdinaryExecFailureIsNotASecurityWarning(t *testing.T) {
	m, _ := testManager(t, Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}})
	put(t, m, "/var/log/audit/audit.log", []byte(
		"type=SYSCALL msg=audit(1700000000.001:1): success=no exit=-2 key=\"anquan_exec\"\n"+
			"type=EOE msg=audit(1700000000.001:1):\n"+
			"type=SYSCALL msg=audit(1700000000.002:2): success=yes key=\"anquan_exec\"\n"+
			"type=EOE msg=audit(1700000000.002:2):\n"+
			"type=USER_AUTH msg=audit(1700000000.003:3): res=failed\n"+
			"type=EOE msg=audit(1700000000.003:3):\n"))
	var events []Event
	if err := m.Poll(context.Background(), func(event Event) error { events = append(events, event); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("audit records were dropped: %+v", events)
	}
	for _, event := range events {
		if event.Data["kind"] == "exec" && event.Data["severity"] != "info" {
			t.Fatalf("ordinary execution generated a warning: %+v", event)
		}
		if event.Data["kind"] == "audit" && event.Data["severity"] != "warning" {
			t.Fatalf("non-execution failure classification changed: %+v", event)
		}
	}
	if fields := events[0].Data["fields"].(map[string]string); fields["success"] != "no" || fields["exit"] != "-2" {
		t.Fatalf("failed execution evidence was lost: %+v", fields)
	}
}

func TestCustomAuditExecutionFailuresKeepTheirWarning(t *testing.T) {
	for _, records := range [][]string{
		{`type=SYSCALL msg=audit(1700000000.001:1): success=no key="anquan_exec_denied"`},
		{`type=SYSCALL msg=audit(1700000000.001:1): success=no key="anquan_exec" key="anquan_exec_denied"`},
		{`type=SYSCALL msg=audit(1700000000.001:1): success=no key="anquan_exec_denied"`, `type=EXECVE msg=audit(1700000000.001:1): key="anquan_exec"`},
	} {
		m, _ := testManager(t, Config{Enabled: true, Auditd: AuditdConfig{Enabled: true}})
		log := ""
		for _, record := range records {
			log += record + "\n"
		}
		log += "type=EOE msg=audit(1700000000.001:1):\n"
		put(t, m, "/var/log/audit/audit.log", []byte(log))
		var events []Event
		if err := m.Poll(context.Background(), func(event Event) error { events = append(events, event); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].Data["severity"] != "warning" {
			t.Fatalf("custom audit rule warning suppressed: %+v", events)
		}
	}
}
