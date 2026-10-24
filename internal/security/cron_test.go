package security

import (
	"reflect"
	"testing"
)

func TestDefaultCronPathsAreExactAndIndependent(t *testing.T) {
	want := []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.allow", "/etc/cron.deny", "/var/spool/cron", "/etc/anacrontab", "/etc/cron.yearly"}
	got := DefaultCronPaths()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cron defaults = %v, want %v", got, want)
	}
	got[0] = "/changed-by-caller"
	if !reflect.DeepEqual(DefaultCronPaths(), want) {
		t.Fatal("caller changed shared cron defaults")
	}
	for _, path := range want {
		if !IsCronPath(path) || cronAuditRulePath("-w "+path+" -p wa -k anquan_file") != path {
			t.Fatalf("standard cron path was not recognized: %s", path)
		}
	}
	for _, path := range []string{"/etc", "/etc/cron.custom", "/etc/cron.d/job", "/etc/cron.d/", "/etc/crontab.bak", "/var/spool", "/var/spool/cron-extra", "etc/crontab"} {
		if IsCronPath(path) {
			t.Fatalf("optional cron handling escaped its exact allowlist: %s", path)
		}
	}
	for _, rule := range []string{"-w /etc/crontab -p r -k anquan_file", "-w /etc/crontab -p wa -k anquan_custom", "-w /etc/crontab -p wa -k anquan_file -F uid=1000"} {
		if cronAuditRulePath(rule) != "" {
			t.Fatalf("custom audit rule acquired optional generated-rule behavior: %s", rule)
		}
	}
}
