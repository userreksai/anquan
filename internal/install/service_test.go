package install

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"anqu/internal/defaults"
)

func testOperations(t *testing.T, commands *[][]string) runtimeOperations {
	t.Helper()
	return runtimeOperations{
		euid: func() int { return 0 },
		systemctl: func(args ...string) error {
			*commands = append(*commands, append([]string(nil), args...))
			return nil
		},
		exec: func(string, []string, []string) error {
			t.Fatal("installation or an installed process must not start a second foreground process")
			return nil
		},
	}
}

func TestFirstNoArgumentLaunchStartsFixedAddressServiceAndReturns(t *testing.T) {
	requireSymlinks(t)
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	put(t, filepath.Join(filepath.Dir(source), "config.age"), "optional local configuration")
	put(t, filepath.Join(paths.directory, "logs", "existing.log"), "retained log")
	var commands [][]string
	var output bytes.Buffer
	prepared, err := prepare(source, nil, &output, paths, testOperations(t, &commands))
	if err != nil || !prepared.InstallOnly || prepared.Path != paths.executable {
		t.Fatalf("preparation: %+v, error %v", prepared, err)
	}
	wantCommands := [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("systemctl commands: %v; want %v", commands, wantCommands)
	}
	wantFile(t, paths.service, string(serviceUnit(paths.executable)))
	wantFile(t, paths.executable, "uploaded agent")
	wantFile(t, filepath.Join(paths.directory, "config.age"), "optional local configuration")
	wantFile(t, filepath.Join(paths.directory, "logs", "existing.log"), "retained log")
	wantFile(t, paths.script, hook)
	if target, err := os.Readlink(paths.sshrc); err != nil || target != paths.script {
		t.Fatalf("SSH hook link: target %q, error %v", target, err)
	}
	for _, name := range []string{"state", "logs", "textfile"} {
		info, err := os.Stat(filepath.Join(paths.directory, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("runtime directory %s: %v", name, err)
		}
	}
	if !strings.Contains(output.String(), defaults.MasterAddress) || !strings.Contains(output.String(), "enabled and started") {
		t.Fatalf("installation success not reported: %q", output.String())
	}
}

func TestInstalledChecksAndServiceDoNotActivateSystemdAgain(t *testing.T) {
	requireSymlinks(t)
	source, paths := fixture(t)
	put(t, source, "uploaded agent")
	var commands [][]string
	ops := testOperations(t, &commands)
	if _, err := prepare(source, nil, nil, paths, ops); err != nil {
		t.Fatal(err)
	}
	commands = nil
	ops.euid = func() int { return 1000 }
	for _, args := range [][]string{nil, {"-service"}, {"-service", "-master", defaults.MasterAddress}} {
		prepared, err := prepare(paths.executable, args, nil, paths, ops)
		if err != nil || prepared.InstallOnly || prepared.Path != paths.executable {
			t.Fatalf("args %v: %+v, error %v", args, prepared, err)
		}
	}
	if len(commands) != 0 {
		t.Fatalf("recursive service activation: %v", commands)
	}
	if _, err := os.Stat(paths.service + ".anquan.bak"); !os.IsNotExist(err) {
		t.Fatal("installed checks replaced the service")
	}
}

func TestFirstLaunchAlreadyAtFixedPathInstallsService(t *testing.T) {
	requireSymlinks(t)
	_, paths := fixture(t)
	put(t, paths.executable, "agent already at fixed path")
	var commands [][]string
	prepared, err := prepare(paths.executable, nil, nil, paths, testOperations(t, &commands))
	if err != nil || !prepared.InstallOnly || len(commands) != 2 {
		t.Fatalf("preparation %+v, commands %v, error %v", prepared, commands, err)
	}
}

func TestUploadOccupyingDirectoryInstallsAndStartsService(t *testing.T) {
	requireSymlinks(t)
	_, paths := fixture(t)
	put(t, paths.directory, "uploaded agent")
	put(t, filepath.Join(filepath.Dir(paths.directory), "config.age"), "optional upload configuration")
	var commands [][]string
	var output bytes.Buffer
	prepared, err := prepare(paths.directory, nil, &output, paths, testOperations(t, &commands))
	if err != nil || !prepared.InstallOnly || prepared.Path != paths.executable {
		t.Fatalf("directory-conflict preparation %+v, error %v", prepared, err)
	}
	if want := [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}}; !reflect.DeepEqual(commands, want) {
		t.Fatalf("systemctl commands %v; want %v", commands, want)
	}
	backups, err := filepath.Glob(paths.directory + ".upload-*")
	if err != nil || len(backups) != 1 || !strings.Contains(output.String(), backups[0]) {
		t.Fatalf("backup path not reported: backups %v, output %q, error %v", backups, output.String(), err)
	}
	wantFile(t, backups[0], "uploaded agent")
	wantFile(t, paths.executable, "uploaded agent")
	wantFile(t, filepath.Join(paths.directory, "config.age"), "optional upload configuration")
	wantFile(t, paths.service, string(serviceUnit(paths.executable)))
	wantFile(t, paths.script, hook)
	if target, err := os.Readlink(paths.sshrc); err != nil || target != paths.script {
		t.Fatalf("SSH link target %q, error %v", target, err)
	}
	for _, name := range []string{"state", "logs", "textfile"} {
		info, err := os.Stat(filepath.Join(paths.directory, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("missing runtime directory %s: %v", name, err)
		}
	}
	commands = nil
	ops := testOperations(t, &commands)
	ops.euid = func() int { return 1000 }
	prepared, err = prepare(paths.executable, nil, nil, paths, ops)
	if err != nil || prepared.InstallOnly || len(commands) != 0 {
		t.Fatalf("installed no-argument launch no longer a one-shot check: %+v, commands %v, error %v", prepared, commands, err)
	}
}

func TestExplicitServiceFromDirectoryOccupantExecutesInstalledBinary(t *testing.T) {
	requireSymlinks(t)
	_, paths := fixture(t)
	put(t, paths.directory, "uploaded agent")
	var commands [][]string
	ops := testOperations(t, &commands)
	var started []string
	ops.exec = func(path string, argv, _ []string) error {
		if path != paths.executable {
			t.Fatalf("wrong executable %q", path)
		}
		started = append([]string(nil), argv...)
		return nil
	}
	args := []string{"-service", "-master", defaults.MasterAddress}
	prepared, err := prepare(paths.directory, args, nil, paths, ops)
	if err != nil || prepared.InstallOnly || prepared.Path != paths.executable || len(commands) != 0 {
		t.Fatalf("explicit directory-conflict preparation %+v, commands %v, error %v", prepared, commands, err)
	}
	if want := append([]string{paths.executable}, args...); !reflect.DeepEqual(started, want) {
		t.Fatalf("foreground args %v; want %v", started, want)
	}
	wantFile(t, paths.executable, "uploaded agent")
}

func TestServiceInstallationPreservesLegacyUnitAndDropIns(t *testing.T) {
	_, paths := fixture(t)
	put(t, paths.service, "legacy service configuration\n")
	dropIn := filepath.Join(paths.service+".d", "master.conf")
	put(t, dropIn, "[Service]\nEnvironment=ANQUAN_MASTER=old.example.com\n")
	if err := ensureService(paths.service, paths.executable); err != nil {
		t.Fatal(err)
	}
	wantFile(t, paths.service+".anquan.bak", "legacy service configuration\n")
	wantFile(t, dropIn, "[Service]\nEnvironment=ANQUAN_MASTER=old.example.com\n")
	wantFile(t, paths.service, string(serviceUnit(paths.executable)))
	data := string(serviceUnit(paths.executable))
	for _, required := range []string{
		"Environment=ANQUAN_MASTER=" + defaults.MasterAddress,
		"ExecStart=" + paths.executable + " -service -master " + defaults.MasterAddress,
		"WorkingDirectory=" + paths.directory,
		"Conflicts=agent.timer anqu.service anqu-oneshot.service",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(data, required) {
			t.Fatalf("service missing %q: %s", required, data)
		}
	}
	if err := ensureService(paths.service, paths.executable); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.service + ".anquan.bak.1"); !os.IsNotExist(err) {
		t.Fatal("matching service backed up again")
	}
}

func TestSystemctlSequenceAndFailuresWithoutHostServiceManager(t *testing.T) {
	for _, existed := range []bool{false, true} {
		want := [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}}
		if existed {
			want = append(want, []string{"restart", ServiceName})
		}
		for failureIndex := -1; failureIndex < len(want); failureIndex++ {
			t.Run(fmt.Sprintf("existing_%t_failure_%d", existed, failureIndex), func(t *testing.T) {
				_, paths := fixture(t)
				if err := ensureDirectory(paths.directory); err != nil {
					t.Fatal(err)
				}
				if existed {
					put(t, paths.service, "legacy unit")
				}
				var calls [][]string
				failure := errors.New("service manager unavailable")
				err := installService(paths, func(args ...string) error {
					calls = append(calls, append([]string(nil), args...))
					if len(calls)-1 == failureIndex {
						return failure
					}
					return nil
				}, existed)
				if failureIndex < 0 {
					if err != nil || !reflect.DeepEqual(calls, want) {
						t.Fatalf("commands %v, error %v; want %v", calls, err, want)
					}
					if pending, err := serviceInstallationPending(paths.directory); err != nil || pending {
						t.Fatalf("successful install still pending: %t, error %v", pending, err)
					}
					return
				}
				if !errors.Is(err, failure) || !reflect.DeepEqual(calls, want[:failureIndex+1]) {
					t.Fatalf("commands after failure %v, error %v", calls, err)
				}
				if pending, err := serviceInstallationPending(paths.directory); err != nil || !pending {
					t.Fatalf("failed install not marked pending: %t, error %v", pending, err)
				}
				if runtime.GOOS == "linux" {
					info, err := os.Stat(filepath.Join(paths.directory, serviceInstalling))
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatalf("progress marker permissions: %v, error %v", info, err)
					}
				}
				calls = nil
				if err := installService(paths, func(args ...string) error {
					calls = append(calls, append([]string(nil), args...))
					return nil
				}, true); err != nil {
					t.Fatalf("retry failed: %v", err)
				}
				retryWant := [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}, {"restart", ServiceName}}
				if !reflect.DeepEqual(calls, retryWant) {
					t.Fatalf("retry commands %v; want %v", calls, retryWant)
				}
				if pending, err := serviceInstallationPending(paths.directory); err != nil || pending {
					t.Fatalf("successful retry still pending: %t, error %v", pending, err)
				}
				if _, err := os.Stat(paths.service + ".anquan.bak.1"); !os.IsNotExist(err) {
					t.Fatal("retry backed up unchanged service")
				}
			})
		}
	}
}

func TestFixedPathActivationFailureCanRetryWithoutRecursiveServiceInstall(t *testing.T) {
	requireSymlinks(t)
	for _, failedCall := range []int{1, 2} {
		t.Run(fmt.Sprint(failedCall), func(t *testing.T) {
			_, paths := fixture(t)
			put(t, paths.executable, "fixed path agent")
			var calls [][]string
			ops := testOperations(t, &calls)
			failure := errors.New("service startup failed")
			ops.systemctl = func(args ...string) error {
				calls = append(calls, append([]string(nil), args...))
				if len(calls) == failedCall {
					return failure
				}
				return nil
			}
			if _, err := prepare(paths.executable, nil, nil, paths, ops); !errors.Is(err, failure) {
				t.Fatalf("first activation error: %v", err)
			}
			if pending, err := serviceInstallationPending(paths.directory); err != nil || !pending {
				t.Fatalf("failed activation not retained: %t, error %v", pending, err)
			}
			calls = nil
			ops = testOperations(t, &calls)
			prepared, err := prepare(paths.executable, []string{"-service"}, nil, paths, ops)
			if err != nil || prepared.InstallOnly || len(calls) != 0 {
				t.Fatalf("service recursively installed: %+v, calls %v, error %v", prepared, calls, err)
			}
			prepared, err = prepare(paths.executable, nil, nil, paths, ops)
			want := [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}, {"restart", ServiceName}}
			if err != nil || !prepared.InstallOnly || !reflect.DeepEqual(calls, want) {
				t.Fatalf("fixed path retry: %+v, calls %v, error %v", prepared, calls, err)
			}
			calls = nil
			ops.euid = func() int { return 1000 }
			prepared, err = prepare(paths.executable, nil, nil, paths, ops)
			if err != nil || prepared.InstallOnly || len(calls) != 0 {
				t.Fatalf("successful installation did not retain one-shot behavior: %+v, calls %v, error %v", prepared, calls, err)
			}
		})
	}
}

func TestExistingTimersAreStoppedBeforeServiceEnable(t *testing.T) {
	for _, timers := range [][]string{{}, {"agent.timer"}, {"anqu.timer"}, {"agent.timer", "anqu.timer"}} {
		t.Run(strings.Join(timers, "_"), func(t *testing.T) {
			_, paths := fixture(t)
			if err := ensureDirectory(paths.directory); err != nil {
				t.Fatal(err)
			}
			want := [][]string{{"daemon-reload"}}
			for _, name := range timers {
				put(t, filepath.Join(filepath.Dir(paths.service), name), "legacy timer")
				want = append(want, []string{"disable", "--now", name})
			}
			want = append(want, []string{"enable", "--now", ServiceName})
			var calls [][]string
			if err := installService(paths, testOperations(t, &calls).systemctl, false); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("timer migration calls %v; want %v", calls, want)
			}
			for _, name := range timers {
				wantFile(t, filepath.Join(filepath.Dir(paths.service), name), "legacy timer")
			}
		})
	}
}

func TestTimerStopFailureStopsActivationAndCanRetry(t *testing.T) {
	for _, failedTimer := range []string{"agent.timer", "anqu.timer"} {
		t.Run(failedTimer, func(t *testing.T) {
			_, paths := fixture(t)
			if err := ensureDirectory(paths.directory); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"agent.timer", "anqu.timer"} {
				put(t, filepath.Join(filepath.Dir(paths.service), name), "old timer")
			}
			var calls [][]string
			failure := errors.New("cannot stop old timer")
			err := installService(paths, func(args ...string) error {
				calls = append(calls, append([]string(nil), args...))
				if args[0] == "disable" && args[2] == failedTimer {
					return failure
				}
				return nil
			}, false)
			want := [][]string{{"daemon-reload"}, {"disable", "--now", "agent.timer"}}
			if failedTimer == "anqu.timer" {
				want = append(want, []string{"disable", "--now", "anqu.timer"})
			}
			if !errors.Is(err, failure) || !reflect.DeepEqual(calls, want) {
				t.Fatalf("continued after timer failure: calls %v, error %v", calls, err)
			}
			if pending, err := serviceInstallationPending(paths.directory); err != nil || !pending {
				t.Fatalf("timer failure not retained for retry: %t, error %v", pending, err)
			}
			calls = nil
			if err := installService(paths, testOperations(t, &calls).systemctl, true); err != nil {
				t.Fatal(err)
			}
			want = [][]string{{"daemon-reload"}, {"disable", "--now", "agent.timer"}, {"disable", "--now", "anqu.timer"}, {"enable", "--now", ServiceName}, {"restart", ServiceName}}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("timer retry calls %v; want %v", calls, want)
			}
		})
	}
}

func TestInvalidLegacyTimerPreventsServiceActivation(t *testing.T) {
	_, paths := fixture(t)
	if err := ensureDirectory(paths.directory); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(filepath.Dir(paths.service), "agent.timer"), 0755); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	if err := installService(paths, testOperations(t, &calls).systemctl, false); err == nil || !strings.Contains(err.Error(), "legacy timer") {
		t.Fatalf("invalid timer detection error: %v", err)
	}
	if !reflect.DeepEqual(calls, [][]string{{"daemon-reload"}}) {
		t.Fatalf("service enabled despite invalid timer: %v", calls)
	}
	if pending, err := serviceInstallationPending(paths.directory); err != nil || !pending {
		t.Fatalf("invalid timer not retained for retry: %t, error %v", pending, err)
	}
}

func TestExistingServiceIsRestartedForUploadedUpgrade(t *testing.T) {
	requireSymlinks(t)
	source, paths := fixture(t)
	put(t, source, "updated binary")
	put(t, paths.executable, "previous binary")
	put(t, paths.service, "legacy service")
	put(t, filepath.Join(paths.directory, "agent.connection.json"), "existing connection settings")
	put(t, filepath.Join(filepath.Dir(source), "agent.connection.json"), "uploaded connection settings")
	var commands [][]string
	prepared, err := prepare(source, nil, nil, paths, testOperations(t, &commands))
	if err != nil || !prepared.InstallOnly {
		t.Fatalf("preparation %+v, error %v", prepared, err)
	}
	want := [][]string{{"daemon-reload"}, {"enable", "--now", ServiceName}, {"restart", ServiceName}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("upgrade commands %v; want %v", commands, want)
	}
	wantFile(t, paths.executable, "updated binary")
	wantFile(t, filepath.Join(paths.directory, "agent.connection.json"), "existing connection settings")
	wantFile(t, paths.service+".anquan.bak", "legacy service")
}

func TestServiceActivationFailureStopsAndUploadedRetryCanSucceed(t *testing.T) {
	requireSymlinks(t)
	for _, failedCall := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(failedCall), func(t *testing.T) {
			source, paths := fixture(t)
			put(t, source, "uploaded binary")
			if failedCall == 3 {
				put(t, paths.service, "legacy service")
			}
			var commands [][]string
			ops := testOperations(t, &commands)
			failure := errors.New("injected systemctl failure")
			ops.systemctl = func(args ...string) error {
				commands = append(commands, append([]string(nil), args...))
				if len(commands) == failedCall {
					return failure
				}
				return nil
			}
			var output bytes.Buffer
			if _, err := prepare(source, nil, &output, paths, ops); !errors.Is(err, failure) {
				t.Fatalf("systemctl failure not propagated: %v", err)
			}
			if len(commands) != failedCall || output.Len() != 0 {
				t.Fatalf("continued after failure: %v, output %q", commands, output.String())
			}
			commands = nil
			prepared, err := prepare(source, nil, nil, paths, testOperations(t, &commands))
			if err != nil || !prepared.InstallOnly || len(commands) != 3 {
				t.Fatalf("retry %+v, commands %v, error %v", prepared, commands, err)
			}
		})
	}
}

func TestFirstDeploymentRequiresRootBeforeChangingFiles(t *testing.T) {
	source, paths := fixture(t)
	put(t, source, "uploaded binary")
	var commands [][]string
	ops := testOperations(t, &commands)
	ops.euid = func() int { return 1000 }
	if _, err := prepare(source, nil, nil, paths, ops); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("first installation as non-root: %v", err)
	}
	if _, err := os.Stat(paths.directory); !os.IsNotExist(err) {
		t.Fatal("non-root installation changed target directory")
	}
	if len(commands) != 0 {
		t.Fatalf("non-root installation invoked systemctl: %v", commands)
	}
}

func TestExplicitModesKeepForegroundExecution(t *testing.T) {
	requireSymlinks(t)
	for _, args := range [][]string{{"-service"}, {"-master", "192.0.2.8"}} {
		source, paths := fixture(t)
		put(t, source, "uploaded binary")
		var commands [][]string
		ops := testOperations(t, &commands)
		var started []string
		ops.exec = func(path string, argv, _ []string) error {
			if path != paths.executable {
				t.Fatalf("wrong executable %q", path)
			}
			started = append([]string(nil), argv...)
			return nil
		}
		prepared, err := prepare(source, args, nil, paths, ops)
		if err != nil || prepared.InstallOnly || len(commands) != 0 {
			t.Fatalf("explicit mode: %+v, commands %v, error %v", prepared, commands, err)
		}
		if !reflect.DeepEqual(started, append([]string{paths.executable}, args...)) {
			t.Fatalf("foreground args %v", started)
		}
	}
}

func TestNonLinuxPrepareDoesNotInstall(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("development-platform behavior")
	}
	source, paths := fixture(t)
	put(t, source, "uploaded binary")
	prepared, err := Prepare(source, nil, nil)
	if err != nil || prepared.Path != source || prepared.InstallOnly {
		t.Fatalf("non-Linux preparation %+v, error %v", prepared, err)
	}
	if _, err := os.Stat(paths.directory); !os.IsNotExist(err) {
		t.Fatal("non-Linux preparation installed files")
	}
}
