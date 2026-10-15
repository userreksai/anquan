//go:build !linux

package audit

import (
	"context"
	"fmt"
	"io"
)

func RequestSSHExecution(context.Context, string, SSHExecutionRequest) error {
	return fmt.Errorf("SSH execution IPC is supported only on Linux")
}

func CurrentSSHExecutionCaller() (SSHExecutionCaller, error) {
	return SSHExecutionCaller{}, fmt.Errorf("SSH execution caller identification is supported only on Linux")
}

func serveSSHExecutions(context.Context, Config, io.Writer) error {
	return fmt.Errorf("SSH execution IPC is supported only on Linux")
}
