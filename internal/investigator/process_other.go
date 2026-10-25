//go:build !linux

package investigator

import (
	"errors"
	"os/exec"
)

func terminateProcess(*exec.Cmd) {}
func isolateProcess(*exec.Cmd) error {
	return errors.New("live model CLI requires Linux/WSL process-group cancellation")
}
