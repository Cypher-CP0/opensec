//go:build !linux

package runner

import "errors"

func CheckIsolation(Limits) error { return errors.New("isolated inspector requires Linux containers") }
