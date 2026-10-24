// Package configfile loads bounded, strict JSON configuration.
package configfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const MaxBytes = 4 << 20

func Decode(raw []byte, out any) error {
	if len(raw) > MaxBytes || !json.Valid(raw) {
		return errors.New("expected JSON of at most 4 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
func Read(path string, out any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return err
	}
	return Decode(raw, out)
}
