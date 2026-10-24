// Package artifact stores immutable, scoped, content-addressed artifacts.
package artifact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
)

const MaxBytes = 64 << 10

type Store interface {
	Put(context.Context, string, string, []byte) error
	Get(context.Context, string, string) ([]byte, error)
}
type Local struct{ root *os.Root }

func OpenLocal(path string) (*Local, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &Local{root: root}, nil
}
func (s *Local) Close() error          { return s.root.Close() }
func Digest(b []byte) string           { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func Scope(project, run string) string { return Digest([]byte(project + "\x00" + run)) }
func key(scope, digest string) (string, error) {
	valid := regexp.MustCompile("^[0-9a-f]{64}$")
	if !valid.MatchString(scope) || !valid.MatchString(digest) {
		return "", errors.New("invalid artifact key")
	}
	return scope + "-" + digest + ".json", nil
}
func (s *Local) Get(ctx context.Context, scope, digest string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := key(scope, digest)
	if err != nil {
		return nil, err
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes {
		return nil, errors.New("invalid artifact file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(b) > MaxBytes || Digest(b) != digest {
		return nil, errors.New("artifact integrity failure")
	}
	return b, nil
}
func (s *Local) Put(ctx context.Context, scope, digest string, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := key(scope, digest)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > MaxBytes || Digest(raw) != digest {
		return errors.New("artifact digest or size mismatch")
	}
	// Do not overwrite a damaged existing object: surface corruption.
	if _, err = s.Get(ctx, scope, digest); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var entropy [16]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return err
	}
	tmp := fmt.Sprintf(".pending-%x", entropy[:])
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(tmp)
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Concurrent writers of this immutable hash can only publish the same bytes.
	if err = s.root.Rename(tmp, name); err != nil {
		if _, readErr := s.Get(ctx, scope, digest); readErr == nil {
			return nil
		}
		return err
	}
	if runtime.GOOS != "windows" {
		dir, e := s.root.Open(".")
		if e != nil {
			return e
		}
		e = dir.Sync()
		_ = dir.Close()
		if e != nil {
			return e
		}
	}
	_, err = s.Get(ctx, scope, digest)
	return err
}
