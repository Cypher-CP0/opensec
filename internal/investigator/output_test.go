package investigator

import (
	"context"
	"io"
	"strings"
	"testing"
)

// io.Copy uses ReaderFrom when a writer exposes it. Embedding bytes.Buffer
// accidentally promoted that method and bypassed the bounded Write method.
func TestCLIOutputCopyCannotBypassLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &cappedWriter{limit: 32, cancel: cancel}
	source := io.LimitReader(strings.NewReader(strings.Repeat("x", 64)), 64)
	_, err := io.Copy(w, source)
	if err == nil || !w.exceeded || ctx.Err() == nil || len(w.Bytes()) > 32 {
		t.Fatalf("copy bypassed bound: error=%v exceeded=%v cancelled=%v stored=%d", err, w.exceeded, ctx.Err(), len(w.Bytes()))
	}
	if _, ok := any(w).(io.ReaderFrom); ok {
		t.Fatal("writer must not expose an unbounded ReaderFrom")
	}
}
