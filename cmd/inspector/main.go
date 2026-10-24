// inspector is the fixed, offline entrypoint of the isolated runner image.
package main

import (
	"example.com/unified-harness/internal/runner"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	deadline := flag.Int64("deadline-unix-ms", 0, "hard stop time")
	memory := flag.Int64("memory-bytes", 128<<20, "memory cap")
	cpu := flag.Int64("cpu-millis", 500, "CPU cap")
	pids := flag.Int("pids", 32, "PID cap")
	tmp := flag.Int64("tmp-bytes", 16<<20, "scratch cap")
	flag.Parse()
	remaining := time.Until(time.UnixMilli(*deadline))
	if remaining <= 0 || remaining > 5*time.Minute || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "invalid inspector deadline")
		os.Exit(2)
	}
	// This watchdog survives loss of the worker process/connection.
	timer := time.AfterFunc(remaining, func() { os.Exit(124) })
	defer timer.Stop()
	if err := runner.CheckIsolation(runner.Limits{MemoryBytes: *memory, CPUMillis: *cpu, PIDs: *pids, TmpBytes: *tmp}); err != nil {
		fmt.Fprintln(os.Stderr, "isolation preflight failed")
		os.Exit(2)
	}
	if err := runner.InspectStream(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "inspection rejected")
		os.Exit(2)
	}
}
