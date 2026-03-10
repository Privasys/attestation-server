package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Minimal Prometheus-compatible metrics — zero external dependencies.

var (
	verifyTotal        atomic.Int64
	verifySuccessTotal atomic.Int64
	verifyFailTotal    atomic.Int64
	verifySGXTotal     atomic.Int64
	verifyTDXTotal     atomic.Int64
	authFailTotal      atomic.Int64

	// Histogram buckets (seconds): 10ms, 50ms, 100ms, 250ms, 500ms, 1s, 5s
	histBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0}

	histMu    sync.Mutex
	histCount int64
	histSum   float64
	histBins  [7]int64 // one per bucket
)

func recordVerifyDuration(d time.Duration) {
	secs := d.Seconds()
	histMu.Lock()
	histCount++
	histSum += secs
	for i, b := range histBuckets {
		if secs <= b {
			histBins[i]++
		}
	}
	histMu.Unlock()
}

func metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP attestation_verify_total Total verification requests.\n")
	fmt.Fprintf(w, "# TYPE attestation_verify_total counter\n")
	fmt.Fprintf(w, "attestation_verify_total %d\n", verifyTotal.Load())

	fmt.Fprintf(w, "# HELP attestation_verify_success_total Successful verifications.\n")
	fmt.Fprintf(w, "# TYPE attestation_verify_success_total counter\n")
	fmt.Fprintf(w, "attestation_verify_success_total %d\n", verifySuccessTotal.Load())

	fmt.Fprintf(w, "# HELP attestation_verify_fail_total Failed verifications.\n")
	fmt.Fprintf(w, "# TYPE attestation_verify_fail_total counter\n")
	fmt.Fprintf(w, "attestation_verify_fail_total %d\n", verifyFailTotal.Load())

	fmt.Fprintf(w, "# HELP attestation_verify_sgx_total SGX quote verifications.\n")
	fmt.Fprintf(w, "# TYPE attestation_verify_sgx_total counter\n")
	fmt.Fprintf(w, "attestation_verify_sgx_total %d\n", verifySGXTotal.Load())

	fmt.Fprintf(w, "# HELP attestation_verify_tdx_total TDX quote verifications.\n")
	fmt.Fprintf(w, "# TYPE attestation_verify_tdx_total counter\n")
	fmt.Fprintf(w, "attestation_verify_tdx_total %d\n", verifyTDXTotal.Load())

	fmt.Fprintf(w, "# HELP attestation_auth_fail_total Authentication failures.\n")
	fmt.Fprintf(w, "# TYPE attestation_auth_fail_total counter\n")
	fmt.Fprintf(w, "attestation_auth_fail_total %d\n", authFailTotal.Load())

	histMu.Lock()
	count := histCount
	sum := histSum
	bins := histBins
	histMu.Unlock()

	fmt.Fprintf(w, "# HELP attestation_verify_duration_seconds Verification latency.\n")
	fmt.Fprintf(w, "# TYPE attestation_verify_duration_seconds histogram\n")
	var cumulative int64
	for i, b := range histBuckets {
		cumulative += bins[i]
		fmt.Fprintf(w, "attestation_verify_duration_seconds_bucket{le=\"%.3f\"} %d\n", b, cumulative)
	}
	fmt.Fprintf(w, "attestation_verify_duration_seconds_bucket{le=\"+Inf\"} %d\n", count)
	fmt.Fprintf(w, "attestation_verify_duration_seconds_sum %.6f\n", sum)
	fmt.Fprintf(w, "attestation_verify_duration_seconds_count %d\n", count)
}
