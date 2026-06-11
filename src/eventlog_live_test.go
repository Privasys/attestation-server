package main

// Live-data test: cross-checks a real CC event log against a real TDX
// quote captured from the same running machine. Skipped unless the
// CCEL_B64_FILE and QUOTE_B64_FILE environment variables point at
// base64-encoded captures (e.g. of /sys/firmware/acpi/tables/data/CCEL
// and a configfs-tsm outblob).

import (
	"encoding/base64"
	"os"
	"testing"

	tdxAbi "github.com/google/go-tdx-guest/abi"
	tdxPb "github.com/google/go-tdx-guest/proto/tdx"
)

func TestCrossCheckLiveCapture(t *testing.T) {
	ccelPath := os.Getenv("CCEL_B64_FILE")
	quotePath := os.Getenv("QUOTE_B64_FILE")
	if ccelPath == "" || quotePath == "" {
		t.Skip("CCEL_B64_FILE / QUOTE_B64_FILE not set")
	}
	readB64 := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		raw, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil {
			t.Fatalf("decode %s: %v", p, err)
		}
		return raw
	}
	ccelRaw := readB64(ccelPath)
	quoteRaw := readB64(quotePath)

	parsed, err := tdxAbi.QuoteToProto(quoteRaw)
	if err != nil {
		t.Fatalf("parse quote: %v", err)
	}
	q4 := parsed.(*tdxPb.QuoteV4)
	rtmrs := q4.GetTdQuoteBody().GetRtmrs()

	events, err := crossCheckEventLog(ccelRaw, rtmrs)
	if err != nil {
		t.Fatalf("cross-check against live capture failed: %v", err)
	}
	t.Logf("cross-check OK: %d events replay exactly to the quote's RTMRs", len(events))

	summaries := summarizeEvents(events)
	var grubCmds, textual int
	for _, s := range summaries {
		if s.Data != "" {
			textual++
		}
		if len(s.Data) >= 9 && s.Data[:9] == "grub_cmd:" {
			grubCmds++
		}
	}
	if grubCmds == 0 {
		t.Error("expected grub_cmd events in a real boot log")
	}
	t.Logf("%d events total, %d with printable payloads, %d grub_cmd", len(summaries), textual, grubCmds)
}
