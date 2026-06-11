package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"strings"
	"testing"
)

// buildTestLog assembles a minimal crypto-agile CCEL: a Spec ID
// header followed by the given events (all SHA-384).
func buildTestLog(events []ccelEvent, padding []byte) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian

	// Header: TCG_PCClientPCREvent (SHA1 format), EV_NO_ACTION.
	binary.Write(&b, le, uint32(0))          // mr index
	binary.Write(&b, le, uint32(evNoAction)) // event type
	b.Write(make([]byte, 20))                // SHA1-sized zero digest
	specID := append([]byte("Spec ID Event03\x00"), make([]byte, 24)...)
	binary.Write(&b, le, uint32(len(specID)))
	b.Write(specID)

	for _, ev := range events {
		binary.Write(&b, le, ev.MRIndex)
		binary.Write(&b, le, ev.EventType)
		binary.Write(&b, le, uint32(1)) // digest count
		binary.Write(&b, le, uint16(sha384AlgID))
		b.Write(ev.Digest[:])
		binary.Write(&b, le, uint32(len(ev.Data)))
		b.Write(ev.Data)
	}
	b.Write(padding)
	return b.Bytes()
}

func sha384Of(data string) (d [sha384Size]byte) {
	h := sha512.Sum384([]byte(data))
	copy(d[:], h[:])
	return
}

// expectedRtmrs replays events the trivial way for comparison.
func expectedRtmrs(events []ccelEvent) [][]byte {
	regs := make([][]byte, 4)
	for i := range regs {
		regs[i] = make([]byte, sha384Size)
	}
	for _, ev := range events {
		if ev.EventType == evNoAction {
			continue
		}
		h := sha512.New384()
		h.Write(regs[ev.MRIndex-1])
		h.Write(ev.Digest[:])
		regs[ev.MRIndex-1] = h.Sum(nil)
	}
	return regs
}

func testEvents() []ccelEvent {
	return []ccelEvent{
		{MRIndex: 1, EventType: 0x80000003, Digest: sha384Of("shim"), Data: []byte{0x01, 0x02}},
		{MRIndex: 1, EventType: 0x80000003, Digest: sha384Of("grub"), Data: []byte{0x03}},
		{MRIndex: 2, EventType: 0x0000000D, Digest: sha384Of("grub_cmd: linux ..."), Data: []byte("grub_cmd: linux /vmlinuz root=/dev/mapper/verity\x00")},
		{MRIndex: 2, EventType: 0x0000000D, Digest: sha384Of("kernel"), Data: []byte("/vmlinuz\x00")},
		{MRIndex: 3, EventType: 0x00000004, Digest: sha384Of("sep"), Data: []byte{0, 0, 0, 0}},
	}
}

func TestParseAndReplayRoundTrip(t *testing.T) {
	events := testEvents()
	raw := buildTestLog(events, nil)

	parsed, err := parseCCEL(raw)
	if err != nil {
		t.Fatalf("parseCCEL: %v", err)
	}
	if len(parsed) != len(events) {
		t.Fatalf("parsed %d events, want %d", len(parsed), len(events))
	}
	if got := string(parsed[2].Data); !strings.HasPrefix(got, "grub_cmd: linux") {
		t.Fatalf("event 2 data mangled: %q", got)
	}

	if _, err := crossCheckEventLog(raw, expectedRtmrs(events)); err != nil {
		t.Fatalf("cross-check should pass: %v", err)
	}
}

func TestCrossCheckDetectsMismatch(t *testing.T) {
	events := testEvents()
	raw := buildTestLog(events, nil)

	good := expectedRtmrs(events)
	good[1][0] ^= 0xFF // corrupt RTMR[1]
	_, err := crossCheckEventLog(raw, good)
	if err == nil {
		t.Fatal("cross-check passed against corrupted RTMR")
	}
	if !strings.Contains(err.Error(), "RTMR[1] mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCrossCheckDetectsTamperedLog(t *testing.T) {
	events := testEvents()
	good := expectedRtmrs(events)

	// An attacker swaps in a different grub_cmd digest.
	events[2].Digest = sha384Of("grub_cmd: linux /evil")
	raw := buildTestLog(events, nil)

	if _, err := crossCheckEventLog(raw, good); err == nil {
		t.Fatal("cross-check passed against tampered event log")
	}
}

func TestParseToleratesACPIPadding(t *testing.T) {
	events := testEvents()
	for _, pad := range [][]byte{bytes.Repeat([]byte{0x00}, 512), bytes.Repeat([]byte{0xFF}, 512)} {
		raw := buildTestLog(events, pad)
		parsed, err := parseCCEL(raw)
		if err != nil {
			t.Fatalf("parseCCEL with padding: %v", err)
		}
		if len(parsed) != len(events) {
			t.Fatalf("parsed %d events, want %d", len(parsed), len(events))
		}
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":      {},
		"truncated":  buildTestLog(testEvents(), nil)[:40],
		"not-a-log":  []byte("hello world this is not an event log at all............"),
		"wrong-head": append([]byte{9, 0, 0, 0, 9, 0, 0, 0}, make([]byte, 64)...),
	}
	for name, raw := range cases {
		if _, err := parseCCEL(raw); err == nil {
			t.Errorf("%s: parseCCEL accepted invalid input", name)
		}
	}
}

func TestSummarizeEvents(t *testing.T) {
	events := testEvents()
	sum := summarizeEvents(events)
	if len(sum) != len(events) {
		t.Fatalf("summarized %d, want %d", len(sum), len(events))
	}
	if sum[2].EventType != "EV_IPL" {
		t.Fatalf("event 2 type = %s, want EV_IPL", sum[2].EventType)
	}
	if sum[2].RTMR != 1 {
		t.Fatalf("event 2 rtmr = %d, want 1 (CC MR 2)", sum[2].RTMR)
	}
	if !strings.HasPrefix(sum[2].Data, "grub_cmd: linux") {
		t.Fatalf("event 2 printable data missing: %q", sum[2].Data)
	}
	if sum[0].Data != "" {
		t.Fatalf("binary payload should not be rendered as text: %q", sum[0].Data)
	}
}
