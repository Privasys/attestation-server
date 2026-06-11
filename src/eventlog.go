package main

// CC event log (CCEL) parsing and quote cross-checking.
//
// A TDX quote proves the *final* values of the four RTMRs but says
// nothing about how they got there. The CC event log records every
// individual extend operation (shim/GRUB Authenticode hashes, each
// grub_cmd, the kernel, the initrd, the command line with the
// dm-verity root hash, ...). On its own the log is unauthenticated
// hearsay: nothing stops a host from handing the verifier a forged
// log. Replaying the log and requiring the reconstructed registers to
// equal the quote's RTMRs binds the two together — if they match, the
// log is exactly the sequence of extends that produced the attested
// registers, and its per-event digests become trustworthy,
// fine-grained evidence (e.g. for pinpointing WHICH boot component
// changed after an image upgrade).
//
// Format: TCG EFI crypto-agile log (TCG PC Client Platform Firmware
// Profile, TCG_PCR_EVENT2), as exposed by Linux at
// /sys/firmware/acpi/tables/data/CCEL on TDX guests. The first event
// is a SHA1-format TCG_PCClientPCREvent header (Spec ID Event03);
// subsequent events carry a digest per algorithm. TDX uses SHA-384
// only.
//
// Register mapping: CC MR index n in the log corresponds to RTMR[n-1]
// (index 0 is MRTD, which is never extended through the log).

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	evNoAction       = 0x00000003
	sha384AlgID      = 0x000C
	sha384Size       = 48
	maxEventLogSize  = 4 << 20 // 4 MiB: real CCELs are tens of KiB
	maxEventDataSize = 1 << 20
)

// ccelEvent is one parsed event from the CC event log.
type ccelEvent struct {
	MRIndex   uint32 // CC MR index as recorded (1..4 → RTMR[0..3])
	EventType uint32
	Digest    [sha384Size]byte
	Data      []byte
}

// EventSummary is the JSON shape of one event in the verify response
// (returned when the caller sets includeEventLog).
type EventSummary struct {
	RTMR      int    `json:"rtmr"`
	EventType string `json:"eventType"`
	Digest    string `json:"digest"`
	// Data carries the event payload when it is printable text
	// (grub_cmd lines, kernel command line, file paths). Binary
	// payloads are omitted.
	Data string `json:"data,omitempty"`
}

// eventTypeNames covers the event types TDVF/GRUB actually emit on
// our boot path; anything else is rendered as EV_0x%08X.
var eventTypeNames = map[uint32]string{
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000D: "EV_IPL",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
}

func eventTypeName(t uint32) string {
	if n, ok := eventTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("EV_0x%08X", t)
}

// parseCCEL parses a crypto-agile CC event log into its events.
func parseCCEL(raw []byte) ([]ccelEvent, error) {
	if len(raw) > maxEventLogSize {
		return nil, fmt.Errorf("event log too large (%d bytes)", len(raw))
	}
	r := &logReader{buf: raw}

	// --- Header event (SHA1 format, EV_NO_ACTION, Spec ID Event03) ---
	hdrIndex, err := r.u32()
	if err != nil {
		return nil, fmt.Errorf("truncated header: %w", err)
	}
	hdrType, err := r.u32()
	if err != nil {
		return nil, fmt.Errorf("truncated header: %w", err)
	}
	if hdrType != evNoAction {
		return nil, fmt.Errorf("first event must be EV_NO_ACTION (Spec ID), got %s", eventTypeName(hdrType))
	}
	_ = hdrIndex
	if err := r.skip(20); err != nil { // SHA1-sized digest, always zero
		return nil, fmt.Errorf("truncated header digest: %w", err)
	}
	hdrLen, err := r.u32()
	if err != nil {
		return nil, fmt.Errorf("truncated header length: %w", err)
	}
	hdrData, err := r.bytes(int(hdrLen))
	if err != nil {
		return nil, fmt.Errorf("truncated header data: %w", err)
	}
	if !strings.HasPrefix(string(hdrData), "Spec ID Event03") {
		return nil, errors.New("header is not a Spec ID Event03 (not a crypto-agile log)")
	}

	// --- Crypto-agile events ---
	var events []ccelEvent
	for r.remaining() > 0 {
		// A log captured from a fixed-size ACPI region may be padded
		// with 0xFF or zeros after the last event.
		if r.atPadding() {
			break
		}
		mrIndex, err := r.u32()
		if err != nil {
			return nil, fmt.Errorf("event %d: truncated index: %w", len(events), err)
		}
		evType, err := r.u32()
		if err != nil {
			return nil, fmt.Errorf("event %d: truncated type: %w", len(events), err)
		}
		digestCount, err := r.u32()
		if err != nil {
			return nil, fmt.Errorf("event %d: truncated digest count: %w", len(events), err)
		}
		if digestCount == 0 || digestCount > 8 {
			return nil, fmt.Errorf("event %d: implausible digest count %d", len(events), digestCount)
		}
		var ev ccelEvent
		ev.MRIndex = mrIndex
		ev.EventType = evType
		haveSHA384 := false
		for i := uint32(0); i < digestCount; i++ {
			algID, err := r.u16()
			if err != nil {
				return nil, fmt.Errorf("event %d: truncated digest alg: %w", len(events), err)
			}
			size, ok := digestSize(algID)
			if !ok {
				return nil, fmt.Errorf("event %d: unknown digest algorithm 0x%04X", len(events), algID)
			}
			d, err := r.bytes(size)
			if err != nil {
				return nil, fmt.Errorf("event %d: truncated digest: %w", len(events), err)
			}
			if algID == sha384AlgID {
				copy(ev.Digest[:], d)
				haveSHA384 = true
			}
		}
		if !haveSHA384 {
			return nil, fmt.Errorf("event %d: no SHA-384 digest (TDX RTMRs are SHA-384)", len(events))
		}
		dataLen, err := r.u32()
		if err != nil {
			return nil, fmt.Errorf("event %d: truncated data length: %w", len(events), err)
		}
		if dataLen > maxEventDataSize {
			return nil, fmt.Errorf("event %d: implausible data length %d", len(events), dataLen)
		}
		data, err := r.bytes(int(dataLen))
		if err != nil {
			return nil, fmt.Errorf("event %d: truncated data: %w", len(events), err)
		}
		ev.Data = data
		events = append(events, ev)
	}
	return events, nil
}

// digestSize maps TPM_ALG_ID to digest length for the algorithms a
// CCEL can plausibly carry.
func digestSize(alg uint16) (int, bool) {
	switch alg {
	case 0x0004: // SHA1
		return 20, true
	case 0x000B: // SHA256
		return 32, true
	case sha384AlgID: // SHA384
		return 48, true
	case 0x000D: // SHA512
		return 64, true
	}
	return 0, false
}

// replayCCEL folds the parsed events into the four RTMR hash chains:
// RTMR ← SHA384(RTMR ∥ digest). EV_NO_ACTION events are informational
// and never extended by the firmware.
func replayCCEL(events []ccelEvent) (rtmrs [4][sha384Size]byte, err error) {
	for i, ev := range events {
		if ev.EventType == evNoAction {
			continue
		}
		if ev.MRIndex < 1 || ev.MRIndex > 4 {
			return rtmrs, fmt.Errorf("event %d: CC MR index %d out of range (expected 1..4)", i, ev.MRIndex)
		}
		reg := ev.MRIndex - 1
		h := sha512.New384()
		h.Write(rtmrs[reg][:])
		h.Write(ev.Digest[:])
		copy(rtmrs[reg][:], h.Sum(nil))
	}
	return rtmrs, nil
}

// crossCheckEventLog parses the log, replays it, and compares the
// reconstructed registers against the quote's RTMRs. It returns the
// parsed events for optional inclusion in the response. A mismatch on
// any register is an error: the log does not describe the boot the
// quote attests.
func crossCheckEventLog(raw []byte, quoteRtmrs [][]byte) ([]ccelEvent, error) {
	if len(quoteRtmrs) != 4 {
		return nil, fmt.Errorf("quote carries %d RTMRs, expected 4", len(quoteRtmrs))
	}
	events, err := parseCCEL(raw)
	if err != nil {
		return nil, fmt.Errorf("event log parse: %w", err)
	}
	replayed, err := replayCCEL(events)
	if err != nil {
		return nil, fmt.Errorf("event log replay: %w", err)
	}
	for i := 0; i < 4; i++ {
		if !bytesEqual(replayed[i][:], quoteRtmrs[i]) {
			return nil, fmt.Errorf(
				"RTMR[%d] mismatch: event log replays to %s but quote attests %s",
				i, hex.EncodeToString(replayed[i][:]), hex.EncodeToString(quoteRtmrs[i]))
		}
	}
	return events, nil
}

// summarizeEvents renders parsed events for the JSON response,
// skipping the informational EV_NO_ACTION entries.
func summarizeEvents(events []ccelEvent) []EventSummary {
	out := make([]EventSummary, 0, len(events))
	for _, ev := range events {
		if ev.EventType == evNoAction {
			continue
		}
		s := EventSummary{
			RTMR:      int(ev.MRIndex) - 1,
			EventType: eventTypeName(ev.EventType),
			Digest:    hex.EncodeToString(ev.Digest[:]),
		}
		if txt, ok := printableData(ev.Data); ok {
			s.Data = txt
		}
		out = append(out, s)
	}
	return out
}

// printableData returns the event payload as text when it is plain
// ASCII (possibly NUL-terminated), which covers EV_IPL events
// (grub_cmd, kernel_cmdline, file paths) and EV_EFI_ACTION strings.
func printableData(data []byte) (string, bool) {
	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" || len(trimmed) > 4096 {
		return "", false
	}
	for _, r := range trimmed {
		if r > unicode.MaxASCII || (!unicode.IsPrint(r) && r != '\n' && r != '\t') {
			return "", false
		}
	}
	return trimmed, true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// logReader is a bounds-checked little-endian cursor.
type logReader struct {
	buf []byte
	off int
}

func (r *logReader) remaining() int { return len(r.buf) - r.off }

func (r *logReader) atPadding() bool {
	// The next event would need at least 12 bytes of header; treat a
	// run of 0x00 or 0xFF from here as ACPI-region padding.
	rest := r.buf[r.off:]
	if len(rest) >= 8 {
		rest = rest[:8]
	}
	allZero, allFF := true, true
	for _, b := range rest {
		if b != 0x00 {
			allZero = false
		}
		if b != 0xFF {
			allFF = false
		}
	}
	return allZero || allFF
}

func (r *logReader) u16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errors.New("unexpected end of log")
	}
	v := binary.LittleEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v, nil
}

func (r *logReader) u32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errors.New("unexpected end of log")
	}
	v := binary.LittleEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *logReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, errors.New("unexpected end of log")
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b, nil
}

func (r *logReader) skip(n int) error {
	_, err := r.bytes(n)
	return err
}
