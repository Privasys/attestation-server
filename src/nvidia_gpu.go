package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// NVIDIA GPU attestation verification via NVIDIA Remote Attestation
// Service (NRAS). The NRAS endpoint is configured with --nvidia-nras-url
// or the NVIDIA_NRAS_URL environment variable.

// nvidiaVerifierURL is set from the flag / environment in main.go.
var nvidiaVerifierURL string

// verifyNVIDIAGPU verifies NVIDIA GPU attestation evidence by forwarding
// it to NVIDIA's Remote Attestation Service (NRAS). The evidence must be
// sent with an explicit "type":"nvidia-gpu" in the request because the
// binary format is not auto-detectable from Intel/AMD quote headers.
func verifyNVIDIAGPU(w http.ResponseWriter, evidence []byte, start time.Time) {
	url := nvidiaVerifierURL
	if url == "" {
		url = os.Getenv("NVIDIA_NRAS_URL")
	}
	if url == "" {
		verifyFailTotal.Add(1)
		sendJSON(w, 400, VerifyResponse{
			Success: false,
			Error:   "NVIDIA GPU attestation not configured (set --nvidia-nras-url or NVIDIA_NRAS_URL)",
		})
		return
	}

	result, err := forwardToNRAS(url, evidence)
	if err != nil {
		verifyFailTotal.Add(1)
		recordVerifyDuration(time.Since(start))
		sendJSON(w, 200, VerifyResponse{
			Success: false,
			Status:  "VERIFICATION_FAILED",
			TeeType: "nvidia-gpu",
			Error:   fmt.Sprintf("NVIDIA GPU verification failed: %v", err),
		})
		return
	}

	verifySuccessTotal.Add(1)
	recordVerifyDuration(time.Since(start))
	sendJSON(w, 200, VerifyResponse{
		Success: true,
		Status:  "OK",
		TeeType: "nvidia-gpu",
		Message: result,
	})
}

// nrasRequest is the envelope sent to NVIDIA NRAS.
type nrasRequest struct {
	EvidenceList []nrasEvidence `json:"evidence_list"`
	Nonce        string         `json:"nonce,omitempty"`
}

type nrasEvidence struct {
	Evidence string `json:"evidence"`
}

// nrasResponse captures the top-level NRAS response.
type nrasResponse struct {
	EATToken string `json:"eat_token,omitempty"`
	Status   string `json:"status,omitempty"`
	Message  string `json:"message,omitempty"`
}

// forwardToNRAS sends the GPU evidence to NVIDIA NRAS and returns a
// human-readable result string on success or an error on failure.
func forwardToNRAS(nrasURL string, evidence []byte) (string, error) {
	reqBody := nrasRequest{
		EvidenceList: []nrasEvidence{
			{Evidence: encodeBase64(evidence)},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal NRAS request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", nrasURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create NRAS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("NRAS request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		return "", fmt.Errorf("read NRAS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("NRAS returned HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	var nras nrasResponse
	if err := json.Unmarshal(respBody, &nras); err != nil {
		return "", fmt.Errorf("parse NRAS response: %w", err)
	}

	if nras.EATToken != "" {
		return "NVIDIA GPU attestation verified via NRAS (EAT token received)", nil
	}
	if nras.Status != "" {
		return fmt.Sprintf("NVIDIA GPU attestation: %s", nras.Status), nil
	}
	return "NVIDIA GPU attestation forwarded to NRAS", nil
}

func encodeBase64(data []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	buf := make([]byte, ((len(data)+2)/3)*4)
	for i, j := 0, 0; i < len(data); i, j = i+3, j+4 {
		var val uint32
		remaining := len(data) - i
		for k := 0; k < 3 && i+k < len(data); k++ {
			val |= uint32(data[i+k]) << (16 - 8*k)
		}
		buf[j] = enc[(val>>18)&0x3f]
		buf[j+1] = enc[(val>>12)&0x3f]
		if remaining > 1 {
			buf[j+2] = enc[(val>>6)&0x3f]
		} else {
			buf[j+2] = '='
		}
		if remaining > 2 {
			buf[j+3] = enc[val&0x3f]
		} else {
			buf[j+3] = '='
		}
	}
	return string(buf)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
