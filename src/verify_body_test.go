package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyRefusesOversizedBody(t *testing.T) {
	body := `{"quote":"` + strings.Repeat("A", maxVerifyBody) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	verifyHandler(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}

	// A body inside the bound is parsed as before.
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"quote":""}`))
	rec = httptest.NewRecorder()
	verifyHandler(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Missing 'quote'") {
		t.Fatalf("status = %d body %q, want the missing-quote 400", rec.Code, rec.Body.String())
	}
}
