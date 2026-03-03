package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
//  reverseBytes
// ---------------------------------------------------------------------------

func TestReverseBytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5}
	out := reverseBytes(in)
	want := []byte{5, 4, 3, 2, 1}
	for i, b := range out {
		if b != want[i] {
			t.Fatalf("reverseBytes[%d] = %d, want %d", i, b, want[i])
		}
	}
	// Verify input unchanged
	if in[0] != 1 {
		t.Fatal("reverseBytes mutated input")
	}
}

func TestReverseBytesEmpty(t *testing.T) {
	out := reverseBytes(nil)
	if len(out) != 0 {
		t.Fatal("expected empty")
	}
}

// ---------------------------------------------------------------------------
//  ecdsaKeyAutoDetect
// ---------------------------------------------------------------------------

func TestEcdsaKeyAutoDetect_BigEndian(t *testing.T) {
	// Generate a real P-256 key, serialize (x||y) in big-endian
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	key.X.FillBytes(raw[:32])
	key.Y.FillBytes(raw[32:])

	pub, le, err := ecdsaKeyAutoDetect(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if le {
		t.Fatal("expected big-endian detection")
	}
	if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Fatal("key mismatch")
	}
}

func TestEcdsaKeyAutoDetect_LittleEndian(t *testing.T) {
	// Generate a real P-256 key, serialize (x||y) in little-endian
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xBE := make([]byte, 32)
	yBE := make([]byte, 32)
	key.X.FillBytes(xBE)
	key.Y.FillBytes(yBE)

	raw := make([]byte, 64)
	copy(raw[:32], reverseBytes(xBE))
	copy(raw[32:], reverseBytes(yBE))

	// Make sure the BE interpretation is NOT on the curve
	// (statistically guaranteed for random keys)
	xCheck := new(big.Int).SetBytes(raw[:32])
	yCheck := new(big.Int).SetBytes(raw[32:])
	if elliptic.P256().IsOnCurve(xCheck, yCheck) {
		t.Skip("extremely unlikely: LE encoding is also valid BE — skipping")
	}

	pub, le, err := ecdsaKeyAutoDetect(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !le {
		t.Fatal("expected little-endian detection")
	}
	if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Fatal("key mismatch")
	}
}

func TestEcdsaKeyAutoDetect_InvalidLength(t *testing.T) {
	_, _, err := ecdsaKeyAutoDetect(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestEcdsaKeyAutoDetect_InvalidPoint(t *testing.T) {
	// All zeros is not on P-256
	_, _, err := ecdsaKeyAutoDetect(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for invalid point")
	}
}

// ---------------------------------------------------------------------------
//  verifyECDSA
// ---------------------------------------------------------------------------

func TestVerifyECDSA_BigEndian(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256([]byte("hello"))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	if !verifyECDSA(&key.PublicKey, hash[:], sig, false) {
		t.Fatal("valid BE signature rejected")
	}
}

func TestVerifyECDSA_LittleEndian(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256([]byte("hello"))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	rBE := make([]byte, 32)
	sBE := make([]byte, 32)
	r.FillBytes(rBE)
	s.FillBytes(sBE)
	sig := make([]byte, 64)
	copy(sig[:32], reverseBytes(rBE))
	copy(sig[32:], reverseBytes(sBE))

	if !verifyECDSA(&key.PublicKey, hash[:], sig, true) {
		t.Fatal("valid LE signature rejected")
	}
}

func TestVerifyECDSA_InvalidSig(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256([]byte("hello"))
	sig := make([]byte, 64) // all zeros = invalid
	if verifyECDSA(&key.PublicKey, hash[:], sig, false) {
		t.Fatal("invalid signature accepted")
	}
}

func TestVerifyECDSA_WrongLength(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256([]byte("hello"))
	if verifyECDSA(&key.PublicKey, hash[:], make([]byte, 32), false) {
		t.Fatal("wrong-length signature accepted")
	}
}

// ---------------------------------------------------------------------------
//  parsePEMChain
// ---------------------------------------------------------------------------

func TestParsePEMChain(t *testing.T) {
	// Generate a self-signed cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	certs, err := parsePEMChain(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "test" {
		t.Fatal("wrong CN")
	}
}

func TestParsePEMChainMultiple(t *testing.T) {
	var allPEM []byte
	for i := 0; i < 3; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "test"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		allPEM = append(allPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	certs, err := parsePEMChain(allPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(certs))
	}
}

func TestParsePEMChainEmpty(t *testing.T) {
	certs, err := parsePEMChain(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatal("expected 0 certs")
	}
}

// ---------------------------------------------------------------------------
//  ParseSGXQuote — structural tests
// ---------------------------------------------------------------------------

// buildMinimalQuote creates a minimal syntactically valid SGX DCAP Quote v3.
// The ECDSA signatures will NOT be valid, but it exercises the parser.
func buildMinimalQuote(t *testing.T) []byte {
	t.Helper()

	// Generate a real P-256 key for the attestation key (so parser doesn't reject it)
	attKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build attestation key bytes (big-endian x||y)
	attKeyBytes := make([]byte, 64)
	attKey.X.FillBytes(attKeyBytes[:32])
	attKey.Y.FillBytes(attKeyBytes[32:])

	// QE Auth Data
	qeAuthData := []byte("authdata")

	// Generate a self-signed cert for the PEM chain
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Intel SGX PCK Certificate"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	pemChain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Quote Header (48 bytes)
	header := make([]byte, 48)
	binary.LittleEndian.PutUint16(header[0:2], 3) // version
	binary.LittleEndian.PutUint16(header[2:4], 2) // att_key_type (ECDSA-256)

	// Report Body (384 bytes)
	reportBody := make([]byte, 384)
	// Put known MRENCLAVE at offset 64
	for i := 0; i < 32; i++ {
		reportBody[64+i] = byte(i + 1) // 01 02 03 ... 20
	}
	// Put known MRSIGNER at offset 128
	for i := 0; i < 32; i++ {
		reportBody[128+i] = byte(i + 0xA0) // A0 A1 ...
	}
	// ISV Prod ID at 256
	binary.LittleEndian.PutUint16(reportBody[256:258], 7)
	// ISV SVN at 258
	binary.LittleEndian.PutUint16(reportBody[258:260], 3)

	// ISV Report Signature (64 bytes, fake)
	isvSig := make([]byte, 64)

	// QE Report Body (384 bytes)
	qeReport := make([]byte, 384)
	// Set REPORTDATA[0:32] = SHA-256(AttKey || QEAuthData)
	h := sha256.New()
	h.Write(attKeyBytes)
	h.Write(qeAuthData)
	expected := h.Sum(nil)
	copy(qeReport[320:352], expected)

	// QE Report Signature (64 bytes, fake)
	qeSig := make([]byte, 64)

	// Assemble signature data
	var sigData []byte
	sigData = append(sigData, isvSig...)
	sigData = append(sigData, attKeyBytes...)
	sigData = append(sigData, qeReport...)
	sigData = append(sigData, qeSig...)

	// QE Auth Data length + data
	authLenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(authLenBytes, uint16(len(qeAuthData)))
	sigData = append(sigData, authLenBytes...)
	sigData = append(sigData, qeAuthData...)

	// Certification data type (5 = PEM chain)
	certTypeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(certTypeBytes, 5)
	sigData = append(sigData, certTypeBytes...)

	// Certification data length + data
	certLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(certLenBytes, uint32(len(pemChain)))
	sigData = append(sigData, certLenBytes...)
	sigData = append(sigData, pemChain...)

	// Assemble full quote
	var quote []byte
	quote = append(quote, header...)
	quote = append(quote, reportBody...)

	sigDataLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigDataLenBytes, uint32(len(sigData)))
	quote = append(quote, sigDataLenBytes...)
	quote = append(quote, sigData...)

	return quote
}

func TestParseSGXQuote_Valid(t *testing.T) {
	raw := buildMinimalQuote(t)
	q, err := ParseSGXQuote(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Version
	if v := binary.LittleEndian.Uint16(q.Header[:2]); v != 3 {
		t.Fatalf("version = %d, want 3", v)
	}

	// MRENCLAVE
	mre := q.MRENCLAVE()
	if mre[0] != 1 || mre[31] != 32 {
		t.Fatalf("MRENCLAVE mismatch: first=%d last=%d", mre[0], mre[31])
	}

	// MRSIGNER
	mrs := q.MRSIGNER()
	if mrs[0] != 0xA0 {
		t.Fatalf("MRSIGNER[0] = %x, want A0", mrs[0])
	}

	// ISVProdID
	if q.ISVProdID() != 7 {
		t.Fatalf("ISVProdID = %d, want 7", q.ISVProdID())
	}

	// ISVSVN
	if q.ISVSVN() != 3 {
		t.Fatalf("ISVSVN = %d, want 3", q.ISVSVN())
	}

	// QECertType
	if q.QECertType != 5 {
		t.Fatalf("QECertType = %d, want 5", q.QECertType)
	}
}

func TestParseSGXQuote_WrongVersion(t *testing.T) {
	raw := buildMinimalQuote(t)
	binary.LittleEndian.PutUint16(raw[0:2], 4) // change to v4
	_, err := ParseSGXQuote(raw)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestParseSGXQuote_TooShort(t *testing.T) {
	_, err := ParseSGXQuote(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short quote")
	}
}

func TestParseSGXQuote_SigDataOverflow(t *testing.T) {
	raw := make([]byte, 436)
	binary.LittleEndian.PutUint16(raw[0:2], 3)
	binary.LittleEndian.PutUint32(raw[432:436], 0xFFFFFFFF) // absurd sig length
	_, err := ParseSGXQuote(raw)
	if err == nil {
		t.Fatal("expected error for sig data overflow")
	}
}

// ---------------------------------------------------------------------------
//  VerifyAttKeyBinding — uses the minimal quote which has correct binding
// ---------------------------------------------------------------------------

func TestVerifyAttKeyBinding_Valid(t *testing.T) {
	raw := buildMinimalQuote(t)
	q, err := ParseSGXQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.VerifyAttKeyBinding(); err != nil {
		t.Fatalf("expected binding to pass: %v", err)
	}
}

func TestVerifyAttKeyBinding_Tampered(t *testing.T) {
	raw := buildMinimalQuote(t)
	q, err := ParseSGXQuote(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the QE Auth Data
	q.QEAuthData[0] ^= 0xFF
	if err := q.VerifyAttKeyBinding(); err == nil {
		t.Fatal("expected binding to fail after tampering")
	}
}

// ---------------------------------------------------------------------------
//  quoteType
// ---------------------------------------------------------------------------

func TestQuoteType(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{3, "sgx"},
		{4, "tdx"},
		{0, "unknown"},
		{5, "unknown"},
	}
	for _, tt := range tests {
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint16(raw[:2], tt.version)
		if got := quoteType(raw); got != tt.want {
			t.Errorf("quoteType(version=%d) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestQuoteType_TooShort(t *testing.T) {
	if got := quoteType([]byte{1, 2}); got != "unknown" {
		t.Errorf("quoteType(2 bytes) = %q, want unknown", got)
	}
}

// ---------------------------------------------------------------------------
//  ReportData accessor
// ---------------------------------------------------------------------------

func TestReportData(t *testing.T) {
	raw := buildMinimalQuote(t)
	q, _ := ParseSGXQuote(raw)
	rd := q.ReportData()
	if len(rd) != 64 {
		t.Fatalf("ReportData length = %d, want 64", len(rd))
	}
}
