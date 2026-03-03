package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
//  SGX DCAP Quote v3 — parser and verifier (pure Go)
// ---------------------------------------------------------------------------
//
// Quote layout (little-endian):
//
//   Offset   Size   Field
//   ──────   ────   ─────
//   0        48     Quote Header
//   48       384    ISV Enclave Report Body
//   432      4      Signature Data Length
//   436      64     ECDSA ISV Report Signature  (r‖s, LE)
//   500      64     ECDSA Attestation Key       (x‖y, LE)
//   564      384    QE Report Body
//   948      64     QE Report Signature          (r‖s, LE)
//   1012     2      QE Auth Data Length
//   1014     N      QE Auth Data
//   1014+N   2      QE Certification Data Type
//   1016+N   4      QE Certification Data Length
//   1020+N   M      QE Certification Data        (PEM chain when type=5)
//
// Verification steps:
//   1. Verify ECDSA(Header‖ReportBody) with Attestation Key
//   2. Verify SHA-256(AttKey‖AuthData) == QEReport.REPORTDATA[0:32]
//   3. Verify ECDSA(QEReportBody) with PCK Certificate public key
//   4. Verify PCK certificate chain

const (
	sgxHeaderSize     = 48
	sgxReportBodySize = 384
	sgxSigOff         = sgxHeaderSize + sgxReportBodySize // 432
	sgxECDSASigBytes  = 64                                // r(32) + s(32)
	sgxECDSAKeyBytes  = 64                                // x(32) + y(32)
)

// SGXQuote holds a parsed SGX DCAP Quote v3.
type SGXQuote struct {
	Raw        []byte // full raw quote bytes
	Header     []byte // [0..48)
	ReportBody []byte // [48..432)

	ISVSignature   [64]byte  // ECDSA-P256 (r‖s, little-endian)
	AttestationKey [64]byte  // raw P-256 (x‖y, little-endian)
	QEReportBody   [384]byte // QE enclave report body
	QESignature    [64]byte  // ECDSA-P256 (r‖s, little-endian)
	QEAuthData     []byte
	QECertType     uint16
	QECertData     []byte // PEM cert chain when QECertType == 5
}

// ParseSGXQuote parses a raw SGX DCAP Quote v3 byte slice.
func ParseSGXQuote(raw []byte) (*SGXQuote, error) {
	minSize := sgxSigOff + 4 // header + report body + sig data length
	if len(raw) < minSize {
		return nil, fmt.Errorf("quote too short: %d bytes (need >= %d)", len(raw), minSize)
	}

	// Validate version == 3
	ver := binary.LittleEndian.Uint16(raw[0:2])
	if ver != 3 {
		return nil, fmt.Errorf("expected quote version 3, got %d", ver)
	}

	q := &SGXQuote{
		Raw:        raw,
		Header:     raw[:sgxHeaderSize],
		ReportBody: raw[sgxHeaderSize:sgxSigOff],
	}

	sigDataLen := binary.LittleEndian.Uint32(raw[sgxSigOff : sgxSigOff+4])
	off := sgxSigOff + 4

	if uint64(off)+uint64(sigDataLen) > uint64(len(raw)) {
		return nil, fmt.Errorf("signature data overflows quote (%d + %d > %d)",
			off, sigDataLen, len(raw))
	}

	// --- Fixed-size fields ---

	// ISV Report Signature (64 B)
	if off+64 > len(raw) {
		return nil, fmt.Errorf("truncated at ISV report signature")
	}
	copy(q.ISVSignature[:], raw[off:off+64])
	off += 64

	// Attestation Key (64 B)
	if off+64 > len(raw) {
		return nil, fmt.Errorf("truncated at attestation key")
	}
	copy(q.AttestationKey[:], raw[off:off+64])
	off += 64

	// QE Report Body (384 B)
	if off+384 > len(raw) {
		return nil, fmt.Errorf("truncated at QE report body")
	}
	copy(q.QEReportBody[:], raw[off:off+384])
	off += 384

	// QE Report Signature (64 B)
	if off+64 > len(raw) {
		return nil, fmt.Errorf("truncated at QE report signature")
	}
	copy(q.QESignature[:], raw[off:off+64])
	off += 64

	// --- Variable-size fields ---

	// QE Auth Data
	if off+2 > len(raw) {
		return nil, fmt.Errorf("truncated at QE auth data length")
	}
	authLen := int(binary.LittleEndian.Uint16(raw[off : off+2]))
	off += 2
	if off+authLen > len(raw) {
		return nil, fmt.Errorf("truncated at QE auth data")
	}
	q.QEAuthData = raw[off : off+authLen]
	off += authLen

	// QE Certification Data
	if off+2 > len(raw) {
		return nil, fmt.Errorf("truncated at certification data type")
	}
	q.QECertType = binary.LittleEndian.Uint16(raw[off : off+2])
	off += 2

	if off+4 > len(raw) {
		return nil, fmt.Errorf("truncated at certification data length")
	}
	certLen := int(binary.LittleEndian.Uint32(raw[off : off+4]))
	off += 4
	if off+certLen > len(raw) {
		return nil, fmt.Errorf("truncated at certification data")
	}
	q.QECertData = raw[off : off+certLen]

	return q, nil
}

// ---------------------------------------------------------------------------
//  Verification
// ---------------------------------------------------------------------------

// VerifyAll runs the full verification pipeline and returns a combined error.
func (q *SGXQuote) VerifyAll() error {
	if err := q.VerifyISVSignature(); err != nil {
		return fmt.Errorf("step 1 (ISV report signature): %w", err)
	}
	if err := q.VerifyAttKeyBinding(); err != nil {
		return fmt.Errorf("step 2 (attestation key binding): %w", err)
	}
	if err := q.VerifyQESignature(); err != nil {
		return fmt.Errorf("step 3 (QE report signature): %w", err)
	}
	if err := q.VerifyCertChain(); err != nil {
		return fmt.Errorf("step 4 (certificate chain): %w", err)
	}
	return nil
}

// VerifyISVSignature checks ECDSA-P256(Header ‖ ReportBody) against the
// attestation key embedded in the quote.
func (q *SGXQuote) VerifyISVSignature() error {
	pubKey, err := ecdsaKeyFromLE(q.AttestationKey[:])
	if err != nil {
		return fmt.Errorf("invalid attestation key: %w", err)
	}

	msg := make([]byte, sgxHeaderSize+sgxReportBodySize)
	copy(msg[:sgxHeaderSize], q.Header)
	copy(msg[sgxHeaderSize:], q.ReportBody)
	hash := sha256.Sum256(msg)

	if !verifyECDSALE(pubKey, hash[:], q.ISVSignature[:]) {
		return fmt.Errorf("ECDSA signature does not match")
	}
	return nil
}

// VerifyAttKeyBinding checks that SHA-256(AttKey ‖ AuthData) matches the
// first 32 bytes of REPORTDATA in the QE report body.
func (q *SGXQuote) VerifyAttKeyBinding() error {
	h := sha256.New()
	h.Write(q.AttestationKey[:])
	h.Write(q.QEAuthData)
	expected := h.Sum(nil) // 32 bytes

	// REPORTDATA is at offset 320..384 in the report body
	reportData := q.QEReportBody[320:352] // first 32 bytes

	for i := 0; i < 32; i++ {
		if expected[i] != reportData[i] {
			return fmt.Errorf("hash mismatch at byte %d", i)
		}
	}
	return nil
}

// VerifyQESignature verifies the QE report body signature using the public
// key from the PCK leaf certificate in the certification data.
func (q *SGXQuote) VerifyQESignature() error {
	if q.QECertType != 5 {
		return fmt.Errorf("unsupported certification data type %d (expected 5 = PEM chain)", q.QECertType)
	}

	certs, err := parsePEMChain(q.QECertData)
	if err != nil {
		return fmt.Errorf("failed to parse PEM chain: %w", err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	pckPub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("PCK certificate does not contain an ECDSA key")
	}

	hash := sha256.Sum256(q.QEReportBody[:])

	if !verifyECDSALE(pckPub, hash[:], q.QESignature[:]) {
		return fmt.Errorf("ECDSA signature does not match")
	}
	return nil
}

// VerifyCertChain validates the PEM certificate chain (PCK → Intermediate → Root).
func (q *SGXQuote) VerifyCertChain() error {
	if q.QECertType != 5 {
		return fmt.Errorf("unsupported certification data type %d", q.QECertType)
	}

	certs, err := parsePEMChain(q.QECertData)
	if err != nil {
		return fmt.Errorf("failed to parse PEM chain: %w", err)
	}
	if len(certs) < 2 {
		return fmt.Errorf("certificate chain has %d cert(s), need >= 2", len(certs))
	}

	// Last cert = root (self-signed), middle = intermediates
	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs)-1; i++ {
		intermediates.AddCert(certs[i])
	}

	_, err = certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("x509 chain verification: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
//  Report body accessors
// ---------------------------------------------------------------------------

// MRENCLAVE returns the 32-byte measurement from the ISV enclave report body.
func (q *SGXQuote) MRENCLAVE() []byte { return q.ReportBody[64:96] }

// MRSIGNER returns the 32-byte signer measurement from the ISV enclave report body.
func (q *SGXQuote) MRSIGNER() []byte { return q.ReportBody[128:160] }

// ReportData returns the 64-byte REPORTDATA from the ISV enclave report body.
func (q *SGXQuote) ReportData() []byte { return q.ReportBody[320:384] }

// ISVProdID returns the 2-byte ISV Product ID from the ISV enclave report body.
func (q *SGXQuote) ISVProdID() uint16 {
	return binary.LittleEndian.Uint16(q.ReportBody[256:258])
}

// ISVSVN returns the 2-byte ISV Security Version Number from the ISV enclave report body.
func (q *SGXQuote) ISVSVN() uint16 {
	return binary.LittleEndian.Uint16(q.ReportBody[258:260])
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

// ecdsaKeyFromLE constructs a P-256 public key from 64 bytes (x‖y) in
// little-endian byte order (Intel format).
func ecdsaKeyFromLE(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("expected 64 bytes, got %d", len(raw))
	}
	x := new(big.Int).SetBytes(reverseBytes(raw[:32]))
	y := new(big.Int).SetBytes(reverseBytes(raw[32:64]))

	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("point not on P-256 curve")
	}
	return pub, nil
}

// verifyECDSALE verifies an ECDSA signature stored as r‖s (each 32 bytes,
// little-endian) over the given hash.
func verifyECDSALE(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(reverseBytes(sig[:32]))
	s := new(big.Int).SetBytes(reverseBytes(sig[32:64]))
	return ecdsa.Verify(pub, hash, r, s)
}

// reverseBytes returns a new slice with the bytes in reverse order.
func reverseBytes(b []byte) []byte {
	n := len(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = b[n-1-i]
	}
	return out
}

// parsePEMChain decodes a concatenated PEM blob into X.509 certificates.
func parsePEMChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
