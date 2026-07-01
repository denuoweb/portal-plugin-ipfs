package website

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pluginCore "go.lumeweb.com/portal-plugin-ipfs/core"
	apiDTO "go.lumeweb.com/portal-plugin-ipfs/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-ipfs/internal/db"
)

func TestNormalizeHNSDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "bare", in: "example"},
		{name: "trailing slash", in: "Example/"},
		{name: "url", in: "https://Example/"},
		{name: "trailing dot", in: "example."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHNSDomain(tt.in)
			require.NoError(t, err)
			assert.Equal(t, "example/", got.DisplayName)
			assert.Equal(t, "example.", got.ZoneName)
			assert.Equal(t, "example", got.GatewayHost)
		})
	}
}

func TestNormalizeHNSDomainRejectsUnsupportedNames(t *testing.T) {
	for _, in := range []string{"", "sub.example", "example/path", "-example", "example-", "exa_mple"} {
		t.Run(in, func(t *testing.T) {
			_, err := normalizeHNSDomain(in)
			require.Error(t, err)
		})
	}
}

func TestTLSARecordFromCertificateUsesSPKISHA256(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	certDER := srv.TLS.Certificates[0].Certificate[0]
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, "3 1 1 "+hex.EncodeToString(sum[:]), tlsaRecordFromCertificate(cert))
}

func TestNormalizeTLSARecord(t *testing.T) {
	digest := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	got, err := normalizeTLSARecord("3 1 1 " + digest)
	require.NoError(t, err)
	assert.Equal(t, "3 1 1 "+strings.ToLower(digest), got)

	_, err = normalizeTLSARecord("2 1 1 " + strings.ToLower(digest))
	require.Error(t, err)
}

func TestBuildHNSWalletBundle(t *testing.T) {
	ds := &pluginCore.DNSSECRecord{
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "abcd",
	}

	bundle := buildHNSWalletBundle([]string{"ns1.example", "ns2.example."}, ds)

	require.Len(t, bundle.Records, 3)
	assert.Equal(t, pluginDb.HNSWalletRecord{Type: "NS", NS: "ns1.example."}, bundle.Records[0])
	assert.Equal(t, pluginDb.HNSWalletRecord{Type: "NS", NS: "ns2.example."}, bundle.Records[1])
	assert.Equal(t, pluginDb.HNSWalletRecord{
		Type:       "DS",
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "ABCD",
	}, bundle.Records[2])
}

func TestManagedRecordsAndGatewayRoute(t *testing.T) {
	records := managedRecordsFromDTO([]*apiDTO.DNSRecord{
		{Name: "_dnslink.example.", Type: "TXT", Content: "dnslink=/ipfs/bafy"},
		{Name: "_443._tcp.example.", Type: "TLSA", Content: "3 1 1 abc"},
	})

	require.Len(t, records, 2)
	assert.Equal(t, pluginDb.HNSManagedRecord{Name: "_dnslink.example.", Type: "TXT", Value: "dnslink=/ipfs/bafy"}, records[0])
	assert.Equal(t, pluginDb.HNSGatewayRoute{Host: "example", Target: "ipfs://bafy"}, gatewayRoute("example", pluginDb.WebsiteTargetTypeIPFS, "bafy"))
}

func TestHNSDomainStatusDoesNotSupportImplicitVerified(t *testing.T) {
	domain := &pluginDb.HNSDomain{
		Domain:      "example/",
		DNSZoneName: "example.",
		GatewayHost: "example",
		CID:         "bafy",
		Status:      string(pluginDb.HNSDomainStatusWaitingForParentDelegation),
	}
	require.NoError(t, domain.BeforeSave(nil))
	assert.Equal(t, string(pluginDb.DomainTypeHNS), domain.DomainType)
	assert.Equal(t, string(pluginDb.HNSModeDANE), domain.HNSMode)

	domain.Status = "verified"
	require.Error(t, domain.BeforeSave(nil))
}

func TestTLSARecordFromPEMRejectsInvalidPEM(t *testing.T) {
	_, err := tlsaRecordFromPEM("not a certificate")
	require.Error(t, err)
}
