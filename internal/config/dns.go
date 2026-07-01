package config

import (
	"time"

	"go.lumeweb.com/portal/config"
)

var _ config.Defaults = (*DnsConfig)(nil)

// DnsConfig contains the configuration for the DNS hosting feature
type DnsConfig struct {
	// DNS hosting enabled/disabled
	Enabled bool `config:"enabled"`

	// PowerDNS configuration
	PowerDNSAPIURL string `config:"powerdns_api_url"`
	PowerDNSAPIKey string `config:"powerdns_api_key"`

	// Approved nameservers for validation
	Nameservers []string `config:"nameservers"`

	// Gateway domain for ALIAS records (auto-wiring)
	GatewayDomain string `config:"gateway_domain"`

	// Optional fixed TLSA record for HNS/DANE mode (for example: "3 1 1 <spki-sha256>").
	DANETLSARecord string `config:"dane_tlsa_record"`

	// Optional PEM certificate used to derive the HNS/DANE TLSA SPKI hash.
	DANECertificatePEM string `config:"dane_certificate_pem"`

	// Optional host:port used to fetch the gateway certificate for TLSA generation.
	DANETLSAEndpoint string `config:"dane_tlsa_endpoint"`

	// Verification token key used as the subdomain label for validation TXT records
	VerificationTokenKey string `config:"verification_token_key"`

	// Nameserver validation job configuration
	NameserverValidationInterval time.Duration `config:"nameserver_validation_interval"`
}

func (c DnsConfig) Defaults() map[string]any {
	return map[string]any{
		"Enabled":                      false,
		"PowerDNSAPIURL":               "",
		"PowerDNSAPIKey":               "",
		"Nameservers":                  []string{},
		"GatewayDomain":                "",
		"DANETLSARecord":               "",
		"DANECertificatePEM":           "",
		"DANETLSAEndpoint":             "",
		"VerificationTokenKey":         "lumeweb-verify",
		"NameserverValidationInterval": 5 * time.Minute,
	}
}
