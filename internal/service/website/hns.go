package website

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	pluginCore "go.lumeweb.com/portal-plugin-ipfs/core"
	apiDTO "go.lumeweb.com/portal-plugin-ipfs/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-ipfs/internal/db"
	"go.lumeweb.com/portal/core"
	portalDb "go.lumeweb.com/portal/db"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type normalizedHNSDomain struct {
	DisplayName string
	ZoneName    string
	GatewayHost string
}

func normalizeHNSDomain(input string) (normalizedHNSDomain, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return normalizedHNSDomain{}, fmt.Errorf("HNS domain cannot be empty")
	}

	var name string
	if strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return normalizedHNSDomain{}, fmt.Errorf("invalid HNS URL: %w", err)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return normalizedHNSDomain{}, fmt.Errorf("HNS URL path is not supported")
		}
		name = parsed.Hostname()
	} else {
		name = strings.TrimSuffix(raw, "/")
		name = strings.TrimSuffix(name, ".")
	}

	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return normalizedHNSDomain{}, fmt.Errorf("HNS domain cannot be empty")
	}
	if strings.ContainsAny(name, "/:") || strings.Contains(name, ".") {
		return normalizedHNSDomain{}, fmt.Errorf("HNS domain must be a single Handshake name")
	}
	if len(name) > 63 {
		return normalizedHNSDomain{}, fmt.Errorf("HNS name too long")
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return normalizedHNSDomain{}, fmt.Errorf("HNS name cannot start or end with hyphen")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return normalizedHNSDomain{}, fmt.Errorf("HNS name contains invalid character: %c", r)
		}
	}

	return normalizedHNSDomain{
		DisplayName: name + "/",
		ZoneName:    name + ".",
		GatewayHost: name,
	}, nil
}

func tlsaRecordFromCertificate(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "3 1 1 " + hex.EncodeToString(sum[:])
}

func tlsaRecordFromPEM(pemData string) (string, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return tlsaRecordFromCertificate(cert), nil
}

func normalizeTLSARecord(record string) (string, error) {
	fields := strings.Fields(record)
	if len(fields) != 4 {
		return "", fmt.Errorf("TLSA record must have four fields")
	}
	if fields[0] != "3" || fields[1] != "1" || fields[2] != "1" {
		return "", fmt.Errorf("only TLSA 3 1 1 records are supported")
	}
	digest := strings.ToLower(fields[3])
	if len(digest) != sha256.Size*2 {
		return "", fmt.Errorf("TLSA digest must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("invalid TLSA digest: %w", err)
	}
	return strings.Join([]string{"3", "1", "1", digest}, " "), nil
}

func fetchTLSARecordFromGateway(ctx context.Context, endpoint string, sni string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("gateway TLS endpoint is required")
	}
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		endpoint = net.JoinHostPort(endpoint, "443")
	}

	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("gateway connection did not use TLS")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("gateway presented no certificates")
	}
	return tlsaRecordFromCertificate(state.PeerCertificates[0]), nil
}

func (s *WebsiteServiceDefault) hnsTLSARecord(ctx context.Context, gatewayHost string) (string, error) {
	if s.dnsConfig == nil {
		return "", fmt.Errorf("DNS service config not loaded")
	}
	if s.dnsConfig.DANETLSARecord != "" {
		return normalizeTLSARecord(s.dnsConfig.DANETLSARecord)
	}
	if s.dnsConfig.DANECertificatePEM != "" {
		return tlsaRecordFromPEM(s.dnsConfig.DANECertificatePEM)
	}

	endpoint := s.dnsConfig.DANETLSAEndpoint
	if endpoint == "" && s.dnsConfig.GatewayDomain != "" {
		endpoint = s.dnsConfig.GatewayDomain
	}
	if endpoint == "" {
		return "", fmt.Errorf("dane_tlsa_record, dane_certificate_pem, or gateway_domain must be configured")
	}
	return fetchTLSARecordFromGateway(ctx, endpoint, gatewayHost)
}

func formatDSRecord(ds *pluginCore.DNSSECRecord) string {
	if ds == nil {
		return ""
	}
	return strings.Join([]string{
		strconv.FormatUint(uint64(ds.KeyTag), 10),
		strconv.FormatUint(uint64(ds.Algorithm), 10),
		strconv.FormatUint(uint64(ds.DigestType), 10),
		strings.ToUpper(ds.Digest),
	}, " ")
}

func buildHNSWalletBundle(nameservers []string, ds *pluginCore.DNSSECRecord) pluginDb.HNSWalletBundle {
	records := make([]pluginDb.HNSWalletRecord, 0, len(nameservers)+1)
	for _, ns := range nameservers {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		records = append(records, pluginDb.HNSWalletRecord{
			Type: "NS",
			NS:   strings.TrimSuffix(ns, ".") + ".",
		})
	}
	if ds != nil {
		records = append(records, pluginDb.HNSWalletRecord{
			Type:       "DS",
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
			Digest:     strings.ToUpper(ds.Digest),
		})
	}
	return pluginDb.HNSWalletBundle{Records: records}
}

func marshalJSON(v any) (datatypes.JSON, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return datatypes.JSON(data), nil
}

func managedRecordsFromDTO(records []*apiDTO.DNSRecord) []pluginDb.HNSManagedRecord {
	managed := make([]pluginDb.HNSManagedRecord, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		managed = append(managed, pluginDb.HNSManagedRecord{
			Name:  record.Name,
			Type:  record.Type,
			Value: record.Content,
		})
	}
	return managed
}

func gatewayRoute(host string, targetType pluginDb.WebsiteTargetType, targetHash string) pluginDb.HNSGatewayRoute {
	return pluginDb.HNSGatewayRoute{
		Host:   host,
		Target: fmt.Sprintf("%s://%s", targetType, targetHash),
	}
}

func (s *WebsiteServiceDefault) CreateHNSDomain(ctx context.Context, userID uint, websiteID uint, domain string, mode string) (*pluginDb.HNSDomain, error) {
	ctx, span := core.TraceMethod(ctx, "WebsiteServiceDefault.CreateHNSDomain")
	defer span.End()

	if mode == "" {
		mode = string(pluginDb.HNSModeDANE)
	}
	if mode != string(pluginDb.HNSModeDANE) {
		return nil, fmt.Errorf("unsupported HNS mode: %s", mode)
	}
	if s.dnsSvc == nil {
		return nil, fmt.Errorf("DNS service is required for HNS/DANE domains")
	}
	if s.dnsConfig == nil || len(s.dnsConfig.Nameservers) == 0 {
		return nil, fmt.Errorf("DNS nameservers must be configured for HNS/DANE domains")
	}

	normalized, err := normalizeHNSDomain(domain)
	if err != nil {
		return nil, err
	}

	website, err := s.GetWebsite(ctx, userID, websiteID)
	if err != nil {
		return nil, err
	}
	if website == nil {
		return nil, fmt.Errorf("website not found")
	}

	existing, err := s.GetHNSDomainByDomain(ctx, normalized.GatewayHost)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("HNS domain already exists: %s", normalized.DisplayName)
	}

	zone, err := s.dnsSvc.CreateZone(ctx, normalized.ZoneName, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to create HNS DNS zone: %w", err)
	}

	ds, err := s.dnsSvc.EnsureZoneDNSSEC(ctx, zone.ID)
	if err != nil {
		return nil, err
	}

	tlsaRecord, err := s.hnsTLSARecord(ctx, normalized.GatewayHost)
	if err != nil {
		return nil, err
	}

	targetType := pluginDb.WebsiteTargetType(website.TargetType)
	managedRecords, err := s.dnsSvc.CreateHNSDNSRecords(ctx, zone.ID, normalized.ZoneName, website.TargetHash(), targetType, tlsaRecord)
	if err != nil {
		return nil, err
	}

	walletBundle := buildHNSWalletBundle(s.dnsConfig.Nameservers, ds)
	walletJSON, err := marshalJSON(walletBundle)
	if err != nil {
		return nil, err
	}
	managedJSON, err := marshalJSON(managedRecordsFromDTO(managedRecords))
	if err != nil {
		return nil, err
	}
	routeJSON, err := marshalJSON(gatewayRoute(normalized.GatewayHost, targetType, website.TargetHash()))
	if err != nil {
		return nil, err
	}

	hnsDomain := &pluginDb.HNSDomain{
		UserID:               userID,
		WebsiteID:            website.ID,
		Domain:               normalized.DisplayName,
		DomainType:           string(pluginDb.DomainTypeHNS),
		HNSMode:              mode,
		DNSZoneName:          normalized.ZoneName,
		GatewayHost:          normalized.GatewayHost,
		ZoneID:               &zone.ID,
		CID:                  website.TargetHash(),
		Status:               string(pluginDb.HNSDomainStatusRecordsGenerated),
		HNSWalletBundle:      walletJSON,
		PinnerManagedRecords: managedJSON,
		DNSSECDS:             formatDSRecord(ds),
		TLSARecord:           tlsaRecord,
		GatewayRoute:         routeJSON,
		GatewayRouteStatus:   "ready",
	}

	err = portalDb.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Create(hnsDomain)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create HNS domain: %w", err)
	}

	return hnsDomain, nil
}

func (s *WebsiteServiceDefault) ListHNSDomains(ctx context.Context, userID uint, websiteID uint) ([]*pluginDb.HNSDomain, error) {
	ctx, span := core.TraceMethod(ctx, "WebsiteServiceDefault.ListHNSDomains")
	defer span.End()

	var domains []*pluginDb.HNSDomain
	err := portalDb.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Where("user_id = ? AND website_id = ?", userID, websiteID).
			Order("created_at ASC").
			Find(&domains)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list HNS domains: %w", err)
	}
	return domains, nil
}

func (s *WebsiteServiceDefault) GetHNSDomainByDomain(ctx context.Context, domain string) (*pluginDb.HNSDomain, error) {
	normalized, err := normalizeHNSDomain(domain)
	if err != nil {
		return nil, nil
	}

	var hnsDomain pluginDb.HNSDomain
	err = portalDb.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Where("gateway_host = ? OR domain = ? OR dns_zone_name = ?", normalized.GatewayHost, normalized.DisplayName, normalized.ZoneName).
			First(&hnsDomain)
	})
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get HNS domain: %w", err)
	}
	return &hnsDomain, nil
}

func (s *WebsiteServiceDefault) getWebsiteByHNSDomain(ctx context.Context, domain string) (*pluginDb.Website, error) {
	hnsDomain, err := s.GetHNSDomainByDomain(ctx, domain)
	if err != nil || hnsDomain == nil {
		return nil, err
	}
	switch pluginDb.HNSDomainStatus(hnsDomain.Status) {
	case pluginDb.HNSDomainStatusRecordsGenerated, pluginDb.HNSDomainStatusWaitingForParentDelegation, pluginDb.HNSDomainStatusActive:
	default:
		return nil, nil
	}

	var website pluginDb.Website
	err = portalDb.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
		return tx.Where("id = ?", hnsDomain.WebsiteID).First(&website)
	})
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get HNS website: %w", err)
	}
	return &website, nil
}

func (s *WebsiteServiceDefault) refreshHNSDomains(ctx context.Context, website *pluginDb.Website) {
	if s.dnsSvc == nil || website == nil {
		return
	}
	domains, err := s.ListHNSDomains(ctx, website.UserID, website.ID)
	if err != nil {
		s.Logger().Warn("Failed to list HNS domains for DNS refresh", zap.Error(err), zap.Uint("website_id", website.ID))
		return
	}
	for _, hnsDomain := range domains {
		if hnsDomain.ZoneID == nil {
			continue
		}
		managedRecords, err := s.dnsSvc.CreateHNSDNSRecords(ctx, *hnsDomain.ZoneID, hnsDomain.DNSZoneName, website.TargetHash(), pluginDb.WebsiteTargetType(website.TargetType), hnsDomain.TLSARecord)
		if err != nil {
			s.Logger().Warn("Failed to refresh HNS DNS records", zap.Error(err), zap.Uint("hns_domain_id", hnsDomain.ID))
			continue
		}
		managedJSON, err := marshalJSON(managedRecordsFromDTO(managedRecords))
		if err != nil {
			s.Logger().Warn("Failed to marshal refreshed HNS records", zap.Error(err), zap.Uint("hns_domain_id", hnsDomain.ID))
			continue
		}
		route := gatewayRoute(hnsDomain.GatewayHost, pluginDb.WebsiteTargetType(website.TargetType), website.TargetHash())
		routeJSON, err := marshalJSON(route)
		if err != nil {
			s.Logger().Warn("Failed to marshal refreshed HNS route", zap.Error(err), zap.Uint("hns_domain_id", hnsDomain.ID))
			continue
		}
		_ = portalDb.RetryableComponentTransaction(s, ctx, func(tx *gorm.DB) *gorm.DB {
			return tx.Model(hnsDomain).Updates(map[string]interface{}{
				"cid":                    website.TargetHash(),
				"pinner_managed_records": managedJSON,
				"gateway_route":          routeJSON,
			})
		})
	}
}
