package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	pluginCore "go.lumeweb.com/portal-plugin-ipfs/core"
	"go.lumeweb.com/portal-plugin-ipfs/internal/dns/powerdns"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

// Default PowerDNS server ID for single-server deployments
const defaultServerID = "localhost"

// PowerDNSClient wraps the generated PowerDNS client
type PowerDNSClient struct {
	client     *powerdns.Client
	httpClient *http.Client
	baseURL    string
	apiKey     string
	logger     *core.Logger
}

type cryptokey struct {
	ID        int      `json:"id,omitempty"`
	KeyType   string   `json:"keytype,omitempty"`
	Active    bool     `json:"active,omitempty"`
	Published bool     `json:"published,omitempty"`
	DS        []string `json:"ds,omitempty"`
}

// NewPowerDNSClient creates a new PowerDNS client wrapper
func NewPowerDNSClient(baseURL, apiKey string, logger *core.Logger) (*PowerDNSClient, error) {
	pdnsClient, err := powerdns.NewClient(baseURL, powerdns.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("X-API-Key", apiKey)
		return nil
	}))
	if err != nil {
		return nil, err
	}

	return &PowerDNSClient{
		client:     pdnsClient,
		httpClient: http.DefaultClient,
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		logger:     logger,
	}, nil
}

// handleResponse processes HTTP response, checking status code and decoding JSON
// It safely closes the response body and returns an error if the status code is not 2xx
func handleResponse[T any](resp *http.Response) (*T, error) {
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var zero T
		return &zero, fmt.Errorf("PowerDNS API returned status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		var zero T
		return &zero, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// CreateZone creates a new zone in PowerDNS, or returns the existing zone if it already exists (409)
func (c *PowerDNSClient) CreateZone(ctx context.Context, domain string, nameservers []string) (*powerdns.Zone, error) {
	canonicalDomain := strings.TrimSuffix(domain, ".") + "."

	canonicalNameservers := make([]string, len(nameservers))
	for i, ns := range nameservers {
		canonicalNameservers[i] = strings.TrimSuffix(ns, ".") + "."
	}

	c.logger.Debug("Creating zone in PowerDNS",
		zap.String("domain", domain),
		zap.String("canonical_domain", canonicalDomain),
		zap.Strings("nameservers", nameservers),
		zap.Strings("canonical_nameservers", canonicalNameservers))

	zoneCreate := powerdns.ZoneCreate{
		Name:        canonicalDomain,
		Nameservers: &canonicalNameservers,
	}

	kind := powerdns.ZoneCreateKindNative
	zoneCreate.Kind = &kind

	resp, err := c.client.CreateZone(ctx, defaultServerID, zoneCreate)
	if err != nil {
		return nil, fmt.Errorf("failed to create zone: %w", err)
	}

	zone, err := handleResponse[powerdns.Zone](resp)
	if err != nil {
		if strings.Contains(err.Error(), "status 409") {
			c.logger.Info("Zone already exists in PowerDNS, fetching existing zone",
				zap.String("domain", domain))

			existingZone, getErr := c.GetZone(ctx, canonicalDomain)
			if getErr != nil {
				return nil, fmt.Errorf("zone already exists but failed to fetch it: %w", getErr)
			}
			if existingZone.Id == nil {
				return nil, fmt.Errorf("existing zone has no ID for domain %q", domain)
			}

			return existingZone, nil
		}
		return nil, err
	}

	if zone.Id == nil {
		return nil, fmt.Errorf("powerdns API returned zone with no ID for domain %q", domain)
	}

	c.logger.Info("Zone created in PowerDNS",
		zap.String("domain", domain),
		zap.String("zone_id", *zone.Id))

	return zone, nil
}

// GetZone retrieves a zone from PowerDNS
func (c *PowerDNSClient) GetZone(ctx context.Context, zoneID string) (*powerdns.Zone, error) {
	resp, err := c.client.GetZone(ctx, defaultServerID, zoneID)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone: %w", err)
	}

	return handleResponse[powerdns.Zone](resp)
}

// UpdateZoneRRSets updates RRsets in a zone
func (c *PowerDNSClient) UpdateZoneRRSets(ctx context.Context, zoneID string, rrsets []powerdns.RRSet) error {
	zonePatch := powerdns.ZonePatch{
		Rrsets: &rrsets,
	}

	resp, err := c.client.UpdateZoneRRSets(ctx, defaultServerID, zoneID, zonePatch)
	if err != nil {
		return fmt.Errorf("failed to update zone: %w", err)
	}
	if resp != nil {
		defer resp.Body.Close()
	}

	c.logger.Info("Zone RRsets updated in PowerDNS",
		zap.String("zone_id", zoneID),
		zap.Int("rrsets_count", len(rrsets)))

	return nil
}

// DeleteZone deletes a zone from PowerDNS
func (c *PowerDNSClient) DeleteZone(ctx context.Context, zoneID string) error {
	resp, err := c.client.DeleteZone(ctx, defaultServerID, zoneID)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}
	if resp != nil {
		defer resp.Body.Close()
	}

	c.logger.Info("Zone deleted from PowerDNS",
		zap.String("zone_id", zoneID))

	return nil
}

func (c *PowerDNSClient) EnsureDNSSECAndGetDS(ctx context.Context, zoneID string) (*pluginCore.DNSSECRecord, error) {
	if err := c.EnableDNSSEC(ctx, zoneID); err != nil {
		return nil, err
	}

	keys, err := c.GetCryptokeys(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	if ds := firstDSRecord(keys); ds != "" {
		return parseDSRecord(ds)
	}

	key, err := c.CreateCryptokey(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	if ds := firstDSRecord([]cryptokey{*key}); ds != "" {
		return parseDSRecord(ds)
	}

	keys, err = c.GetCryptokeys(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	if ds := firstDSRecord(keys); ds != "" {
		return parseDSRecord(ds)
	}

	return nil, fmt.Errorf("PowerDNS returned no DS records for zone %q", zoneID)
}

func (c *PowerDNSClient) EnableDNSSEC(ctx context.Context, zoneID string) error {
	resp, err := c.doJSON(ctx, http.MethodPut, fmt.Sprintf("/servers/%s/zones/%s", defaultServerID, url.PathEscape(zoneID)), map[string]any{
		"dnssec":      true,
		"api_rectify": true,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PowerDNS DNSSEC enable returned status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func (c *PowerDNSClient) GetCryptokeys(ctx context.Context, zoneID string) ([]cryptokey, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/servers/%s/zones/%s/cryptokeys", defaultServerID, url.PathEscape(zoneID)), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("PowerDNS cryptokeys returned status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	var keys []cryptokey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode PowerDNS cryptokeys: %w", err)
	}
	return keys, nil
}

func (c *PowerDNSClient) CreateCryptokey(ctx context.Context, zoneID string) (*cryptokey, error) {
	resp, err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/servers/%s/zones/%s/cryptokeys", defaultServerID, url.PathEscape(zoneID)), map[string]any{
		"keytype":   "ksk",
		"active":    true,
		"published": true,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("PowerDNS cryptokey create returned status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	var key cryptokey
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return nil, fmt.Errorf("failed to decode PowerDNS cryptokey: %w", err)
	}
	return &key, nil
}

func (c *PowerDNSClient) doJSON(ctx context.Context, method string, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

func firstDSRecord(keys []cryptokey) string {
	for _, key := range keys {
		if !key.Active || !key.Published {
			continue
		}
		if len(key.DS) > 0 {
			return key.DS[0]
		}
	}
	for _, key := range keys {
		if len(key.DS) > 0 {
			return key.DS[0]
		}
	}
	return ""
}

func parseDSRecord(record string) (*pluginCore.DNSSECRecord, error) {
	fields := strings.Fields(record)
	dsIndex := -1
	for i, field := range fields {
		if strings.EqualFold(field, "DS") {
			dsIndex = i
			break
		}
	}
	if dsIndex >= 0 {
		fields = fields[dsIndex+1:]
	}
	if len(fields) < 4 {
		return nil, fmt.Errorf("invalid DS record %q", record)
	}
	fields = fields[len(fields)-4:]

	keyTag, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid DS key tag %q: %w", fields[0], err)
	}
	algorithm, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DS algorithm %q: %w", fields[1], err)
	}
	digestType, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DS digest type %q: %w", fields[2], err)
	}

	return &pluginCore.DNSSECRecord{
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     strings.ToUpper(fields[3]),
	}, nil
}
