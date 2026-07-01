package db

import (
	"fmt"
	"time"

	"go.lumeweb.com/portal-plugin-ipfs/internal/errors"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var _ schema.Tabler = (*HNSDomain)(nil)

type DomainType string

const (
	DomainTypeICANN DomainType = "icann"
	DomainTypeHNS   DomainType = "hns"
)

type HNSMode string

const (
	HNSModeDANE HNSMode = "dane"
)

type HNSDomainStatus string

const (
	HNSDomainStatusDraft                      HNSDomainStatus = "draft"
	HNSDomainStatusRecordsGenerated           HNSDomainStatus = "records_generated"
	HNSDomainStatusWaitingForParentDelegation HNSDomainStatus = "waiting_for_parent_delegation"
	HNSDomainStatusActive                     HNSDomainStatus = "active"
	HNSDomainStatusError                      HNSDomainStatus = "error"
)

var validHNSDomainStatuses = map[HNSDomainStatus]struct{}{
	HNSDomainStatusDraft:                      {},
	HNSDomainStatusRecordsGenerated:           {},
	HNSDomainStatusWaitingForParentDelegation: {},
	HNSDomainStatusActive:                     {},
	HNSDomainStatusError:                      {},
}

type HNSWalletBundle struct {
	Records []HNSWalletRecord `json:"records"`
}

type HNSWalletRecord struct {
	Type       string `json:"type"`
	NS         string `json:"ns,omitempty"`
	Address    string `json:"address,omitempty"`
	KeyTag     uint16 `json:"keyTag,omitempty"`
	Algorithm  uint8  `json:"algorithm,omitempty"`
	DigestType uint8  `json:"digestType,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

type HNSManagedRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type HNSGatewayRoute struct {
	Host   string `json:"host"`
	Target string `json:"target"`
}

// HNSDomain is an HNS/DANE alias binding for an existing website.
type HNSDomain struct {
	ID                   uint           `gorm:"primaryKey;autoIncrement"`
	UserID               uint           `gorm:"index:idx_ipfs_hns_domains_user_id;not null"`
	WebsiteID            uint           `gorm:"index:idx_ipfs_hns_domains_website_id;not null"`
	Website              Website        `gorm:"foreignKey:WebsiteID"`
	Domain               string         `gorm:"type:varchar(255);index:idx_ipfs_hns_domains_domain;not null"`
	DomainType           string         `gorm:"type:varchar(32);index:idx_ipfs_hns_domains_domain_type;not null;default:'hns'"`
	HNSMode              string         `gorm:"column:hns_mode;type:varchar(32);not null;default:'dane'"`
	DNSZoneName          string         `gorm:"column:dns_zone_name;type:varchar(255);not null"`
	GatewayHost          string         `gorm:"column:gateway_host;type:varchar(255);index:idx_ipfs_hns_domains_gateway_host;not null"`
	ZoneID               *uint          `gorm:"column:zone_id;index:idx_ipfs_hns_domains_zone_id"`
	CID                  string         `gorm:"column:cid;type:varchar(255);not null"`
	Status               string         `gorm:"type:varchar(64);index:idx_ipfs_hns_domains_status;not null"`
	HNSWalletBundle      datatypes.JSON `gorm:"column:hns_wallet_bundle;type:json"`
	PinnerManagedRecords datatypes.JSON `gorm:"column:pinner_managed_records;type:json"`
	DNSSECDS             string         `gorm:"column:dnssec_ds;type:text"`
	TLSARecord           string         `gorm:"column:tlsa_record;type:text"`
	GatewayRoute         datatypes.JSON `gorm:"column:gateway_route;type:json"`
	GatewayRouteStatus   string         `gorm:"column:gateway_route_status;type:varchar(64)"`
	CreatedAt            time.Time      `gorm:"autoCreateTime"`
	UpdatedAt            time.Time      `gorm:"autoUpdateTime"`
	DeletedAt            gorm.DeletedAt `gorm:"index:idx_ipfs_hns_domains_deleted_at"`
}

func (HNSDomain) TableName() string {
	return "ipfs_hns_domains"
}

func (d *HNSDomain) BeforeSave(_ *gorm.DB) error {
	if d.DomainType == "" {
		d.DomainType = string(DomainTypeHNS)
	}
	if DomainType(d.DomainType) != DomainTypeHNS {
		return fmt.Errorf("invalid domain type: %s", d.DomainType)
	}
	if d.HNSMode == "" {
		d.HNSMode = string(HNSModeDANE)
	}
	if HNSMode(d.HNSMode) != HNSModeDANE {
		return fmt.Errorf("invalid HNS mode: %s", d.HNSMode)
	}
	if d.Status == "" {
		d.Status = string(HNSDomainStatusDraft)
	}
	if _, ok := validHNSDomainStatuses[HNSDomainStatus(d.Status)]; !ok {
		return fmt.Errorf("%s: %s", errors.ErrInvalidWebsiteStatus, d.Status)
	}
	return nil
}
