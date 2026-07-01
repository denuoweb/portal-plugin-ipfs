-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ipfs_hns_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    website_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    domain_type TEXT NOT NULL DEFAULT 'hns',
    hns_mode TEXT NOT NULL DEFAULT 'dane',
    dns_zone_name TEXT NOT NULL,
    gateway_host TEXT NOT NULL,
    zone_id INTEGER NULL,
    cid TEXT NOT NULL,
    status TEXT NOT NULL,
    hns_wallet_bundle JSON NULL,
    pinner_managed_records JSON NULL,
    dnssec_ds TEXT,
    tlsa_record TEXT,
    gateway_route JSON NULL,
    gateway_route_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL DEFAULT NULL,
    FOREIGN KEY (website_id) REFERENCES ipfs_websites(id),
    FOREIGN KEY (zone_id) REFERENCES ipfs_dns_zones(id)
);

CREATE UNIQUE INDEX idx_ipfs_hns_domains_domain ON ipfs_hns_domains(domain COLLATE NOCASE) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_ipfs_hns_domains_gateway_host ON ipfs_hns_domains(gateway_host COLLATE NOCASE) WHERE deleted_at IS NULL;
CREATE INDEX idx_ipfs_hns_domains_user_id ON ipfs_hns_domains(user_id);
CREATE INDEX idx_ipfs_hns_domains_website_id ON ipfs_hns_domains(website_id);
CREATE INDEX idx_ipfs_hns_domains_zone_id ON ipfs_hns_domains(zone_id);
CREATE INDEX idx_ipfs_hns_domains_status ON ipfs_hns_domains(status);
CREATE INDEX idx_ipfs_hns_domains_deleted_at ON ipfs_hns_domains(deleted_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ipfs_hns_domains_deleted_at;
DROP INDEX IF EXISTS idx_ipfs_hns_domains_status;
DROP INDEX IF EXISTS idx_ipfs_hns_domains_zone_id;
DROP INDEX IF EXISTS idx_ipfs_hns_domains_website_id;
DROP INDEX IF EXISTS idx_ipfs_hns_domains_user_id;
DROP INDEX IF EXISTS idx_ipfs_hns_domains_gateway_host;
DROP INDEX IF EXISTS idx_ipfs_hns_domains_domain;
DROP TABLE IF EXISTS ipfs_hns_domains;
-- +goose StatementEnd
