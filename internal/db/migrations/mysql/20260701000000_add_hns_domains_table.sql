-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ipfs_hns_domains (
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    website_id BIGINT UNSIGNED NOT NULL,
    domain VARCHAR(255) NOT NULL,
    domain_type VARCHAR(32) NOT NULL DEFAULT 'hns',
    hns_mode VARCHAR(32) NOT NULL DEFAULT 'dane',
    dns_zone_name VARCHAR(255) NOT NULL,
    gateway_host VARCHAR(255) NOT NULL,
    zone_id BIGINT UNSIGNED NULL,
    cid VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL,
    hns_wallet_bundle JSON NULL,
    pinner_managed_records JSON NULL,
    dnssec_ds TEXT,
    tlsa_record TEXT,
    gateway_route JSON NULL,
    gateway_route_status VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL DEFAULT NULL,
    active_domain VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN domain ELSE NULL END) STORED,
    active_gateway_host VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN gateway_host ELSE NULL END) STORED,

    UNIQUE KEY idx_ipfs_hns_domains_domain (active_domain),
    UNIQUE KEY idx_ipfs_hns_domains_gateway_host (active_gateway_host),
    KEY idx_ipfs_hns_domains_user_id (user_id),
    KEY idx_ipfs_hns_domains_website_id (website_id),
    KEY idx_ipfs_hns_domains_zone_id (zone_id),
    KEY idx_ipfs_hns_domains_status (status),
    KEY idx_ipfs_hns_domains_deleted_at (deleted_at),

    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (website_id) REFERENCES ipfs_websites(id),
    FOREIGN KEY (zone_id) REFERENCES ipfs_dns_zones(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ipfs_hns_domains;
-- +goose StatementEnd
