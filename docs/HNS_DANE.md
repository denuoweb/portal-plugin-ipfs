# HNS/DANE Website Bundles

This plugin supports an initial HNS/DANE website flow. Pinner generates the records needed for a customer to delegate a Handshake name to Pinner-operated DNS, but Pinner does not take HNS wallet keys and does not publish HNS transactions.

## API

Create a bundle for an existing website:

```http
POST /api/websites/{id}/hns-domains
Content-Type: application/json

{
  "domain": "example",
  "mode": "dane"
}
```

`mode` is optional and currently defaults to `dane`. The `domain` must be a single Handshake name such as `example` or `example/`; dotted domains and paths are rejected.

List bundles for a website:

```http
GET /api/websites/{id}/hns-domains
```

## Response Semantics

The create response contains two sets of records:

- `customer_publish_from_hns_wallet`: records the customer must publish from their HNS wallet.
- `pinner_managed_records`: records Pinner has created in PowerDNS for the delegated zone.

Pinner-generated HNS domains start as `records_generated`. They are not marked verified or active by bundle generation alone. Moving a name to `waiting_for_parent_delegation` or `active` requires a future verifier or a manual administrative action that confirms the HNS parent delegation state.

## Customer Wallet Records

The wallet bundle contains:

- `NS` records for each configured Pinner nameserver.
- A `DS` record generated from the DNSSEC key material for the PowerDNS zone.

Example:

```json
{
  "records": [
    {"type": "NS", "ns": "ns1.pinner.example."},
    {"type": "NS", "ns": "ns2.pinner.example."},
    {"type": "DS", "keyTag": 12345, "algorithm": 13, "digestType": 2, "digest": "ABCD..."}
  ]
}
```

## Pinner-Managed DNS Records

For a name such as `example/`, Pinner creates a PowerDNS zone `example.` and writes:

- `_dnslink.example. TXT "dnslink=/ipfs/<cid>"` or `"dnslink=/ipns/<peer-id>"`.
- `_443._tcp.example. TLSA 3 1 1 <sha256-spki-digest>`.
- `example. ALIAS <gateway-domain>.` when `gateway_domain` is configured.

When the website target changes, the DNSLink record and gateway route metadata are refreshed for all attached HNS domains.

## TLSA Source

The TLSA value can come from configuration in this order:

1. `dane_tlsa_record`: precomputed `3 1 1 <sha256>` record.
2. `dane_certificate_pem`: certificate PEM used to compute the SPKI SHA-256 digest.
3. `dane_tlsa_endpoint` or `gateway_domain`: TLS endpoint used to fetch the served certificate and compute the digest.

For production, prefer a pinned `dane_tlsa_record` or `dane_certificate_pem` so bundle generation does not depend on live network certificate probing.

## Gateway Routing

The gateway resolves a request by host through the internal website lookup API. HNS hosts are single-label names, so `Host: example` maps to the generated HNS domain binding and rewrites to the same `/ipfs/<cid>` or `/ipns/<peer-id>` path as ICANN website domains.
