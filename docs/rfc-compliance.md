# RFC Compliance Matrix

This document maps the stirshaken-ruby gem's implementation against the relevant STIR/SHAKEN RFCs. Each row indicates whether a specific requirement is implemented, partially implemented, or not applicable.

**Status key:**
- **Implemented** -- The feature is fully implemented.
- **Partial** -- The feature is implemented with limitations noted.
- **N/A** -- The requirement is out of scope for this library (e.g., SIP stack integration, network-level concerns).

---

## RFC 8224 -- Authenticated Identity Management in SIP

RFC 8224 defines how to carry authenticated identity information in SIP messages using the Identity header.

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| 4.1 | SIP Identity header creation with token, info, alg, ppt parameters | Implemented | `SipIdentity.create` produces the full header format: `<token>;info=<url>;alg=ES256;ppt=shaken` |
| 4.1 | SIP Identity header parsing | Implemented | `SipIdentity.parse` splits token from parameters and validates required fields |
| 4.1 | Multiple Identity headers | Implemented | `SipIdentity.parse_multiple` and `VerificationService#verify_multiple` handle arrays of headers |
| 4.1 | `info` parameter as URI in angle brackets | Implemented | `SipIdentity.create` wraps URL in `<>` and `parse` strips them |
| 4.1 | `alg` parameter | Implemented | Validated as `ES256` in `SipIdentity#validate!` |
| 4.1 | `ppt` parameter | Implemented | Validated as `shaken` or `div` in `SipIdentity#validate!` |
| 4.1 | `canon` parameter | Implemented | Optional parameter supported in `SipIdentity.create` and `parse` |
| 4.3 | Verification of Identity header | Implemented | `VerificationService#verify_call` performs full verification: parse header, fetch cert, verify signature, check expiry, validate numbers |
| 4.3 | Certificate fetch via `info` URL | Implemented | `CertificateManager.fetch_certificate` fetches from the `info_url` |
| 4.3 | Signature verification | Implemented | JWT ES256 signature verification via the `jwt` gem |
| 4.4 | Freshness check (token age) | Implemented | `Passport#expired?` checks `iat` against configurable `max_age` (default 60s) with 60s clock skew allowance |
| 5 | SIP request handling (INVITE, etc.) | N/A | SIP message framing is outside this library's scope; it produces and consumes Identity header values only |
| 5.2 | Authentication service behavior (signing outbound calls) | Implemented | `AuthenticationService#sign_call` creates a PASSporT and wraps it in an Identity header |
| 5.3 | Verification service behavior | Implemented | `VerificationService#verify_call` implements the verification flow |
| 6 | Header injection protection | Implemented | `SipIdentity.sanitize_header_param!` rejects `;`, `\r`, `\n`, `\0` in additional parameters |

---

## RFC 8225 -- PASSporT: Personal Assertion Token

RFC 8225 defines the PASSporT token format as a JWT profile.

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| 3 | JWT header with `typ: "passport"` | Implemented | `Passport::TOKEN_TYPE = 'passport'`; validated in `Passport#validate_header!` |
| 3 | JWT header `alg` claim | Implemented | Fixed to `ES256`; validated in `Passport#validate_header!` |
| 3 | JWT header `x5u` claim for certificate URL | Implemented | Set during creation, validated as present during parsing |
| 4.1 | `orig` claim with `tn` (originating number) | Implemented | `Passport#originating_number` reads `orig.tn` |
| 4.1 | `dest` claim with `tn` array | Implemented | `Passport#destination_numbers` reads `dest.tn` |
| 4.1 | `dest` claim with `uri` array | Implemented | `Passport.create` accepts `destination_uris:` parameter; `Passport#destination_uris` reads `dest.uri` |
| 4.2 | `iat` (issued-at) claim | Implemented | Set to `Time.now.to_i` during creation; validated as present during parsing |
| 5 | ES256 signing algorithm | Implemented | Uses the `jwt` gem with `ES256` for JWT encode/decode |
| 5 | Phone number in E.164 format | Implemented | `Passport.validate_phone_number!` enforces `/^\+[1-9]\d{1,14}$/` |
| 6 | Extension mechanism via `ppt` header | Implemented | Base Passport uses `ppt: "shaken"`, DivPassport uses `ppt: "div"` |
| 7 | Token creation (signing) | Implemented | `Passport.create` builds header/payload and signs with `JWT.encode` |
| 7 | Token verification (parsing) | Implemented | `Passport.parse` decodes with optional signature verification |
| 7 | Payload claim validation | Implemented | `Passport#validate!` checks for `attest`, `dest`, `iat`, `orig`, `origid` |

---

## RFC 8226 -- Secure Telephone Identity Credentials

RFC 8226 defines the certificate requirements for STIR/SHAKEN.

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| 4 | X.509 certificate with EC public key | Implemented | `CertificateManager.extract_public_key` validates the key is EC |
| 4 | P-256 curve for ES256 | Implemented | Enforced in `extract_public_key` (checks `prime256v1`) and `AuthenticationService#validate_private_key!` |
| 5 | TNAuthList certificate extension (OID 1.3.6.1.5.5.7.1.26) | Implemented | `CertificateManager.check_tn_auth_list` parses ASN.1 TNAuthorizationList entries (SPC, range, single number) |
| 5 | Subject Alternative Name with `tel:` URIs | Implemented | `CertificateManager.telephone_number_authorized?` falls back to SAN `URI:tel:` check if TNAuthList is absent |
| 6 | Certificate chain validation | Partial | Self-signed certificate verification is the default. Full chain validation supported when `trust_store_path` or `trust_store_certificates` are configured. |
| 6 | Trust store configuration | Implemented | `Configuration` supports `trust_store_path` (directory of CA certs) and `trust_store_certificates` (array of PEM strings) |
| 9 | HTTPS-only certificate URLs | Implemented | `CertificateManager.download_certificate` and `fetch_certificate_chain` enforce `URI::HTTPS`. `SipIdentity#validate!` also validates HTTPS. |
| 9 | Certificate fetching | Implemented | `CertificateManager.fetch_certificate` with caching, rate limiting, and SSRF protection |
| 9 | Certificate caching | Implemented | Thread-safe cache with configurable TTL (`certificate_cache_ttl`), force refresh support, and cache statistics |
| 9 | Key usage validation (`digitalSignature`) | Implemented | `CertificateManager.valid_key_usage?` checks for `digitalSignature` in keyUsage extension |
| 9 | Extended Key Usage (id-kp-jwt-stir-shaken, OID 1.3.6.1.5.5.7.3.20) | Partial | `valid_key_usage?` checks for the STIR/SHAKEN EKU OID when the EKU extension is present, but also accepts `TLS Web Server Authentication` as a fallback |
| 9 | CRL distribution point support | Implemented | `CertificateManager.extract_crl_distribution_points` parses CDP URIs; CRL fetching and caching supported when `check_revocation` is enabled |
| 9 | Certificate revocation checking | Partial | CRL-based revocation checking is implemented. OCSP is not implemented. Revocation checking is disabled by default (`check_revocation: false`). |

---

## RFC 8588 -- Personal Assertion Token (PASSporT) Extension for SHAKEN

RFC 8588 defines the SHAKEN-specific extension to PASSporT.

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| 3 | `ppt` header value `"shaken"` | Implemented | `Passport::EXTENSION = 'shaken'`; enforced in `validate_header!` |
| 4 | `attest` claim (A, B, C) | Implemented | `Attestation` module defines `FULL='A'`, `PARTIAL='B'`, `GATEWAY='C'` with validation |
| 4 | `origid` claim (origination identifier) | Implemented | Auto-generated via `SecureRandom.uuid` if not provided |
| 4 | Lexicographic ordering of payload keys | Implemented | `Passport.create` sorts payload keys with `.sort.to_h` |
| 5 | Full Attestation (A) semantics | Implemented | `Attestation.description('A')` and `confidence_level('A')` return 100 |
| 5 | Partial Attestation (B) semantics | Implemented | `Attestation.description('B')` and `confidence_level('B')` return 75 |
| 5 | Gateway Attestation (C) semantics | Implemented | `Attestation.description('C')` and `confidence_level('C')` return 50 |
| 6 | Verification of SHAKEN PASSporT | Implemented | `VerificationService#verify_call` and `#verify_passport` perform full SHAKEN verification |

---

## RFC 8946 -- Personal Assertion Token (PASSporT) Extension for Diverted Calls

RFC 8946 defines the DIV extension to PASSporT for call diversion scenarios.

| Section | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| 3 | `ppt` header value `"div"` | Implemented | `DivPassport::EXTENSION = 'div'`; enforced in `DivPassport#validate_header!` |
| 3 | `div` claim with `tn` (original destination) | Implemented | `DivPassport#original_destination` reads `div.tn` |
| 3 | `div` claim with `reason` | Implemented | `DivPassport#diversion_reason` reads `div.reason` |
| 3 | Valid diversion reason values | Implemented | All 10 reasons defined: `forwarding`, `deflection`, `follow-me`, `time-of-day`, `user-busy`, `no-answer`, `unavailable`, `unconditional`, `away`, `unknown` |
| 3 | Preservation of `orig.tn` from original PASSporT | Implemented | `DivPassport.create_div` copies `originating_number` from the original passport |
| 3 | Preservation of `origid` from original PASSporT | Implemented | `DivPassport.create_div` defaults `origination_id` to the original passport's `origination_id` |
| 3 | `dest` contains new (diverted-to) destinations | Implemented | `DivPassport.create_div` sets `dest.tn` to the new destination(s) |
| 4 | DIV PASSporT creation | Implemented | `DivPassport.create_div` and `DivPassport.create_from_identity_header` |
| 4 | DIV PASSporT from existing Identity header | Implemented | `DivPassport.create_from_identity_header` parses the SHAKEN header and creates the DIV token |
| 5 | Chain verification (originating number match) | Implemented | `DivPassport.verify_chain` checks `orig.tn` match |
| 5 | Chain verification (origination ID match) | Implemented | `DivPassport.verify_chain` checks `origid` match |
| 5 | Chain verification (destination linkage) | Implemented | `DivPassport.verify_chain` checks that `div.tn` appears in the SHAKEN `dest.tn` |
| 5 | Complete call forwarding workflow | Implemented | `AuthenticationService#create_call_forwarding` handles the full scenario with attestation reduction |
| 5 | Attestation handling for forwarded calls | Implemented | `AuthenticationService#determine_forwarding_attestation` reduces A->B, B->C, C->C |
| 6 | DIV SIP Identity header | Implemented | `AuthenticationService#sign_diverted_call` creates DIV headers using `SipIdentity.create` with `ppt=div` |

---

## Summary

| RFC | Title | Coverage |
|-----|-------|----------|
| RFC 8224 | Authenticated Identity Management in SIP | Implemented (SIP Identity header creation, parsing, verification; SIP stack integration is out of scope) |
| RFC 8225 | PASSporT Token Format | Implemented (full JWT creation, parsing, validation, E.164 enforcement) |
| RFC 8226 | Secure Telephone Identity Credentials | Implemented (certificate fetch/cache/validate, HTTPS enforcement, TNAuthList, SAN; OCSP not implemented) |
| RFC 8588 | SHAKEN PASSporT Extension | Implemented (attestation levels, origid, lexicographic key ordering) |
| RFC 8946 | DIV PASSporT Extension | Implemented (DIV token creation, diversion reasons, chain verification, forwarding workflow) |

### Not Implemented

The following items from the above RFCs are not implemented:

- **SIP stack integration** (RFC 8224 sections 5+): The library produces and consumes Identity header values but does not handle SIP message framing, INVITE processing, or SIP transport.
- **OCSP revocation checking** (RFC 8226): Only CRL-based revocation checking is supported. OCSP stapling/querying is not implemented.
- **Delegate certificates** (RFC 8226 section 7): Delegate certificate issuance and validation is not implemented.
- **STIR certificate discovery** (RFC 8226 section 10): Automatic discovery of the correct certificate authority is not implemented; certificate URLs must be provided explicitly.
- **Cross-certificate trust** (RFC 8226 section 8): Cross-certification between trust anchors is not directly handled; trust is established via the configured trust store.
