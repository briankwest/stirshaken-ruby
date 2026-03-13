# Call Diversion (DIV PASSporT) Guide

This guide covers call diversion and forwarding support in the stirshaken-ruby gem, implementing the DIV PASSporT extension defined in RFC 8946.

---

## Table of Contents

- [Overview](#overview)
- [Valid Diversion Reasons](#valid-diversion-reasons)
- [Creating a DIV PASSporT from an Existing PASSporT](#creating-a-div-passport-from-an-existing-passport)
- [Creating a DIV PASSporT from a SHAKEN Identity Header](#creating-a-div-passport-from-a-shaken-identity-header)
- [Complete Call Forwarding Scenario](#complete-call-forwarding-scenario)
- [Attestation Reduction Rules](#attestation-reduction-rules)
- [Verifying DIV PASSporT Chain Integrity](#verifying-div-passport-chain-integrity)
- [DIV PASSporT Token Structure](#div-passport-token-structure)

---

## Overview

In STIR/SHAKEN, a call may be forwarded or diverted by an intermediary service provider after the original caller identity has already been signed. RFC 8946 defines the **DIV PASSporT** extension to handle this scenario. It provides a cryptographic assertion that a call has been diverted, preserving the chain of trust back to the original SHAKEN PASSporT.

A DIV PASSporT token:

- Uses the `"div"` extension (JWT header `ppt: "div"`) instead of the standard `"shaken"`.
- Includes a `div` claim in the payload containing the original destination number (`tn`) and the reason for diversion (`reason`).
- Preserves the originating number and origination ID from the original PASSporT so the chain can be verified.
- Is signed by the diverting party's private key and certificate, which may differ from the original signer.

The `StirShaken::DivPassport` class inherits from `StirShaken::Passport` and adds the DIV-specific claims and validation.

---

## Valid Diversion Reasons

RFC 8946 defines 10 valid diversion reasons. These are enforced by `DivPassport.validate_diversion_reason!` and are available as the frozen constant `DivPassport::VALID_DIVERSION_REASONS`.

| Reason | Description |
|--------|-------------|
| `forwarding` | Generic call forwarding |
| `deflection` | Call deflection (redirected before answer) |
| `follow-me` | Follow-me routing to an alternate number |
| `time-of-day` | Time-of-day based routing |
| `user-busy` | Forwarding on busy |
| `no-answer` | Forwarding on no answer |
| `unavailable` | Forwarding when user is unavailable/unreachable |
| `unconditional` | Unconditional call forwarding (always active) |
| `away` | User is marked as away |
| `unknown` | Reason for diversion is unknown |

Using an invalid reason raises `StirShaken::InvalidDiversionReasonError`.

---

## Creating a DIV PASSporT from an Existing PASSporT

When you have already parsed the original SHAKEN PASSporT object, use `DivPassport.create_div` or `AuthenticationService#create_div_passport`.

### Using DivPassport.create_div directly

```ruby
# Setup: generate keys and create original PASSporT
keys = StirShaken::AuthenticationService.generate_key_pair
private_key = keys[:private_key]

original_token = StirShaken::Passport.create(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A',
  certificate_url: 'https://cert.example.com/original.pem',
  private_key: private_key
)

original_passport = StirShaken::Passport.parse(original_token, verify_signature: false)

# Create the DIV PASSporT
div_token = StirShaken::DivPassport.create_div(
  original_passport: original_passport,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'no-answer',
  certificate_url: 'https://cert.example.com/diverter.pem',
  private_key: private_key
)
```

### Using AuthenticationService#create_div_passport

The `AuthenticationService` wraps `DivPassport.create_div` and adds security logging.

```ruby
auth = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://cert.example.com/diverter.pem'
)

div_token = auth.create_div_passport(
  original_passport: original_passport,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'user-busy'
)
```

The `origination_id` defaults to the original passport's origination ID, preserving the chain link between the two tokens.

---

## Creating a DIV PASSporT from a SHAKEN Identity Header

When you have a raw SIP Identity header string rather than a parsed PASSporT object, use `DivPassport.create_from_identity_header` or `AuthenticationService#create_div_passport_from_header`.

This method parses the SIP Identity header, extracts the PASSporT, and then creates the DIV token.

### Using DivPassport.create_from_identity_header directly

```ruby
# shaken_header is a string like:
#   "eyJ...;info=<https://cert.example.com/original.pem>;alg=ES256;ppt=shaken"

div_token = StirShaken::DivPassport.create_from_identity_header(
  shaken_identity_header: shaken_header,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'forwarding',
  certificate_url: 'https://cert.example.com/diverter.pem',
  private_key: private_key,
  public_key: nil  # pass the original signer's public key to verify
)
```

When `public_key` is `nil`, the original PASSporT signature is not verified (it is only decoded). Pass the original signer's public key to enable verification of the original token before creating the DIV token.

### Using AuthenticationService#create_div_passport_from_header

```ruby
auth = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://cert.example.com/diverter.pem',
  certificate: diverter_certificate  # needed if verify_original: true
)

div_token = auth.create_div_passport_from_header(
  shaken_identity_header: shaken_header,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'time-of-day',
  verify_original: false
)
```

When `verify_original` is `true`, the method extracts the public key from the authentication service's loaded certificate and uses it to verify the original PASSporT's signature.

### Creating a complete DIV SIP Identity header

To get both the original SHAKEN header and a new DIV Identity header, use `AuthenticationService#sign_diverted_call`:

```ruby
result = auth.sign_diverted_call(
  shaken_identity_header: shaken_header,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'unconditional'
)

original_header = result[:shaken_header]  # passed through unchanged
div_header      = result[:div_header]     # new DIV SIP Identity header
```

The DIV SIP Identity header uses `ppt=div` instead of `ppt=shaken`:

```
eyJ...;info=<https://cert.example.com/diverter.pem>;alg=ES256;ppt=div
```

---

## Complete Call Forwarding Scenario

`AuthenticationService#create_call_forwarding` handles a complete call forwarding scenario in a single call. It:

1. Creates (or reuses) the original SHAKEN Identity header.
2. Creates a new SHAKEN Identity header for the forwarded leg with automatically reduced attestation.
3. Creates a DIV PASSporT and wraps it in a DIV SIP Identity header.

```ruby
keys = StirShaken::AuthenticationService.generate_key_pair
private_key = keys[:private_key]
cert = StirShaken::AuthenticationService.create_test_certificate(
  private_key,
  telephone_numbers: ['+15551234567']
)

auth = StirShaken::AuthenticationService.new(
  private_key: private_key,
  certificate_url: 'https://cert.example.com/provider.pem',
  certificate: cert
)

result = auth.create_call_forwarding(
  original_call_info: {
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'A',
    origination_id: 'call-uuid-123'
  },
  forwarding_info: {
    new_destination: '+15553334444',
    reason: 'no-answer'
  }
)

# Result contains all the headers you need:
result[:original_shaken_header]     # SHAKEN header for the original call leg
result[:forwarded_shaken_header]    # SHAKEN header for the forwarded leg (attestation: 'B')
result[:div_header]                 # DIV SIP Identity header

# Metadata about the forwarding:
result[:metadata]
# => {
#   originating_number: '+15551234567',
#   original_destination: '+15559876543',
#   new_destination: '+15553334444',
#   original_attestation: 'A',
#   forwarded_attestation: 'B',
#   diversion_reason: 'no-answer',
#   origination_id: 'call-uuid-123'
# }
```

### Overriding attestation reduction

You can override the automatic attestation reduction by explicitly setting the attestation in `forwarding_info`:

```ruby
result = auth.create_call_forwarding(
  original_call_info: {
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'A'
  },
  forwarding_info: {
    new_destination: '+15553334444',
    reason: 'forwarding',
    attestation: 'A'  # override: keep Full Attestation
  }
)
```

### Reusing an existing SHAKEN header

If you already have the original SHAKEN Identity header (e.g., received from an upstream provider), pass it in `original_call_info[:identity_header]` to avoid re-creating it:

```ruby
result = auth.create_call_forwarding(
  original_call_info: {
    originating_number: '+15551234567',
    destination_number: '+15559876543',
    attestation: 'A',
    identity_header: existing_shaken_header
  },
  forwarding_info: {
    new_destination: '+15553334444',
    reason: 'forwarding'
  }
)
```

---

## Attestation Reduction Rules

When a call is forwarded, the diverting service provider generally cannot provide the same level of attestation as the originating provider. The `create_call_forwarding` method applies these reduction rules automatically (via the private `determine_forwarding_attestation` method):

| Original Attestation | Forwarded Attestation | Rationale |
|---------------------|-----------------------|-----------|
| `A` (Full) | `B` (Partial) | Diverter authenticated the origination but cannot fully verify the caller's authorization to the new destination. |
| `B` (Partial) | `C` (Gateway) | Further reduced because the diverter has less information about the originating caller. |
| `C` (Gateway) | `C` (Gateway) | Cannot reduce further; remains at the lowest level. |

These rules apply only to the **forwarded SHAKEN header** (the new `sign_call` for the forwarded leg). The DIV PASSporT itself carries the original attestation level from the original PASSporT so the verifier can see what attestation the call originally had.

---

## Verifying DIV PASSporT Chain Integrity

`DivPassport.verify_chain` verifies that a DIV PASSporT correctly chains back to its original SHAKEN PASSporT. It performs three checks:

1. **Originating number match** -- the DIV and SHAKEN PASSporTs must have the same `orig.tn`.
2. **Origination ID match** -- the DIV and SHAKEN PASSporTs must have the same `origid`.
3. **Destination linkage** -- the DIV PASSporT's `div.tn` (original destination) must appear in the SHAKEN PASSporT's `dest.tn` array.

```ruby
# Parse DIV and SHAKEN tokens with their respective public keys
result = StirShaken::DivPassport.verify_chain(
  div_token: div_jwt_token,
  shaken_token: shaken_jwt_token,
  div_public_key: diverter_public_key,
  shaken_public_key: original_signer_public_key  # optional
)

if result[:valid]
  div_passport    = result[:div_passport]
  shaken_passport = result[:shaken_passport]

  puts "Chain verified successfully"
  puts "Originating: #{div_passport.originating_number}"
  puts "Original destination: #{div_passport.original_destination}"
  puts "New destinations: #{div_passport.destination_numbers.join(', ')}"
  puts "Diversion reason: #{div_passport.diversion_reason}"
else
  puts "Chain verification failed: #{result[:reason]}"
  # Possible reasons:
  #   "Originating number mismatch between DIV and SHAKEN PASSporTs"
  #   "Origination ID mismatch between DIV and SHAKEN PASSporTs"
  #   "DIV original destination not found in SHAKEN destinations"
end
```

When `shaken_public_key` is `nil`, the original SHAKEN token is decoded without signature verification. This is useful when you do not have access to the original signer's certificate but still want to validate the structural chain.

### Full end-to-end example

```ruby
# -- Originating provider signs the call --
orig_keys = StirShaken::AuthenticationService.generate_key_pair
orig_auth = StirShaken::AuthenticationService.new(
  private_key: orig_keys[:private_key],
  certificate_url: 'https://cert.example.com/originator.pem'
)

shaken_token = orig_auth.create_passport(
  originating_number: '+15551234567',
  destination_numbers: ['+15559876543'],
  attestation: 'A'
)

shaken_header = StirShaken::SipIdentity.create(
  passport_token: shaken_token,
  certificate_url: 'https://cert.example.com/originator.pem'
)

# -- Diverting provider forwards the call --
div_keys = StirShaken::AuthenticationService.generate_key_pair
div_auth = StirShaken::AuthenticationService.new(
  private_key: div_keys[:private_key],
  certificate_url: 'https://cert.example.com/diverter.pem'
)

div_token = div_auth.create_div_passport_from_header(
  shaken_identity_header: shaken_header,
  new_destination: '+15553334444',
  original_destination: '+15559876543',
  diversion_reason: 'no-answer'
)

# -- Terminating provider verifies the chain --
chain_result = StirShaken::DivPassport.verify_chain(
  div_token: div_token,
  shaken_token: shaken_token,
  div_public_key: div_keys[:public_key],
  shaken_public_key: orig_keys[:public_key]
)

puts chain_result[:valid]  # => true
```

---

## DIV PASSporT Token Structure

A DIV PASSporT JWT has the following structure:

### Header

```json
{
  "alg": "ES256",
  "typ": "passport",
  "ppt": "div",
  "x5u": "https://cert.example.com/diverter.pem"
}
```

Note that `ppt` is `"div"` instead of `"shaken"`.

### Payload

```json
{
  "attest": "A",
  "dest": {
    "tn": ["+15553334444"]
  },
  "div": {
    "tn": "+15559876543",
    "reason": "no-answer"
  },
  "iat": 1710288000,
  "orig": {
    "tn": "+15551234567"
  },
  "origid": "abc-123-def-456"
}
```

Key differences from a standard SHAKEN PASSporT:
- The `div` claim is present, containing `tn` (original destination) and `reason`.
- The `dest.tn` array contains the new diversion target(s), not the original destination.
- The `orig.tn` and `origid` are preserved from the original PASSporT to maintain chain integrity.
- The `attest` value reflects the original attestation level.
