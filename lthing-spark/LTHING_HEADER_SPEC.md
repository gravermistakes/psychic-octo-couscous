# LTHING Header Specification

**Format:** Legally Tractable Honorably Imposed Notarization Guide
**Version:** Working Draft — 1750099200
**License:** ESL-ANCSA-MRA-IndiModSHA v1.3

---

## §1 — Overview

The LTHING envelope is a pure binary format with four sections:
**Header**, **Body**, **Provenance Seal**, and **Signature**, with an
optional fifth section (**AEAD Tag**) for encrypted bodies. All section
offsets are computable from length fields in the header — no text
delimiters, no scanning.

Nibble order: **high nibble first** within each byte.
Byte order: **big-endian** (network order).
MIME type: `application/vnd.lthing`
File extension: `.{doctype}.lthing` (lowercase), e.g. `.jd.lthing`

---

## §2 — Magic Prefix (14 bytes)

### §2.1 — Preamble (10 bytes)

```
Byte:    00  00  00  0B  0D  EE  D0  00  00  00
Nibble:  0 0 0 0 0 0 0 B 0 D E E D 0 0 0 0 0 0 0
         ├───────────┤ ├─────────┤ ├┤ ├────────┤
         7 null        B0DEED     nul  5 null
```

| Component       | Nibbles | Value     | Purpose                       |
|-----------------|---------|-----------|-------------------------------|
| Null preamble   | 0–6     | `0000000` | Anti-text trap; kills null-term|
| B0DEED          | 7–12    | `B0DEED`  | Format ID — "bodied"          |
| Null separator  | 13      | `0`       | Delimiter                     |
| Null bulk       | 14–18   | `00000`   | Reserved                      |
| Offset nibble   | 19      | `0`       | Pushes doctype to mid-byte    |

**Fixed. MUST reject if ≠ `00 00 00 0B 0D EE D0 00 00 00`.**

### §2.2 — DocType (3 wire bytes, 5 nibbles)

Nibble-straddled ASCII. 2 uppercase bytes + null nibble terminator.
Starts at nibble 20 (mid-byte due to offset nibble).

Alignment transitions in the first 14 bytes:
1. Bytes 0–9: literal comparison (preamble)
2. Bytes 10–12: nibble-straddled ASCII (doctype)
3. Byte 13: nibble-packed version (hi=major, lo=minor)
4. Bytes 14+: byte-aligned integers

Wire encoding for code B1 B2 (nibbles h1 l1, h2 l2):
```
Byte 10 = 0x0{h1}     Byte 11 = 0x{l1}{h2}     Byte 12 = 0x{l2}0
```

### §2.3 — DocType Registry (20 codes)

Valid bytes: 0x41–0x5A (A–Z), 0x30–0x39 (0–9). All others RESERVED.

| Code | Wire (B10 B11 B12) | Extension  | Trust Domain                          |
|------|--------------------|------------|---------------------------------------|
| IP   | 04 95 00           | .ip.lthing | Intellectual Property                 |
| JD   | 04 A4 40           | .jd.lthing | Judicial                              |
| MD   | 04 D4 40           | .md.lthing | Medical                               |
| ED   | 04 54 40           | .ed.lthing | Education                             |
| GV   | 04 75 60           | .gv.lthing | Government                            |
| ES   | 04 55 30           | .es.lthing | ESL License                           |
| JB   | 04 A4 20           | .jb.lthing | JB EASY                               |
| CF   | 04 34 60           | .cf.lthing | Configuration                         |
| MI   | 04 D4 90           | .mi.lthing | Military                              |
| FN   | 04 64 E0           | .fn.lthing | Finance                               |
| RE   | 05 24 50           | .re.lthing | Real Estate                           |
| ID   | 04 94 40           | .id.lthing | Identity                              |
| TR   | 05 45 20           | .tr.lthing | Tribal / Indigenous                   |
| IS   | 04 95 30           | .is.lthing | Insurance / Surety                    |
| IN   | 04 94 E0           | .in.lthing | International                         |
| IQ   | 04 95 10           | .iq.lthing | Intelligence                          |
| EN   | 04 54 E0           | .en.lthing | Environmental                         |
| LB   | 04 C4 20           | .lb.lthing | Labor                                 |
| NG   | 04 E4 70           | .ng.lthing | NGO / Nonprofit                       |
| FE   | 04 64 50           | .fe.lthing | Fourth Estate                         |

### §2.4 — Version (1 byte)

Byte 13. High nibble = major, low = minor. 0x00 RESERVED (MUST reject).
Minimum: 0x01 (v0.1). Maximum: 0xFF (v15.15).

### §2.5 — Prefix Example (JD v1.0)

```
00 00 00 0B 0D EE D0 00 00 00 04 A4 40 10
```

---

## §3 — Header (40 bytes fixed)

The header carries the prefix and all section lengths. Every section
offset is computable from header fields alone.

```
Offset  Size    Field
0       14 B    Prefix (magic + doctype + version)          §2
14      2 B     Crypto suite selector                       §3.1
16      8 B     Timestamp (Unix epoch, signer's claim)      §3.2
24      4 B     Body length                                 §3.3
28      4 B     Provenance seal length                      §3.3
32      4 B     Signature length                            §3.3
36      4 B     AEAD tag length (0 = plaintext)             §3.3
```

**Total header: 40 bytes, fixed.** All subsequent sections are
locatable by cumulative offset:

```
Section             Offset                      Size
Body                40                          body_len
Provenance Seal     40 + BL                     seal_len
Signature           40 + BL + SL                sig_len
AEAD Tag            40 + BL + SL + SigL         aead_len
```

### §3.1 — Crypto Suite Selector (2 bytes)

Big-endian. Interpreted relative to doctype (§2.3). Each suite is a
complete, indivisible cryptographic configuration.

| Suite  | Status   |
|--------|----------|
| 0x0000 | RESERVED — MUST reject |
| 0x0001 | Baseline (all doctypes initially) |

Suite 0x0001 baseline:

| Field      | Value                           |
|------------|---------------------------------|
| Hash       | LTHING SHAKE512 (rate 72, 0x1F) |
| Signature  | ML-DSA-65 (FIPS 204)            |
| AEAD       | None (tag_len = 0)              |
| Rule30     | None (ES doctype suites only)   |

### §3.2 — Timestamp (8 bytes)

Unsigned 64-bit, big-endian, Unix epoch. **Signer's claim, not proof.**

### §3.3 — Length Fields (4 × 4 bytes)

**Body length:** Max ~4 GiB. 0 valid (tombstone/revocation).
**Seal length:** MUST > 0. Variable (contains signer identity).
**Sig length:** MUST > 0. Must match suite definition. Suites MUST
define fixed signature lengths.
**AEAD tag length:** 0 = plaintext body. > 0 = encrypted, tag follows
signature. Must match suite AEAD definition.

---

## §4 — Body

`body_length` bytes at offset 40. Opaque to the envelope — the doctype
(§2.3) declares the trust domain; the payload format is
application-defined. May be a PDF, YAML schema, JSON record, or raw
binary.

**Write-time buffering:** The provenance seal contains the body hash.
The body must be fully buffered or pre-hashed before the seal can be
computed. LTHING envelopes are not streamable on write.

---

## §5 — Provenance Seal

`seal_length` bytes at offset 40 + body_length. A structured binary
record carrying chain position, body hash, signer identity, and
document relationship metadata. This is NOT just a hash — it is a
signed provenance record.

### §5.1 — Seal Layout

```
Offset   Size             Field
0        2 B              AncestorCount (big-endian)
2        var (from suite) ArtifactHash (body hash)
2+AH     64 B             ChainHash
2+AH+64  1 B              Relation
3+AH+64  1 B              SignerIdLen
4+AH+64  SignerIdLen B     SignerId
4+AH+64+SIL  64 B         SealId (unique seal identifier)
```

### §5.2 — AncestorCount (2 bytes)

Big-endian unsigned. Number of documents preceding this one in the
chain. 0 = genesis (first document). Max 65535 chain depth.

### §5.3 — ArtifactHash (suite-determined width)

Hash of the body, computed per the suite's hash algorithm.
Suite 0x0001: `LTHING_SHAKE512(body)` = 64 bytes.

Content-addressable identifier for the payload. Computed over raw body
bytes only, not the header.

### §5.4 — ChainHash (64 bytes, always LTHING SHAKE512)

```
chain = SHAKE512(prev_chain ‖ artifact_hash)
```

Genesis: `prev_chain` = 64 zero bytes.
Subsequent: `prev_chain` = ChainHash of preceding document.

**Design decision:** ChainHash is always LTHING SHAKE512 regardless of
suite. The chain is a structural ordering mechanism independent of the
regulatory crypto domain. ArtifactHash is suite-determined. Two
different hash functions in one seal is by design.

### §5.5 — Relation (1 byte)

Relationship of this document to its chain predecessor:

| Value | Meaning      | Description                              |
|-------|-------------|------------------------------------------|
| 0x00  | GENESIS     | First in chain, no predecessor           |
| 0x01  | SUCCESSOR   | Continuation of chain                    |
| 0x02  | AMENDMENT   | Modifies a predecessor                   |
| 0x03  | REVOCATION  | Invalidates a predecessor                |
| 0x04  | SUPERSEDE   | Replaces a predecessor entirely          |
| 0x05  | RESPONSE    | Reply or counter-document                |
| 0x06–0xFE | RESERVED |                                          |
| 0xFF  | TOMBSTONE   | Chain termination marker                 |

### §5.6 — SignerIdLen + SignerId (1 + variable bytes)

Length-prefixed signer identifier. Max 255 bytes. Content is
application-defined — may be a human name, a key fingerprint (32-byte
SHAKE256 of public key), a URI, or a JB EASY Holder UUID.

### §5.7 — SealId (64 bytes)

Unique identifier for this provenance record. Computed as:

```
seal_id = SHAKE512(ancestor_count ‖ artifact_hash ‖ chain_hash
                   ‖ relation ‖ signer_id)
```

The SealId binds all provenance fields into a single identifier. Two
seals with identical fields produce the same SealId; any difference
produces a different one.

---

## §6 — Signature

`sig_length` bytes at offset 40 + BL + SL.

**The signed message is the exact byte sequence on the wire with no
canonicalization:**

```
signed_message = bytes[0 .. 40 + body_length + seal_length - 1]
               = header ‖ body ‖ provenance_seal
```

The signature binds: format identity (prefix), crypto config (suite),
claimed time (timestamp), section geometry (lengths), the payload
(body), and all provenance metadata (seal).

Suite 0x0001: ML-DSA-65 (FIPS 204), 3309 bytes.

---

## §7 — AEAD Tag

`aead_length` bytes at offset 40 + BL + SL + SigL. Present only when
the suite includes AEAD (aead_length > 0 in header).

When AEAD is active, the **body** is ciphertext. The AEAD tag
authenticates the ciphertext body. The AEAD additional data (AD) is the
header (bytes 0–39) — so the header is authenticated but not encrypted.

Suite 0x0001: no AEAD (aead_length = 0, section absent).
Future suites define the AEAD algorithm and tag size.

---

## §8 — Wire Format Summary

Complete JD v1.0 envelope, suite 0x0001, 4096-byte body, genesis:

```
Offset  Size    Field                         Example
0       10 B    Preamble                      00 00 00 0B 0D EE D0 00 00 00
10      3 B     DocType (straddled)           04 A4 40
13      1 B     Version                       10
14      2 B     Suite                         00 01
16      8 B     Timestamp                     00 00 00 00 68 50 5C 00
24      4 B     Body length                   00 00 10 00  (4096)
28      4 B     Seal length                   00 00 00 CF  (207)
32      4 B     Sig length                    00 00 0C ED  (3309)
36      4 B     AEAD tag length               00 00 00 00  (0 = plaintext)
────── HEADER END (40 bytes) ──────
40      4096 B  Body                          (contents)
────── BODY END ──────
4136    2 B     AncestorCount                 00 00  (genesis)
4138    64 B    ArtifactHash                  LTHING_SHAKE512(body)
4202    64 B    ChainHash                     SHAKE512(zeros ‖ artifact)
4266    1 B     Relation                      00  (genesis)
4267    1 B     SignerIdLen                   0B  (11)
4268    11 B    SignerId                      "l'Evermoor" (UTF-8)
4279    64 B    SealId                        SHAKE512(seal fields)
────── SEAL END (207 bytes) ──────
4343    3309 B  Signature                     ML-DSA-65(bytes[0..4342])
────── SIG END ──────
────── ENVELOPE END ──────
```

Seal length for this example: 2 (ancestor) + 64 (artifact) + 64 (chain) +
1 (relation) + 1 (signer_len) + 11 (signer_id) + 64 (seal_id) = **207**.

Total: 40 + 4096 + 207 + 3309 = **7652 bytes**.

---

## §9 — Parser Requirements

1. **MUST** reject if first 10 bytes ≠ preamble
2. **MUST** reject if doctype bytes outside A–Z / 0–9
3. **MUST** reject if seal_length = 0
4. **MUST** reject if sig_length = 0
5. **MUST** reject if any length field overflows available data
6. **MUST** verify ArtifactHash: recompute hash over body
7. **MUST** verify ChainHash if prev_chain available
8. **MUST** verify SealId: recompute from seal fields
9. **MUST** verify Relation consistency (GENESIS ↔ AncestorCount=0)
10. **MUST** verify signature over bytes[0..40+BL+SL-1]
11. **MUST** verify AEAD tag if aead_length > 0
12. **MUST NOT** expose parsed fields before all verification completes.
    Distinct types: `Unverified_Envelope` → `verify()` → `Envelope`.

---

## §10 — Deferred

| Feature                    | Rationale                               |
|----------------------------|-----------------------------------------|
| Per-doctype suite tables   | Regulatory-specific crypto configs      |
| Rule30 rounds (ES only)    | ESL provenance salt; ES suite 0x0002+   |
| Full hash combiner         | SHAKE256 ‖ BLAKE3 seal; future suite    |
| 5-family PQC combiner      | Future suite; sig_length field ready    |
| Extension TLVs             | Post-seal extension mechanism           |
| Header self-checksum       | Independent of signature                |
| Trusted timestamping       | RFC 3161; external to envelope          |
| Doctype parity nibble      | Error detection for nibble corruption   |
| IANA MIME registration     | Required before public deployment       |
| Passphrase-protected keys  | Argon2id + AEAD on .key files           |

All deferred features are additive. Future versions extend, never redefine.

---

## Appendix A — Per-DocType Suite Tables

**TO BE POPULATED.** Structure per doctype:

```
DocType: XX
Suite  Hash      Sig        Seal   AEAD       Rule30  Notes
0x0000 RESERVED  —          —      —          —       MUST reject
0x0001 SHAKE512  ML-DSA-65  64B    None       No      Baseline
```
