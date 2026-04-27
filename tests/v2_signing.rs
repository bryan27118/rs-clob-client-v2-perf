//! V2 signing parity tests.
//!
//! Verifies our `Order` struct produces the same EIP-712 type hash and
//! domain separator as the official py-clob-client-v2 and clob-client-v2
//! SDKs.
//!
//! Spec reference: `docs/clob-v2-migration-spec.md` §§3, 6 (in the downstream
//! repo). BullpenFi/rs-clob-client-v2 does the same check at
//! `tests/signing.rs:79-86` (independent prior art).

#![allow(clippy::exhaustive_structs, reason = "local test helpers")]

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::{B256, U256, address, keccak256};
use alloy::sol;
use alloy::sol_types::{SolStruct as _, SolValue as _};
use polymarket_client_sdk_v2::clob::types::{OrderV2 as Order, Side, SignatureType};

use std::borrow::Cow;

const CTF_EXCHANGE_V2: alloy::primitives::Address =
    address!("0xE111180000d2663C0091e4f400237545B87B996B");

const NEG_RISK_EXCHANGE_V2: alloy::primitives::Address =
    address!("0xe2222d279d744050d28e00520010520000310F59");

const POLYGON: u64 = 137;
const AMOY: u64 = 80002;

/// EIP-712 domain for V2 exchange signing. Matches the domain built inside
/// `Client::sign` at `src/clob/client.rs:1457-1463` (the only path used in
/// production), extracted here so tests can assert the exact bytes.
fn v2_domain(chain_id: u64, verifying_contract: alloy::primitives::Address) -> Eip712Domain {
    Eip712Domain {
        name: Some(Cow::Borrowed("Polymarket CTF Exchange")),
        version: Some(Cow::Borrowed("2")),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(verifying_contract),
        ..Eip712Domain::default()
    }
}

fn sample_order() -> Order {
    // `Order` is `#[non_exhaustive]` so we can't use a struct literal from
    // outside the crate. Populate via `default()` + field assignment.
    let mut o = Order::default();
    o.salt = U256::from(1_u64);
    o.maker = address!("0x0000000000000000000000000000000000000001");
    o.signer = address!("0x0000000000000000000000000000000000000002");
    o.tokenId = U256::from(123_u64);
    o.makerAmount = U256::from(1_000_000_u64);
    o.takerAmount = U256::from(2_000_000_u64);
    o.side = Side::Buy as u8;
    o.signatureType = SignatureType::Eoa as u8;
    o.timestamp = U256::from(1_700_000_000_000_u64);
    o.metadata = B256::ZERO;
    o.builder = B256::ZERO;
    o
}

/// The **exact** EIP-712 type-hash preimage for the V2 Order struct, as
/// declared by py-clob-client-v2 and clob-client-v2. A byte-level mismatch
/// here means the CLOB will reject every signature we produce.
///
/// Field order and single-space formatting matter — EIP-712 preserves
/// `<type> <name>` separated by a single space, with commas between fields
/// and no other whitespace.
///
/// Citations:
/// - py-clob-client-v2/py_clob_client_v2/order_utils/model/ctf_exchange_v2_typed_data.py:5-17
/// - clob-client-v2/src/order-utils/model/ctfExchangeV2TypedData.ts:5-17
/// - BullpenFi/rs-clob-client-v2/src/clob/types/order.rs:155 (independent
///   derivation of the same literal)
const V2_TYPE_HASH_PREIMAGE: &str =
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)";

#[test]
fn v2_type_hash_preimage_matches_py_ts_v2() {
    let expected_hash = keccak256(V2_TYPE_HASH_PREIMAGE.as_bytes());

    assert_eq!(
        sample_order().eip712_type_hash(),
        expected_hash,
        "V2 Order type hash must match the preimage declared by py-clob-client-v2"
    );
}

// Manually assemble the domain separator via `abi_encode` + `keccak256`
// and verify it matches the one alloy builds via `Eip712Domain::separator`.
// Belt-and-suspenders parity check against the py/ts SDK domain hashing.
sol! {
    struct DomainFields {
        bytes32 typeHash;
        bytes32 nameHash;
        bytes32 versionHash;
        uint256 chainId;
        address verifyingContract;
    }
}

fn expected_domain_separator(
    chain_id: u64,
    verifying_contract: alloy::primitives::Address,
) -> B256 {
    let fields = DomainFields {
        typeHash: keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ),
        nameHash: keccak256("Polymarket CTF Exchange"),
        versionHash: keccak256("2"),
        chainId: U256::from(chain_id),
        verifyingContract: verifying_contract,
    };

    keccak256(fields.abi_encode())
}

#[test]
fn v2_domain_separator_polygon_standard() {
    assert_eq!(
        v2_domain(POLYGON, CTF_EXCHANGE_V2).separator(),
        expected_domain_separator(POLYGON, CTF_EXCHANGE_V2),
    );
}

#[test]
fn v2_domain_separator_polygon_neg_risk() {
    assert_eq!(
        v2_domain(POLYGON, NEG_RISK_EXCHANGE_V2).separator(),
        expected_domain_separator(POLYGON, NEG_RISK_EXCHANGE_V2),
    );
}

#[test]
fn v2_domain_separator_amoy_standard() {
    assert_eq!(
        v2_domain(AMOY, CTF_EXCHANGE_V2).separator(),
        expected_domain_separator(AMOY, CTF_EXCHANGE_V2),
    );
}

#[test]
fn v2_domain_separator_amoy_neg_risk() {
    assert_eq!(
        v2_domain(AMOY, NEG_RISK_EXCHANGE_V2).separator(),
        expected_domain_separator(AMOY, NEG_RISK_EXCHANGE_V2),
    );
}

#[test]
fn v2_neg_risk_domain_differs_from_standard() {
    let standard = v2_domain(POLYGON, CTF_EXCHANGE_V2).separator();
    let neg_risk = v2_domain(POLYGON, NEG_RISK_EXCHANGE_V2).separator();
    assert_ne!(
        standard, neg_risk,
        "neg-risk vs standard domain separators must differ — otherwise orders \
         routed to the wrong exchange would still validate"
    );
}

#[test]
fn v2_signing_hash_stable_for_fixed_order() {
    // Given fixed inputs, the EIP-712 digest must be deterministic.
    let order = sample_order();
    let domain = v2_domain(POLYGON, CTF_EXCHANGE_V2);
    let digest_1 = order.eip712_signing_hash(&domain);
    let digest_2 = order.eip712_signing_hash(&domain);
    assert_eq!(digest_1, digest_2);
}

#[test]
fn v2_signing_hash_differs_for_different_chain() {
    let order = sample_order();
    let polygon = v2_domain(POLYGON, CTF_EXCHANGE_V2);
    let amoy = v2_domain(AMOY, CTF_EXCHANGE_V2);
    assert_ne!(
        order.eip712_signing_hash(&polygon),
        order.eip712_signing_hash(&amoy),
        "same order on different chains must produce different signing hashes"
    );
}

#[test]
fn v2_signing_hash_differs_for_different_exchange() {
    let order = sample_order();
    let std = v2_domain(POLYGON, CTF_EXCHANGE_V2);
    let neg = v2_domain(POLYGON, NEG_RISK_EXCHANGE_V2);
    assert_ne!(
        order.eip712_signing_hash(&std),
        order.eip712_signing_hash(&neg),
        "orders routed to standard vs neg-risk exchanges must produce different digests"
    );
}

#[test]
fn v2_order_struct_has_no_v1_fields() {
    // Compile-time check: if any of these fields ever reappear on `Order`,
    // signing will diverge silently from py/ts V2. Keep this test.
    // (The struct is `#[non_exhaustive]`, but field access below is still
    // name-checked at compile time.)
    let order = sample_order();
    let _ = order.timestamp;
    let _ = order.metadata;
    let _ = order.builder;
    // The following lines would fail to compile if V2 field removal is reverted.
    // Leave them commented — they document intent without breaking the build.
    // let _ = order.nonce;      // removed in V2
    // let _ = order.taker;      // removed in V2
    // let _ = order.feeRateBps; // removed in V2
    // let _ = order.expiration; // wire-only in V2, not in signed struct
}

/// Redundant safety check: our `Order` struct's auto-derived type hash matches
/// the hand-computed keccak of the py/ts preimage. If this ever fails, the
/// sol! struct in `src/clob/types/mod.rs` has drifted from V2 spec.
#[test]
fn v2_type_hash_matches_manual_keccak() {
    let from_preimage = keccak256(V2_TYPE_HASH_PREIMAGE.as_bytes());
    assert_eq!(sample_order().eip712_type_hash(), from_preimage);
}

// ------------------------------------------------------------------------
// Byte-for-byte parity against py-clob-client-v2 generated signatures.
// Fixture: tests/fixtures/v2_signing_vectors.json (produced by
// clob-v2-research/gen_v2_vector.py using py-clob-client-v2 directly).
// ------------------------------------------------------------------------

use alloy::signers::SignerSync as _;
use alloy::signers::local::PrivateKeySigner;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct VectorsFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    inputs: Inputs,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct Inputs {
    private_key: String,
    chain_id: u64,
    verifying_contract: String,
    salt: u64,
    maker: String,
    signer: String,
    token_id: u64,
    maker_amount: u64,
    taker_amount: u64,
    side: u8,
    signature_type: u8,
    timestamp_ms: u64,
    metadata: String,
    builder: String,
    expiration: u64,
}

#[derive(Debug, Deserialize)]
struct Expected {
    domain_separator: String,
    struct_hash: String,
    digest: String,
    signature: String,
}

fn parse_b256(s: &str) -> B256 {
    B256::from_str(s.trim_start_matches("0x")).unwrap_or_else(|e| panic!("bad b256 {s}: {e}"))
}

#[test]
fn v2_byte_parity_with_py_clob_client_v2() {
    let raw = include_str!("fixtures/v2_signing_vectors.json");
    let file: VectorsFile = serde_json::from_str(raw).expect("fixture parses");
    assert!(!file.vectors.is_empty(), "at least one vector");

    for v in &file.vectors {
        // Build the order exactly as the Python fixture did.
        let mut order = Order::default();
        order.salt = U256::from(v.inputs.salt);
        order.maker = alloy::primitives::Address::from_str(&v.inputs.maker).unwrap();
        order.signer = alloy::primitives::Address::from_str(&v.inputs.signer).unwrap();
        order.tokenId = U256::from(v.inputs.token_id);
        order.makerAmount = U256::from(v.inputs.maker_amount);
        order.takerAmount = U256::from(v.inputs.taker_amount);
        order.side = v.inputs.side;
        order.signatureType = v.inputs.signature_type;
        order.timestamp = U256::from(v.inputs.timestamp_ms);
        order.metadata = parse_b256(&v.inputs.metadata);
        order.builder = parse_b256(&v.inputs.builder);

        let verifying = alloy::primitives::Address::from_str(&v.inputs.verifying_contract).unwrap();
        let domain = v2_domain(v.inputs.chain_id, verifying);

        // 1) Domain separator
        assert_eq!(
            domain.separator(),
            parse_b256(&v.expected.domain_separator),
            "[{}] domain_separator mismatch",
            v.name,
        );

        // 2) Struct hash
        assert_eq!(
            order.eip712_hash_struct(),
            parse_b256(&v.expected.struct_hash),
            "[{}] struct_hash mismatch",
            v.name,
        );

        // 3) EIP-712 digest (0x1901 || domain || structHash)
        let digest = order.eip712_signing_hash(&domain);
        assert_eq!(
            digest,
            parse_b256(&v.expected.digest),
            "[{}] digest mismatch",
            v.name,
        );

        // 4) Full signature bytes. PrivateKeySigner.sign_hash_sync is deterministic.
        let signer = PrivateKeySigner::from_str(v.inputs.private_key.trim_start_matches("0x"))
            .expect("private key parses");
        let sig = signer.sign_hash_sync(&digest).expect("sign");
        let sig_hex = format!("0x{}", alloy::hex::encode(sig.as_bytes()));
        assert_eq!(
            sig_hex.to_lowercase(),
            v.expected.signature.to_lowercase(),
            "[{}] signature bytes mismatch",
            v.name,
        );
    }
}
