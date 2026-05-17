//! ERC-7739 wrapped signature for V2 orders signed by a Polymarket Deposit
//! Wallet (signature type `POLY_1271` = 3).
//!
//! Reference: py-clob-client-v2 `order_utils/exchange_order_builder_v2.py`
//!   `_build_poly_1271_order_signature`.
//!
//! Layout of the wrapped signature (`0x` + hex of):
//! ```text
//!   inner_ecdsa_sig  (65 bytes)
//!   app_domain_separator (32 bytes) — CTF Exchange V2's EIP-712 domain
//!   contents_hash    (32 bytes)     — keccak of the V2 Order struct
//!   ORDER_TYPE_STRING (N bytes)     — readable type string for ERC-7739
//!   uint16 be(N)     (2 bytes)      — length of the type string
//! ```
//!
//! The deposit wallet's on-chain `isValidSignature(orderHash, wrapped)` callback
//! parses this suffix to verify the inner ECDSA against the embedded owner EOA.

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::signers::Signer;
use alloy::sol_types::SolValue;

use super::types::OrderV2;

/// The exact V2 Order EIP-712 type string. Field order must match
/// `OrderV2` in `types/mod.rs` byte-for-byte — changing either drifts the
/// signing hash and silently invalidates orders.
pub const ORDER_TYPE_STRING: &str = "Order(uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)";

/// Solady ERC-7739 envelope. The `TypedDataSign(...)` outer type whose
/// `contents` field carries the inner `Order` hash, plus the smart-account
/// (deposit wallet) domain so the signature is bound to one wallet.
const SOLADY_TYPE_STRING_PREFIX: &str = "TypedDataSign(Order contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";

const DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// CTF Exchange V2 (`verifyingContract` for the outer domain separator).
/// Must match the values the order is being submitted against.
pub const CTF_EXCHANGE_V2_DOMAIN_NAME: &str = "Polymarket CTF Exchange";
pub const CTF_EXCHANGE_V2_DOMAIN_VERSION: &str = "2";

/// Deposit wallet domain (the smart-account whose `isValidSignature` will
/// receive the wrapped sig). Constant across all deposit wallets — only the
/// `verifyingContract` differs per wallet.
const DEPOSIT_WALLET_NAME: &str = "DepositWallet";
const DEPOSIT_WALLET_VERSION: &str = "1";

fn order_type_hash() -> B256 {
    keccak256(ORDER_TYPE_STRING.as_bytes())
}

fn solady_type_hash() -> B256 {
    // SOLADY_TYPE_STRING == prefix + ORDER_TYPE_STRING (the inner type follows
    // the outer per EIP-712 nested struct ordering rules).
    let mut buf = Vec::with_capacity(SOLADY_TYPE_STRING_PREFIX.len() + ORDER_TYPE_STRING.len());
    buf.extend_from_slice(SOLADY_TYPE_STRING_PREFIX.as_bytes());
    buf.extend_from_slice(ORDER_TYPE_STRING.as_bytes());
    keccak256(&buf)
}

fn domain_type_hash() -> B256 {
    keccak256(DOMAIN_TYPE_STRING.as_bytes())
}

/// EIP-712 domain separator for the CTF Exchange V2 (the "app" domain — the
/// outer 0x1901 envelope wraps THIS separator, then the TypedDataSign hash).
pub fn ctf_exchange_v2_domain_separator(chain_id: u64, exchange: Address) -> B256 {
    let encoded = (
        domain_type_hash(),
        keccak256(CTF_EXCHANGE_V2_DOMAIN_NAME.as_bytes()),
        keccak256(CTF_EXCHANGE_V2_DOMAIN_VERSION.as_bytes()),
        U256::from(chain_id),
        exchange,
    )
        .abi_encode();
    keccak256(&encoded)
}

/// EIP-712 struct hash of the V2 `Order` (the inner contents). Mirrors
/// `eip712_hash_struct` but spelled out for clarity / byte-parity test
/// against py-clob-client-v2's `_build_poly_1271_order_signature`.
pub fn order_contents_hash(order: &OrderV2) -> B256 {
    let encoded = (
        order_type_hash(),
        order.salt,
        order.maker,
        order.signer,
        order.tokenId,
        order.makerAmount,
        order.takerAmount,
        U256::from(order.side),
        U256::from(order.signatureType),
        order.timestamp,
        order.metadata,
        order.builder,
    )
        .abi_encode();
    keccak256(&encoded)
}

/// Inner `TypedDataSign(...)` struct hash, binding the order contents to the
/// deposit wallet's domain.
fn typed_data_sign_struct_hash(contents_hash: B256, chain_id: u64, wallet: Address) -> B256 {
    let encoded = (
        solady_type_hash(),
        contents_hash,
        keccak256(DEPOSIT_WALLET_NAME.as_bytes()),
        keccak256(DEPOSIT_WALLET_VERSION.as_bytes()),
        U256::from(chain_id),
        wallet,
        B256::ZERO, // salt — always zero for deposit wallet domain
    )
        .abi_encode();
    keccak256(&encoded)
}

/// Computes the digest the EOA owner signs for a POLY_1271 order. Exposed
/// for testing; production callers should use [`wrap_signature`] which signs
/// it and assembles the wrapped envelope in one shot.
pub fn poly1271_signing_digest(
    order: &OrderV2,
    chain_id: u64,
    exchange: Address,
) -> (B256, B256, B256) {
    let contents_hash = order_contents_hash(order);
    let app_ds = ctf_exchange_v2_domain_separator(chain_id, exchange);
    let tds_hash = typed_data_sign_struct_hash(contents_hash, chain_id, order.signer);

    // EIP-712 envelope: 0x1901 || app_ds || tds_hash
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(app_ds.as_slice());
    buf.extend_from_slice(tds_hash.as_slice());
    let digest = keccak256(&buf);

    (digest, app_ds, contents_hash)
}

/// Signs and wraps a V2 order for POLY_1271. Returns the full wrapped
/// signature bytes that go on the wire as `order.signature`.
///
/// `exchange` is the CTF Exchange V2 contract address for the order's
/// chain + market kind (standard or neg-risk). The `order.signer` field is
/// the deposit wallet address (Phase 2 wiring guarantees that).
pub async fn wrap_signature<S: Signer>(
    signer: &S,
    order: &OrderV2,
    chain_id: u64,
    exchange: Address,
) -> Result<Bytes, alloy::signers::Error> {
    let (digest, app_ds, contents_hash) = poly1271_signing_digest(order, chain_id, exchange);
    let inner = signer.sign_hash(&digest).await?;
    let inner_bytes = inner.as_bytes(); // 65 bytes

    let order_type = ORDER_TYPE_STRING.as_bytes();
    let mut wrapped = Vec::with_capacity(65 + 32 + 32 + order_type.len() + 2);
    wrapped.extend_from_slice(&inner_bytes);
    wrapped.extend_from_slice(app_ds.as_slice());
    wrapped.extend_from_slice(contents_hash.as_slice());
    wrapped.extend_from_slice(order_type);
    wrapped.extend_from_slice(&(order_type.len() as u16).to_be_bytes());
    Ok(Bytes::from(wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, U256};
    use alloy::signers::local::PrivateKeySigner;

    /// Byte-for-byte parity with py-clob-client-v2's
    /// `test_build_order_signature_poly_1271_matches_expected_signature`.
    /// Fixture from `tests/order_utils/test_exchange_order_builder_v2.py`.
    #[tokio::test]
    async fn matches_py_clob_client_v2_fixture() {
        // From py-clob-client-v2's test setUp + _poly_1271_order_data:
        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let chain_id: u64 = 80002; // AMOY
        // V2 exchange address (same on Amoy + Polygon per clob-client-v2/src/config.ts)
        let exchange = address!("E111180000d2663C0091e4f400237545B87B996B");
        let deposit_wallet = address!("1111111111111111111111111111111111111111");

        let order = OrderV2 {
            salt: U256::from(479_249_096_354u64),
            maker: deposit_wallet,
            signer: deposit_wallet,
            tokenId: U256::from(1234u64),
            makerAmount: U256::from(100_000_000u64),
            takerAmount: U256::from(50_000_000u64),
            side: 0,           // BUY
            signatureType: 3,  // POLY_1271
            timestamp: U256::from(1_710_000_000_000u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        };

        let signer: PrivateKeySigner = pk.parse().unwrap();
        let wrapped = wrap_signature(&signer, &order, chain_id, exchange).await.unwrap();
        let wrapped_hex = format!("0x{}", alloy::hex::encode(&wrapped));

        // Byte-for-byte parity with py-clob-client-v2's
        // EXPECTED_POLY_1271_SIGNATURE (tests/order_utils/test_exchange_order_builder_v2.py).
        // Concatenated from the multi-line Python literal.
        let expected = concat!(
            "0xa3a093c83b6c20c83355c16ce94c92e6e9fcbdeb840618cc74f6c57a42ad145b",
            "2b98db73d2c73cbf1f2b6af288566ae81960ddbc3a13921027358a8bff3be6ff1c",
            "a440cbd865bc0c6243d7a8df9a8bf48a8827b0a4abbb61c30e96d305423af148",
            "d23d42d3ad94e65d78258cecaf8dcbaddac0f73dc085040f2c12bb595dd83804",
            "4f726465722875696e743235362073616c742c61646472657373206d616b65722c",
            "61646472657373207369676e65722c75696e7432353620746f6b656e49642c75",
            "696e74323536206d616b6572416d6f756e742c75696e743235362074616b6572",
            "416d6f756e742c75696e743820736964652c75696e7438207369676e61747572",
            "65547970652c75696e743235362074696d657374616d702c6279746573333220",
            "6d657461646174612c62797465733332206275696c6465722900ba",
        );
        assert_eq!(wrapped_hex, expected, "wrapped Poly1271 sig diverges from py-clob-client-v2");
    }

    /// Verify the inner type-string hex matches what py fixture has (the
    /// part between contents_hash and the trailing length).
    #[tokio::test]
    async fn order_type_string_serialization() {
        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = pk.parse().unwrap();
        let order = OrderV2 {
            salt: U256::from(479_249_096_354u64),
            maker: address!("1111111111111111111111111111111111111111"),
            signer: address!("1111111111111111111111111111111111111111"),
            tokenId: U256::from(1234u64),
            makerAmount: U256::from(100_000_000u64),
            takerAmount: U256::from(50_000_000u64),
            side: 0,
            signatureType: 3,
            timestamp: U256::from(1_710_000_000_000u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        };
        let wrapped = wrap_signature(
            &signer,
            &order,
            80002,
            address!("E111180000d2663C0091e4f400237545B87B996B"),
        )
        .await
        .unwrap();

        // Strip the 65-byte sig + 32-byte appDS + 32-byte contents_hash.
        let bytes = wrapped.as_ref();
        assert!(bytes.len() > 65 + 32 + 32 + 2);
        let suffix_start = 65 + 32 + 32;
        let type_str_len = (bytes.len() - suffix_start - 2) as usize;
        let type_str = std::str::from_utf8(&bytes[suffix_start..suffix_start + type_str_len])
            .expect("type string is utf-8");
        assert_eq!(type_str, ORDER_TYPE_STRING);
    }
}
