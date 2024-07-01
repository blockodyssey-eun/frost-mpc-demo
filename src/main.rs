/**
 *
 * Error: (code: -32602, message: transaction could not be decoded: could not decode RLP components: extra data at end, data: None)
 *
 *
 * Signature값 변환 필요 (슈노르 R,z -> r,s)
 *
 */
use dotenv::dotenv;
use ethers::{
    core::types::{Signature, TransactionRequest},
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    utils::{parse_ether, public_key_to_address},
};
use eyre::Result;
use frost_secp256k1::{self as frost};
use rand::thread_rng;
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let infura_key = std::env::var("INFURA_KEY").expect("INFURA_KEY must be set.");
    let private_key = std::env::var("ETH_PRIVATE_KEY").expect("ETH_PRIVATE_KEY must be set.");

    let infura_url = format!("https://sepolia.infura.io/v3/{}", infura_key);
    let provider: Provider<Http> =
        Provider::<Http>::try_from(infura_url).expect("Failed to create provider");

    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;

    // 딜러를 통한 서명자 키 생성
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let pubkey = pubkey_package.verifying_key();
    let pubkey_bytes = pubkey.serialize()?;
    let k256_pubkey =
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("valid key bytes");
    let address = public_key_to_address(&k256_pubkey);
    println!("Ethereum address: {:?}", address);

    let _ = inject_test_ether_to_new_address(&provider, address, private_key).await;
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];

        let (nonces, commitments) = frost::round1::commit(
            key_packages[&participant_identifier].signing_share(),
            &mut rng,
        );

        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    let mut signature_shares = BTreeMap::new();

    let to_address: H160 = "0x04a6fF54A4D3A6E960104ac493E1C9Df6FAd200B"
        .parse()
        .expect("valid address");
    let tx = TransactionRequest::new()
        .to(to_address)
        .value(U256::from(parse_ether(0.0001)?));
    let tx_rlp_unsigned = tx.rlp_unsigned();
    let tx_rlp_as_ref = tx_rlp_unsigned.as_ref();

    let signing_package = frost::SigningPackage::new(commitments_map, tx_rlp_as_ref);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];
        let nonces = &nonces_map[participant_identifier];
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    let serialized_signature = group_signature.serialize()?;

    // let signed_tx = combine_rlp_and_signature(tx_rlp_as_ref, &serialized_signature, 11155111u64);

    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(tx_rlp_as_ref, &group_signature)
        .is_ok();
    // ANCHOR_END: verify

    println!("{:?}", is_signature_valid);
    let tx_bytes = Bytes::from(serialized_signature);
    let _ = send_to_test_ether(&provider, tx_bytes).await?;
    Ok(())
}

// 신규 주소로 테스트 이더 주입
async fn inject_test_ether_to_new_address(
    provider: &Provider<Http>,
    to_address: Address,
    private_key: String,
) -> Result<()> {
    let chain_id = provider.get_chainid().await?;

    let wallet: LocalWallet = private_key
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id.as_u64());
    let client = SignerMiddleware::new(provider.clone(), wallet);

    let tx = TransactionRequest::new()
        .to(to_address)
        .value(U256::from(parse_ether(0.0001)?));
    let pending_tx = client.send_transaction(tx, None).await?;
    let receipt = pending_tx
        .await?
        .ok_or_else(|| eyre::format_err!("tx dropped from mempool"))?;
    let tx: Option<Transaction> = client.get_transaction(receipt.transaction_hash).await?;
    println!(
        "inject_test_ether_to_new_address:Sent tx: {}\n",
        serde_json::to_string(&tx)?
    );
    println!(
        "inject_test_ether_to_new_address:Tx receipt: {}",
        serde_json::to_string(&receipt)?
    );

    Ok(())
}

// 테스트 이더 전송
async fn send_to_test_ether(provider: &Provider<Http>, tx_bytes: Bytes) -> Result<()> {
    let pending_tx = provider.send_raw_transaction(tx_bytes).await?;
    let receipt = pending_tx
        .await?
        .ok_or_else(|| eyre::format_err!("tx dropped from mempool"))?;
    let tx: Option<Transaction> = provider.get_transaction(receipt.transaction_hash).await?;
    println!(
        "send_to_test_ether:Sent tx: {}\n",
        serde_json::to_string(&tx)?
    );
    println!(
        "send_to_test_ether:Tx receipt: {}",
        serde_json::to_string(&receipt)?
    );

    Ok(())
}
