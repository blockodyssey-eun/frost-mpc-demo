use frost_secp256k1::keys::{KeyGenerator, SecretShare};
use frost_secp256k1::sign::Signer;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

fn main() {
    // 키 생성기 초기화
    let mut rng = OsRng;
    let keygen = KeyGenerator::new(3, 2); // 3개 중 2개의 서명자가 필요함

    // 키 생성
    let (shares, pubkeys) = keygen.generate_keys(&mut rng).expect("키 생성 실패");

    // 각 서명자 초기화
    let signer1 = Signer::new(1, shares[0].clone(), pubkeys.clone());
    let signer2 = Signer::new(2, shares[1].clone(), pubkeys.clone());

    // 서명할 메시지
    let message = b"A message.";
    let message_hash = Sha3_256::digest(message);

    // 서명 과정
    let (nonce1, commitment1) = signer1.generate_nonce_commitment(&mut rng).expect("Nonce 생성 실패");
    let (nonce2, commitment2) = signer2.generate_nonce_commitment(&mut rng).expect("Nonce 생성 실패");

    let mut commitments = vec![commitment1, commitment2];
    commitments.sort_by_key(|c| c.index);

    let partial_sig1 = signer1.sign(&mut rng, &message_hash, &commitments).expect("서명 실패");
    let partial_sig2 = signer2.sign(&mut rng, &message_hash, &commitments).expect("서명 실패");

    let mut partial_sigs = vec![partial_sig1, partial_sig2];
    partial_sigs.sort_by_key(|s| s.index);

    let signature = signer1.combine_signatures(&partial_sigs).expect("서명 결합 실패");

    // 서명 결과 출력
    println!("Signature: {:?}", signature);
}