use rustls::{
    crypto::{aws_lc_rs, CryptoProvider, KeyProvider, WebPkiSupportedAlgorithms},
    sign::{Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme, SupportedCipherSuite,
};
use std::sync::Arc;
use webpki::aws_lc_rs as webpki_algs;

#[link(name = "jade")]
extern "C" {
    fn jade_ed25519_amd64_sign(sk: *const [u8; 64], m: *const u8, mlen: u64, sig: *mut [u8; 64]);
    fn jade_ed25519_amd64_pubkey(sk: *const [u8; 32], pk: *mut [u8; 32]);
}

pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = aws_lc_rs::DEFAULT_CIPHER_SUITES;

pub static SIGNATURE_SCHEMES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[webpki_algs::ED25519],
    mapping: &[(SignatureScheme::ED25519, &[webpki_algs::ED25519])],
};

pub fn default_provider() -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.signature_verification_algorithms = SIGNATURE_SCHEMES;
    provider.key_provider = &LibjadeProvider {};

    provider
}

#[derive(Debug)]
struct LibjadeProvider {}

impl KeyProvider for LibjadeProvider {
    fn load_private_key(
        &self,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let secret_key = key_der.secret_der();
        let secret_key = &secret_key[16..48];

        let mut public_key = [0u8; 32];

        unsafe {
            jade_ed25519_amd64_pubkey(
                secret_key.as_ptr() as *const [u8; 32],
                public_key.as_mut_ptr() as *mut [u8; 32],
            );
        }

        let mut sk = [0u8; 64];
        sk[0..32].copy_from_slice(secret_key);
        sk[32..64].copy_from_slice(&public_key);

        Ok(Arc::new(Ed25519Key { sk }))
    }
}

#[derive(Debug)]
struct Ed25519Key {
    sk: [u8; 64],
}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(Ed25519Signer::new(&self.sk)))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

#[derive(Debug)]
struct Ed25519Signer {
    key: [u8; 64],
}

impl Ed25519Signer {
    fn new(key: &[u8; 64]) -> Self {
        Self { key: *key }
    }
}

impl Signer for Ed25519Signer {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = [0u8; 64];
        unsafe {
            jade_ed25519_amd64_sign(
                self.key.as_ptr() as *const [u8; 64],
                message.as_ptr(),
                message.len() as u64,
                signature.as_mut_ptr() as *mut [u8; 64],
            );
        }
        Ok(signature.to_vec())
    }
}
