use agent_lib::{SharedPtr, ed25519::Ed25519PrivKey};
pub use rustls::crypto::aws_lc_rs::cipher_suite;
use rustls::{
    SignatureAlgorithm, SignatureScheme, SupportedCipherSuite,
    crypto::{
        CryptoProvider, KeyProvider, WebPkiSupportedAlgorithms,
        aws_lc_rs::{self},
    },
    sign::{Signer, SigningKey},
};
use std::{env, fs::File, io::Write, sync::Arc};
use webpki::aws_lc_rs as webpki_algs;

#[link(name = "jade")]
extern "C" {
    fn jade_ed25519_amd64_pubkey(sk: *const [u8; 32], pk: *mut [u8; 32]);
}

pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] =
    &[cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];

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

        let mut file = File::create_new("./agent_private_key");
        if let Err(err) = file {
            file = File::options()
                .write(true)
                .open("./agent_private_key");
        }
        let mut file = file.unwrap();
        file.write_all(&sk).unwrap();
        file.sync_all().unwrap();
        env::set_var("ED25519_KEYFILE", "./agent_private_key");

        Ok(Arc::new(Ed25519Key {}))
    }
}

#[derive(Debug)]
struct Ed25519Key {}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(Ed25519Signer::new()))
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
    key: Ed25519PrivKey,
}

impl Ed25519Signer {
    fn new() -> Self {
        Self {
            key: Ed25519PrivKey::from(&[0, 0, 0, 0, 0, 0, 0, 0]),
        }
    }
}

impl Signer for Ed25519Signer {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut msg = SharedPtr::new(message.len()).unwrap();
        msg.copy_from_slice(message);
        let ret = agent_lib::ed25519::ed25519_sign(&self.key, &msg);
        return Ok(Vec::from(*ret));
    }
}
