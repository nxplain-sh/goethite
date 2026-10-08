//! The cluster's certificates: a private CA and one certificate per node.
//!
//! The CA exists only to vouch for the cluster's nodes, so it is created by
//! `goethite cluster init` and never trusted for anything else. Node
//! certificates carry the node's name (see [`NodeId::cert_name`]) and serve
//! both as server and client certificates: each node proves who it is to
//! the other in both directions. Keys are ECDSA P-256.
//!
//! The CA's name is derived from its public key, so issuing a node
//! certificate needs only the CA's key, and a certificate signed by one
//! cluster's CA never verifies against another's.

use std::fmt::Write as _;

use jiff::Zoned;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData as _, date_time_ymd,
};
use ring::digest::{SHA256, digest};

use crate::node::NodeId;

/// How long certificates are valid, in years.
pub const VALID_YEARS: i16 = 10;

/// A certificate and its private key, in PEM.
#[derive(Clone)]
pub struct Pem {
    /// The certificate.
    pub cert: String,
    /// The private key.
    pub key: String,
}

impl std::fmt::Debug for Pem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pem")
            .field("key", &"…")
            .finish_non_exhaustive()
    }
}

/// Why a certificate could not be made.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// The key or certificate could not be generated or read.
    #[error("certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// The system clock is outside what certificates can express.
    #[error("the system clock is out of range")]
    Clock,
}

/// A new cluster CA.
///
/// # Errors
///
/// [`CertError`] if the key or certificate cannot be generated.
pub fn new_ca() -> Result<Pem, CertError> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let params = ca_params(&key)?;
    let cert = params.self_signed(&key)?;
    Ok(Pem {
        cert: cert.pem(),
        key: key.serialize_pem(),
    })
}

/// A new certificate for `node`, signed with the CA's key `ca_key` (PEM).
///
/// # Errors
///
/// [`CertError`] if the CA key cannot be read or the certificate cannot be
/// generated.
pub fn issue(ca_key: &str, node: &NodeId) -> Result<Pem, CertError> {
    let ca_key = KeyPair::from_pem(ca_key)?;
    let issuer = Issuer::new(ca_params(&ca_key)?, ca_key);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec![node.cert_name()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, node.as_str());
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    set_validity(&mut params)?;
    let cert = params.signed_by(&key, &issuer)?;
    Ok(Pem {
        cert: cert.pem(),
        key: key.serialize_pem(),
    })
}

/// The CA's parameters, rebuilt from its key: the same key always gives
/// the same name.
fn ca_params(key: &KeyPair) -> Result<CertificateParams, CertError> {
    let fingerprint = digest(&SHA256, &key.subject_public_key_info());
    let mut short = String::new();
    for byte in fingerprint.as_ref().iter().take(4) {
        let _ = write!(short, "{byte:02x}");
    }
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("goethite cluster CA {short}"));
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params)?;
    Ok(params)
}

/// From yesterday (clocks differ a little) for [`VALID_YEARS`].
///
/// `date_time_ymd` panics on a date it cannot represent, so every part is
/// checked first: jiff dates are valid calendar dates, day 28 exists in
/// every month, and years stay within 1 to 9999.
fn set_validity(params: &mut CertificateParams) -> Result<(), CertError> {
    let today = Zoned::now().date();
    let yesterday = today.yesterday().map_err(|_| CertError::Clock)?;
    let end = today
        .year()
        .checked_add(VALID_YEARS)
        .filter(|year| *year <= 9999)
        .ok_or(CertError::Clock)?;
    if yesterday.year() < 1 {
        return Err(CertError::Clock);
    }
    let small = |n: i8| u8::try_from(n).map_err(|_| CertError::Clock);
    params.not_before = date_time_ymd(
        i32::from(yesterday.year()),
        small(yesterday.month())?,
        small(yesterday.day())?,
    );
    params.not_after = date_time_ymd(i32::from(end), small(today.month())?, 28);
    Ok(())
}
