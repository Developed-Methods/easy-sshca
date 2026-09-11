use rustls::{
    DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    server::ParsedCertificate,
};

#[derive(Debug)]
pub(crate) struct CertificateVerifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
}

impl CertificateVerifier {
    pub(crate) fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert?)?;
        }
        anyhow::ensure!(!roots.is_empty(), "TLS CA must contain a PEM certificate");
        Ok(Self {
            roots,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // The configured CA authenticates the server independently of its address.
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_trust_and_validity_without_hostname_matching() {
        let tls = rcgen::generate_simple_self_signed(vec!["original.example.com".into()]).unwrap();
        let verifier = CertificateVerifier::from_pem(&tls.cert.pem()).unwrap();
        let name = ServerName::try_from("updated.example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(tls.cert.der(), &[], &name, &[], UnixTime::now())
                .is_ok()
        );

        let other = rcgen::generate_simple_self_signed(vec!["updated.example.com".into()]).unwrap();
        assert!(
            verifier
                .verify_server_cert(other.cert.der(), &[], &name, &[], UnixTime::now())
                .is_err()
        );
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(vec![0, 1, 2]),
                    &[],
                    &name,
                    &[],
                    UnixTime::now()
                )
                .is_err()
        );

        let mut params =
            rcgen::CertificateParams::new(vec!["original.example.com".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let expired = params.self_signed(&key).unwrap();
        let verifier = CertificateVerifier::from_pem(&expired.pem()).unwrap();
        assert!(matches!(
            verifier.verify_server_cert(expired.der(), &[], &name, &[], UnixTime::now()),
            Err(Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ));
    }
}
