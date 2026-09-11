use rustls::{
    DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    server::ParsedCertificate,
};

#[derive(Debug)]
pub(crate) struct CertificateVerifier {
    trust: Trust,
    algorithms: WebPkiSupportedAlgorithms,
}

#[derive(Debug)]
enum Trust {
    PinnedLeaf { roots: RootCertStore, spki: Vec<u8> },
    Ca(std::sync::Arc<WebPkiServerVerifier>),
}

impl CertificateVerifier {
    pub(crate) fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let certs =
            CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(!certs.is_empty(), "TLS CA must contain a PEM certificate");
        let mut roots = RootCertStore::empty();
        for cert in &certs {
            roots.add(cert.clone())?;
        }
        let provider = rustls::crypto::ring::default_provider();
        let mut pin = None;
        if certs.len() == 1 {
            let (remaining, cert) = x509_parser::parse_x509_certificate(&certs[0])
                .map_err(|_| anyhow::anyhow!("invalid TLS certificate"))?;
            anyhow::ensure!(remaining.is_empty(), "trailing data in TLS certificate");
            let is_ca = cert.basic_constraints()?.is_some_and(|bc| bc.value.ca);
            if !is_ca && cert.subject() == cert.issuer() && cert.verify_signature(None).is_ok() {
                pin = Some(cert.public_key().raw.to_vec());
            }
        }
        // Only a single self-signed leaf enables address-independent key pinning.
        let trust = match pin {
            Some(spki) => Trust::PinnedLeaf { roots, spki },
            None => Trust::Ca(
                WebPkiServerVerifier::builder_with_provider(
                    std::sync::Arc::new(roots),
                    std::sync::Arc::new(provider.clone()),
                )
                .build()?,
            ),
        };
        Ok(Self {
            trust,
            algorithms: provider.signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (roots, spki) = match &self.trust {
            Trust::Ca(verifier) => {
                return verifier.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                );
            }
            Trust::PinnedLeaf { roots, spki } => (roots, spki),
        };
        let (remaining, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if !remaining.is_empty() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        if cert.public_key().raw != spki {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            roots,
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

    fn ca() -> (
        rcgen::Certificate,
        rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    ) {
        let mut params = rcgen::CertificateParams::new(vec!["Test CA".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let issuer = rcgen::CertifiedIssuer::self_signed(params, key).unwrap();
        (cert, issuer)
    }

    #[test]
    fn ca_trust_checks_hostname_and_issuer() {
        let (root, issuer) = ca();
        let verifier = CertificateVerifier::from_pem(&root.pem()).unwrap();
        assert!(matches!(verifier.trust, Trust::Ca(_)));
        let name = ServerName::try_from("ca.example").unwrap();
        for (hostname, accepted) in [("ca.example", true), ("attacker.example", false)] {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec![hostname.into()])
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap();
            let result = verifier.verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now());
            assert_eq!(result.is_ok(), accepted, "{result:?}");
        }
        let (_, other_issuer) = ca();
        let cert = rcgen::CertificateParams::new(vec!["ca.example".into()])
            .unwrap()
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &other_issuer)
            .unwrap();
        assert!(
            verifier
                .verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now())
                .is_err()
        );

        let bundle =
            CertificateVerifier::from_pem(&format!("{}{}", root.pem(), root.pem())).unwrap();
        assert!(matches!(bundle.trust, Trust::Ca(_)));
        let cert = rcgen::CertificateParams::new(vec!["attacker.example".into()])
            .unwrap()
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        assert!(
            bundle
                .verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }

    #[test]
    fn pin_matches_spki_across_reissued_certificates() {
        let key = rcgen::KeyPair::generate().unwrap();
        let original = rcgen::CertificateParams::new(vec!["old.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let reissued = rcgen::CertificateParams::new(vec!["new.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert_ne!(original.der(), reissued.der());
        let verifier = CertificateVerifier::from_pem(&original.pem()).unwrap();
        assert!(matches!(verifier.trust, Trust::PinnedLeaf { .. }));
        let name = ServerName::try_from("forwarded.example").unwrap();
        assert!(
            verifier
                .verify_server_cert(reissued.der(), &[], &name, &[], UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn pin_rejects_a_different_key_signed_by_the_pinned_key() {
        let params = rcgen::CertificateParams::new(vec!["original.example".into()]).unwrap();
        let issuer =
            rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap())
                .unwrap();
        let verifier = CertificateVerifier::from_pem(&issuer.pem()).unwrap();
        let delegated = rcgen::CertificateParams::new(vec!["forwarded.example".into()])
            .unwrap()
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        let name = ServerName::try_from("forwarded.example").unwrap();
        assert!(matches!(
            verifier.verify_server_cert(delegated.der(), &[], &name, &[], UnixTime::now()),
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            ))
        ));
    }

    #[test]
    fn ca_trust_rejects_expired_certificates() {
        let (root, issuer) = ca();
        let verifier = CertificateVerifier::from_pem(&root.pem()).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["ca.example".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let cert = params
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        let name = ServerName::try_from("ca.example").unwrap();
        assert!(matches!(
            verifier.verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now()),
            Err(Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ));
    }

    #[test]
    fn rejects_empty_or_invalid_trust() {
        for pem in [
            "",
            "not a certificate",
            "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----",
        ] {
            assert!(CertificateVerifier::from_pem(pem).is_err());
        }
    }

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
