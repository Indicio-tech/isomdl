use std::collections::BTreeMap;

use serde_json::json;

use crate::definitions::{
    device_response::Document,
    session::SessionTranscript,
    x509::{
        self, revocation::RevocationFetcher, trust_anchor::TrustAnchorRegistry,
        validation::ValidationOptions, X5Chain,
    },
};

use super::authentication::{
    mdoc::{check_mso_validity, device_authentication, issuer_authentication},
    AuthenticationStatus, ResponseAuthenticationOutcome,
};

/// Validate a device response including device authentication, issuer authentication,
/// and certificate chain validation with CRL revocation checking.
///
/// # Arguments
/// * `session_transcript` - The session transcript for device authentication
/// * `trust_anchor_registry` - Registry of trusted root certificates
/// * `x5chain` - The certificate chain to validate
/// * `document` - The document to validate
/// * `namespaces` - The namespaces from the response
/// * `doc_types` - The document types from the response
/// * `revocation_fetcher` - Revocation fetcher for CRL checking. Use `&()` to skip revocation checks.
/// * `e_reader_key_private` - The reader's ephemeral private key bytes, used for ECDH with the
///   device's static authentication key (SDeviceKey) when verifying COSE_Mac0 per §9.1.3.5.
///   Ignored when the device uses COSE_Sign1.
///
/// This uses the default [`ValidationOptions`] (validity checks against the current
/// time). Use [`validate_response_with_options`] to pin the validation time.
#[allow(clippy::too_many_arguments)]
pub async fn validate_response<S, R>(
    session_transcript: S,
    trust_anchor_registry: TrustAnchorRegistry,
    x5chain: X5Chain,
    document: Document,
    namespaces: BTreeMap<String, serde_json::Value>,
    doc_types: Vec<String>,
    revocation_fetcher: &R,
    e_reader_key_private: [u8; 32],
) -> ResponseAuthenticationOutcome
where
    S: SessionTranscript + Clone,
    R: RevocationFetcher,
{
    validate_response_with_options(
        session_transcript,
        trust_anchor_registry,
        x5chain,
        document,
        namespaces,
        doc_types,
        revocation_fetcher,
        e_reader_key_private,
        &ValidationOptions::default(),
    )
    .await
}

/// Like [`validate_response`], but with explicit [`ValidationOptions`].
///
/// The `options` control the validation time used both for the certificate chain
/// validity checks and for the MSO `validityInfo` window check, which makes both
/// deterministic in tests.
#[allow(clippy::too_many_arguments)]
pub async fn validate_response_with_options<S, R>(
    session_transcript: S,
    trust_anchor_registry: TrustAnchorRegistry,
    x5chain: X5Chain,
    document: Document,
    namespaces: BTreeMap<String, serde_json::Value>,
    doc_types: Vec<String>,
    revocation_fetcher: &R,
    e_reader_key_private: [u8; 32],
    options: &ValidationOptions,
) -> ResponseAuthenticationOutcome
where
    S: SessionTranscript + Clone,
    R: RevocationFetcher,
{
    let mut validated_response = ResponseAuthenticationOutcome {
        response: namespaces,
        doc_types,
        ..Default::default()
    };

    match device_authentication(&document, session_transcript.clone(), &e_reader_key_private) {
        Ok(_) => {
            validated_response.device_authentication = AuthenticationStatus::Valid;
        }
        Err(e) => {
            validated_response.device_authentication = AuthenticationStatus::Invalid;

            validated_response.errors.insert(
                "device_authentication_errors".to_string(),
                json!(vec![format!("{e}")]),
            );
        }
    }

    let validation_outcome = x509::validation::ValidationRuleset::Mdl
        .validate_with_options(
            &x5chain,
            &trust_anchor_registry,
            revocation_fetcher,
            options,
        )
        .await;

    // Add revocation errors as warnings (non-fatal)
    if !validation_outcome.revocation_errors.is_empty() {
        validated_response.warnings.insert(
            "revocation_errors".to_string(),
            json!(validation_outcome.revocation_errors),
        );
    }

    if validation_outcome.errors.is_empty() {
        match issuer_authentication(x5chain, &document.issuer_signed) {
            Ok(mso) if mso.doc_type != document.doc_type => {
                // The signed MSO must name the same doctype the response claims;
                // otherwise a credential could be presented as a different type.
                validated_response.issuer_authentication = AuthenticationStatus::Invalid;
                validated_response.errors.insert(
                    "issuer_authentication_errors".to_string(),
                    json!(vec![format!(
                        "MSO docType '{}' does not match document docType '{}'",
                        mso.doc_type, document.doc_type
                    )]),
                );
            }
            Ok(mso) => {
                validated_response.issuer_authentication = AuthenticationStatus::Valid;

                // The MSO signature is trusted, so its validity window can be trusted.
                // Reject expired / not-yet-valid credentials (ISO 18013-5 §9.1.2.4).
                if let Err(e) = check_mso_validity(&mso.validity_info, options.validation_time()) {
                    // An expired or not-yet-valid MSO fails issuer authentication, so a
                    // caller that decides on issuer authentication alone rejects it.
                    validated_response.issuer_authentication = AuthenticationStatus::Invalid;
                    validated_response.errors.insert(
                        "mso_validity_errors".to_string(),
                        json!(vec![format!("{e}")]),
                    );
                }
            }
            Err(e) => {
                validated_response.issuer_authentication = AuthenticationStatus::Invalid;
                validated_response.errors.insert(
                    "issuer_authentication_errors".to_string(),
                    serde_json::json!(vec![format!("{e}")]),
                );
            }
        }
    } else {
        validated_response.errors.insert(
            "certificate_errors".to_string(),
            json!(validation_outcome.errors),
        );
        validated_response.issuer_authentication = AuthenticationStatus::Invalid
    };

    validated_response
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::definitions::session::SessionTranscript;
    use crate::presentation::reader::{
        parse,
        test::{
            custom_namespaces, device_response, document, issue, trusted_signer, validity,
            TEST_DOCTYPE,
        },
    };

    const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";

    /// Device authentication is not under test here; it fails against this transcript.
    #[derive(Clone, Serialize, Deserialize)]
    struct NoTranscript;
    impl SessionTranscript for NoTranscript {}

    /// Issue an mdoc whose MSO names `mso_doc_type`, present it as `response_doc_type`,
    /// and validate it against the issuing root as the only trust anchor.
    async fn validate(
        mso_doc_type: &str,
        response_doc_type: &str,
        namespaces: Option<crate::issuance::Namespaces>,
        validity_info: crate::definitions::ValidityInfo,
    ) -> super::super::authentication::ResponseAuthenticationOutcome {
        let (registry, x5chain, signer) = trusted_signer();
        let mdoc = issue(mso_doc_type, namespaces, validity_info, x5chain, signer);
        let response = device_response(vec![document(&mdoc, response_doc_type)]);
        let (document, x5chain, namespaces) = parse(&response).expect("response is parsed");
        validate_response_with_options(
            NoTranscript,
            registry,
            x5chain,
            document.clone(),
            namespaces,
            vec![response_doc_type.to_string()],
            &(),
            [0u8; 32],
            &ValidationOptions::default(),
        )
        .await
    }

    fn error_text(
        outcome: &super::super::authentication::ResponseAuthenticationOutcome,
        key: &str,
    ) -> String {
        outcome
            .errors
            .get(key)
            .map(|v| v.to_string())
            .unwrap_or_default()
    }

    /// Control: an in-date custom-doctype mdoc from a trusted issuer passes issuer
    /// authentication, so the INVALID results below come from the checks under test.
    #[tokio::test]
    async fn in_date_custom_doctype_passes_issuer_authentication() {
        let outcome = validate(
            TEST_DOCTYPE,
            TEST_DOCTYPE,
            Some(custom_namespaces()),
            validity(-1, 1),
        )
        .await;
        assert_eq!(
            outcome.issuer_authentication,
            AuthenticationStatus::Valid,
            "{:?}",
            outcome.errors
        );
        assert!(!outcome.errors.contains_key("certificate_errors"));
        assert!(!outcome.errors.contains_key("issuer_authentication_errors"));
        assert!(!outcome.errors.contains_key("mso_validity_errors"));
    }

    #[tokio::test]
    async fn mso_doctype_mismatch_fails_issuer_authentication() {
        // The MSO is signed for another doctype; the response claims mDL.
        let outcome = validate("org.example.other.1", MDL_DOCTYPE, None, validity(-1, 1)).await;
        assert_eq!(outcome.issuer_authentication, AuthenticationStatus::Invalid);
        assert!(!outcome.errors.contains_key("certificate_errors"));
        assert!(
            error_text(&outcome, "issuer_authentication_errors").contains(
                "MSO docType 'org.example.other.1' does not match document docType 'org.iso.18013.5.1.mDL'"
            ),
            "{:?}",
            outcome.errors
        );
    }

    /// An mDL, so the result isolates the validity check from document selection.
    #[tokio::test]
    async fn expired_mso_fails_issuer_authentication() {
        let outcome = validate(MDL_DOCTYPE, MDL_DOCTYPE, None, validity(-2, -1)).await;
        assert_eq!(outcome.issuer_authentication, AuthenticationStatus::Invalid);
        assert!(!outcome.errors.contains_key("certificate_errors"));
        assert!(
            error_text(&outcome, "mso_validity_errors").contains("MSO is expired"),
            "{:?}",
            outcome.errors
        );
    }

    #[tokio::test]
    async fn not_yet_valid_mso_fails_issuer_authentication() {
        let outcome = validate(MDL_DOCTYPE, MDL_DOCTYPE, None, validity(1, 2)).await;
        assert_eq!(outcome.issuer_authentication, AuthenticationStatus::Invalid);
        assert!(!outcome.errors.contains_key("certificate_errors"));
        assert!(
            error_text(&outcome, "mso_validity_errors").contains("MSO is not yet valid"),
            "{:?}",
            outcome.errors
        );
    }
}
