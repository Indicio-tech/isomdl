//! This module is responsible for the reader's interaction with the device.
//!
//! It handles this through [SessionManager] state
//! which is responsible for handling the session with the device.
//!
//! From the reader's perspective, the flow is as follows:
//!
//! ```ignore
#![doc = include_str!("../../docs/on_simulated_reader.txt")]
//! ```
//!
//! ### Example
//!
//! You can view examples in `tests` directory in `simulated_device_and_reader.rs`, for a basic example and
//! `simulated_device_and_reader_state.rs` which uses `State` pattern, `Arc` and `Mutex`.
use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use coset::Label;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{
    authentication::ResponseAuthenticationOutcome, reader_utils::validate_response_with_options,
};

use crate::definitions::x509::revocation::RevocationFetcher;
pub use crate::definitions::x509::validation::ValidationOptions;

use crate::{
    cbor::{self, CborError},
    definitions::{
        device_engagement::{
            nfc::{LeRole, ReaderNegotiatedCarrierInfo},
            BleMode, CentralClientMode, PeripheralServerMode,
        },
        device_key::cose_key::Error as CoseError,
        device_request::{
            self, DeviceRequest, DeviceRequestInfoBytes, DocRequest, ItemsRequest,
            ItemsRequestBytesAll,
        },
        device_response::Document,
        helpers::{non_empty_vec, NonEmptyVec, Tag24},
        session::{
            self, create_p256_ephemeral_keys, derive_session_key, get_shared_secret,
            SessionEstablishment,
        },
        x509::{trust_anchor::TrustAnchorRegistry, x5chain::X5CHAIN_COSE_HEADER_LABEL, X5Chain},
        DeviceEngagement, DeviceResponse, SessionData, SessionTranscript180135,
    },
    presentation::reader::{device_request::ItemsRequestBytes, Error as ReaderError},
};

/// The main state of the reader.
///
/// The reader's [SessionManager] state machine is responsible
/// for handling the session with the device.
///
/// The transition to this state is made by [SessionManager::establish_session].
#[derive(Serialize, Deserialize, Clone)]
pub struct SessionManager {
    session_transcript: SessionTranscript180135,
    sk_device: [u8; 32],
    device_message_counter: u32,
    sk_reader: [u8; 32],
    reader_message_counter: u32,
    e_reader_key_private: [u8; 32],
    trust_anchor_registry: TrustAnchorRegistry,
    holder_le_role: Option<LeRole>,
    holder_central_client_modes: Vec<CentralClientMode>,
    holder_peripheral_server_modes: Vec<PeripheralServerMode>,
}

#[derive(Serialize, Deserialize)]
pub struct ReaderAuthentication(
    pub String,
    pub SessionTranscript180135,
    pub ItemsRequestBytes,
);

#[derive(Serialize, Deserialize)]
pub struct ReaderAuthenticationAll<S>(
    pub String,
    /// Meant to be the SessionTranscript
    pub S,
    pub ItemsRequestBytesAll,
    pub Option<DeviceRequestInfoBytes>,
);

/// Various errors that can occur during the interaction with the device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Received IssuerAuth had a detached payload.")]
    DetachedIssuerAuth,
    #[error("Could not parse MSO.")]
    MSOParsing,
    /// The QR code had the wrong prefix or the contained data could not be decoded.
    #[error("the qr code had the wrong prefix or the contained data could not be decoded: {0}")]
    InvalidQrCode(anyhow::Error),
    /// Device did not transmit any data.
    #[error("Device did not transmit any data.")]
    DeviceTransmissionError,
    /// Device did not transmit an mDL.
    #[error("Device did not transmit an mDL.")]
    DocumentTypeError,
    /// The device did not transmit any mDL data.
    #[error("the device did not transmit any mDL data.")]
    NoMdlDataTransmission,
    /// Device did not transmit any data in the `org.iso.18013.5.1` namespace.
    #[error("device did not transmit any data in the org.iso.18013.5.1 namespace.")]
    IncorrectNamespace,
    /// The Device responded with an error.
    #[error("device responded with an error.")]
    HolderError,
    /// Could not decrypt the response.
    #[error("could not decrypt the response.")]
    DecryptionError,
    /// Unexpected CBOR type for offered value.
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    /// Not a valid JSON input.
    #[error("not a valid JSON input.")]
    JsonError,
    /// Unexpected data type for data element.
    #[error("Unexpected data type for data element: {0}.")]
    ParsingError(String),
    /// Request for data is invalid.
    #[error("Request for data is invalid.")]
    InvalidRequest,
    #[error("Failed mdoc authentication: {0}")]
    MdocAuth(String),
    #[error("Currently unsupported format")]
    Unsupported,
    #[error("No x5chain found for issuer authentication")]
    X5ChainMissing,
    #[error("Failed to parse x5chain: {0}")]
    X5ChainParsing(anyhow::Error),
    #[error("issuer authentication failed: {0}")]
    IssuerAuthentication(String),
    #[error("Unable to parse issuer public key")]
    IssuerPublicKey(anyhow::Error),
    /// A disclosed data element does not match the digest committed to in the MSO.
    #[error("issuer-signed value digest verification failed: {0}")]
    IssuerDigestMismatch(String),
    /// The MSO's `validUntil` is in the past relative to the validation time.
    #[error("MSO is expired")]
    MsoExpired,
    /// The MSO's `validFrom` is in the future relative to the validation time.
    #[error("MSO is not yet valid")]
    MsoNotYetValid,
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Error::CborDecodingError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::JsonError
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(value: x509_cert::der::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(value: p256::ecdsa::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(value: x509_cert::spki::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<CoseError> for Error {
    fn from(value: CoseError) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<non_empty_vec::Error> for Error {
    fn from(value: non_empty_vec::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

impl From<asn1_rs::Error> for Error {
    fn from(value: asn1_rs::Error) -> Self {
        Error::MdocAuth(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Handover {
    QR(String),
    NFC(Box<ReaderNegotiatedCarrierInfo>),
}

impl SessionManager {
    /// Establish a session with the device.
    ///
    /// Internally it generates the ephemeral keys,
    /// derives the shared secret, and derives the session keys
    /// (using **Diffie–Hellman key exchange**).
    pub fn establish_session(
        handover: Handover,
        namespaces: device_request::Namespaces,
        trust_anchor_registry: TrustAnchorRegistry,
    ) -> Result<(Self, Vec<u8>, [u8; 16])> {
        let (
            device_engagement_bytes,
            session_transcript_handover,
            holder_le_role,
            holder_central_client_modes,
            holder_peripheral_server_modes,
        ) = match handover {
            Handover::NFC(carrier_info) => {
                let device_engagement_bytes = carrier_info.device_engagement;
                let le_role = Some(carrier_info.holder_le_role);
                let uuid = carrier_info.uuid;
                let central_client_modes: Vec<_> = device_engagement_bytes
                    .as_ref()
                    .ble_central_client_options()
                    .cloned()
                    .collect();
                let peripheral_server_modes: Vec<_> = device_engagement_bytes
                    .as_ref()
                    .ble_peripheral_server_options()
                    .cloned()
                    .collect();
                let central_client_modes = if central_client_modes.is_empty() {
                    vec![CentralClientMode { uuid }]
                } else {
                    central_client_modes
                };
                let peripheral_server_modes = if peripheral_server_modes.is_empty() {
                    vec![PeripheralServerMode {
                        uuid,
                        ble_device_address: carrier_info.ble_device_address,
                    }]
                } else {
                    peripheral_server_modes
                };
                (
                    device_engagement_bytes,
                    crate::definitions::session::Handover::NFC(
                        carrier_info.hs_message,
                        carrier_info.hr_message,
                    ),
                    le_role,
                    central_client_modes,
                    peripheral_server_modes,
                )
            }
            Handover::QR(qr_code) => {
                let device_engagement_bytes = Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code)
                    .context("failed to construct QR code")?;
                let le_role = None;
                let central_client_modes = device_engagement_bytes
                    .as_ref()
                    .ble_central_client_options()
                    .cloned()
                    .collect();
                let peripheral_server_modes = device_engagement_bytes
                    .as_ref()
                    .ble_peripheral_server_options()
                    .cloned()
                    .collect();
                (
                    device_engagement_bytes,
                    crate::definitions::session::Handover::QR,
                    le_role,
                    central_client_modes,
                    peripheral_server_modes,
                )
            }
        };

        //generate own keys
        let key_pair = create_p256_ephemeral_keys().context("failed to generate ephemeral key")?;
        let e_reader_key_private = key_pair.0;
        let e_reader_key_public =
            Tag24::new(key_pair.1).context("failed to encode public cose key")?;

        // Save private key bytes before consuming the key for ECDH
        let e_reader_key_private_bytes: [u8; 32] = e_reader_key_private.to_bytes().into();

        //decode device_engagement
        let device_engagement = device_engagement_bytes.as_ref();
        let e_device_key = &device_engagement.security.1;

        // calculate ble Ident value
        let ble_ident =
            super::calculate_ble_ident(e_device_key).context("failed to calculate BLE Ident")?;

        // derive shared secret
        let shared_secret = get_shared_secret(
            e_device_key.clone().into_inner(),
            &e_reader_key_private.into(),
        )
        .context("failed to derive shared session secret")?;

        let session_transcript = SessionTranscript180135(
            device_engagement_bytes,
            e_reader_key_public.clone(),
            session_transcript_handover,
        );

        let session_transcript_bytes = Tag24::new(session_transcript.clone())
            .context("failed to encode session transcript")?;

        tracing::debug!(
            "reader SessionTranscript ({} bytes): {:?}",
            session_transcript_bytes.inner_bytes.len(),
            session_transcript_bytes.inner_bytes.as_slice()
        );

        //derive session keys
        let sk_reader = derive_session_key(&shared_secret, &session_transcript_bytes, true)
            .context("failed to derive reader session key")?
            .into();
        let sk_device = derive_session_key(&shared_secret, &session_transcript_bytes, false)
            .context("failed to derive device session key")?
            .into();

        let mut session_manager = Self {
            session_transcript,
            sk_device,
            device_message_counter: 0,
            sk_reader,
            reader_message_counter: 0,
            e_reader_key_private: e_reader_key_private_bytes,
            trust_anchor_registry,
            holder_le_role,
            holder_central_client_modes,
            holder_peripheral_server_modes,
        };

        let request = session_manager
            .build_request(namespaces)
            .context("failed to build device request")?;
        let session = SessionEstablishment {
            data: request.into(),
            e_reader_key: e_reader_key_public,
        };
        let session_request =
            cbor::to_vec(&session).context("failed to encode session establishment")?;

        Ok((session_manager, session_request, ble_ident))
    }

    #[deprecated(since = "0.2.1", note = "use ble_central_client_options instead")]
    pub fn first_central_client_uuid(&self) -> Option<&Uuid> {
        self.ble_central_client_options().next().map(|cc| &cc.uuid)
    }

    /// Retrieve the connection details for BLE central client mode offered by the mdoc, if any.
    ///
    /// The protocol allows for more than one central client mode to be offered, so a consumer
    /// of this API can use the first one that works.
    pub fn ble_central_client_options(&self) -> impl Iterator<Item = &CentralClientMode> {
        self.holder_central_client_modes.iter()
    }

    /// Retrieve the connection details for BLE peripheral server mode offered by the mdoc, if any.
    ///
    /// The protocol allows for more than one peripheral server mode to be offered, so a consumer
    /// of this API can use the first one that works.
    pub fn ble_peripheral_server_options(&self) -> impl Iterator<Item = &PeripheralServerMode> {
        self.holder_peripheral_server_modes.iter()
    }

    /// Retrieve the mdoc's preferred connection details.
    pub fn preferred_ble_mode(&self) -> Option<BleMode> {
        let first_central = self
            .holder_central_client_modes
            .first()
            .map(|m| BleMode::CentralClient(m.clone()));
        let first_peripheral = self
            .holder_peripheral_server_modes
            .first()
            .map(|m| BleMode::PeripheralServer(m.clone()));
        match self.holder_le_role {
            None | Some(LeRole::CentralPreferred) => first_central.or(first_peripheral),
            Some(LeRole::CentralOnly) => first_central,
            Some(LeRole::PeripheralOnly) => first_peripheral,
            Some(LeRole::PeripheralPreferred) => first_peripheral.or(first_central),
        }
    }

    /// Creates a new request with specified elements to request.
    pub fn new_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        let request = self.build_request(namespaces)?;
        let session = SessionData {
            data: Some(request.into()),
            status: None,
        };
        cbor::to_vec(&session).map_err(Into::into)
    }

    fn build_request(&mut self, namespaces: device_request::Namespaces) -> Result<Vec<u8>> {
        // if !validate_request(namespaces.clone()).is_ok() {
        //     return Err(anyhow::Error::msg(
        //         "At least one of the namespaces contain an invalid combination of fields to request",
        //     ));
        // }
        let items_request = ItemsRequest {
            doc_type: "org.iso.18013.5.1.mDL".into(),
            namespaces,
            request_info: None,
        };

        let doc_request = DocRequest {
            reader_auth: None,
            items_request: Tag24::new(items_request)?,
        };
        let device_request = DeviceRequest {
            version: DeviceRequest::VERSION.to_string(),
            doc_requests: NonEmptyVec::new(doc_request),
            device_request_info: None,
            reader_auth_all: None,
        };
        let device_request_bytes = cbor::to_vec(&device_request)?;
        session::encrypt_reader_data(
            &self.sk_reader.into(),
            &device_request_bytes,
            &mut self.reader_message_counter,
        )
        .map_err(|e| anyhow!("unable to encrypt request: {}", e))
    }

    fn decrypt_response(&mut self, response: &[u8]) -> Result<DeviceResponse, Error> {
        let session_data: SessionData = cbor::from_slice(response)?;
        tracing::debug!(
            "decrypt_response: {} response bytes, data_present={}, status={:?}",
            response.len(),
            session_data.data.is_some(),
            session_data.status.as_ref()
        );
        let encrypted_response = match session_data.data {
            None => return Err(Error::HolderError),
            Some(r) => r,
        };
        let decrypted_response = session::decrypt_device_data(
            &self.sk_device.into(),
            encrypted_response.as_ref(),
            &mut self.device_message_counter,
        )
        .map_err(|_e| Error::DecryptionError)?;
        tracing::debug!(
            "decrypt_response: decrypted OK, {} plaintext bytes (from {} encrypted)",
            decrypted_response.len(),
            encrypted_response.as_ref().len()
        );
        let device_response: DeviceResponse = cbor::from_slice(&decrypted_response)?;
        Ok(device_response)
    }

    /// Handle a device response, validating it and checking certificate revocation.
    ///
    /// Validity checks (certificate windows and the MSO `validityInfo` window) are
    /// performed against the current time. Use [`Self::handle_response_with_options`]
    /// to pin the validation time.
    ///
    /// # Arguments
    /// * `response` - The encrypted device response
    /// * `revocation_fetcher` - Revocation fetcher for CRL checking. Use `&()` to skip revocation checks.
    pub async fn handle_response<R: RevocationFetcher>(
        &mut self,
        response: &[u8],
        revocation_fetcher: &R,
    ) -> ResponseAuthenticationOutcome {
        self.handle_response_with_options(
            response,
            revocation_fetcher,
            &ValidationOptions::default(),
        )
        .await
    }

    /// Like [`Self::handle_response`], but with explicit [`ValidationOptions`].
    ///
    /// The `options` control the validation time used both for certificate chain
    /// validity checks and for the MSO `validityInfo` window check.
    pub async fn handle_response_with_options<R: RevocationFetcher>(
        &mut self,
        response: &[u8],
        revocation_fetcher: &R,
        options: &ValidationOptions,
    ) -> ResponseAuthenticationOutcome {
        let mut validated_response = ResponseAuthenticationOutcome::default();

        let device_response = match self.decrypt_response(response) {
            Ok(device_response) => device_response,
            Err(e) => {
                validated_response
                    .errors
                    .insert("decryption_errors".to_string(), json!(vec![format!("{e}")]));
                return validated_response;
            }
        };

        // Extract doc_types from the decrypted device response
        let doc_types: Vec<String> = device_response
            .documents
            .as_ref()
            .map(|docs| docs.iter().map(|d| d.doc_type.clone()).collect())
            .unwrap_or_default();

        match parse(&device_response) {
            Ok((document, x5chain, namespaces)) => {
                validate_response_with_options(
                    self.session_transcript.clone(),
                    self.trust_anchor_registry.clone(),
                    x5chain,
                    document.clone(),
                    namespaces,
                    doc_types,
                    revocation_fetcher,
                    self.e_reader_key_private,
                    options,
                )
                .await
            }
            Err(e) => {
                validated_response.doc_types = doc_types;
                validated_response
                    .errors
                    .insert("parsing_errors".to_string(), json!(vec![format!("{e}")]));
                validated_response
            }
        }
    }
}

pub fn parse(
    device_response: &DeviceResponse,
) -> Result<(&Document, X5Chain, BTreeMap<String, Value>), Error> {
    let document = get_document(device_response)?;
    let header = document.issuer_signed.issuer_auth.unprotected.clone();
    let x5chain = header
        .rest
        .iter()
        .find(|(label, _)| label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL))
        .map(|(_, value)| value.to_owned())
        .map(X5Chain::from_cbor)
        .ok_or(Error::X5ChainMissing)?
        .map_err(Error::X5ChainParsing)?;
    let parsed_response = parse_namespaces(device_response)?;
    Ok((document, x5chain, parsed_response))
}

fn parse_response(value: ciborium::Value) -> Result<Value, Error> {
    match value {
        ciborium::Value::Text(s) => Ok(Value::String(s)),
        ciborium::Value::Tag(_t, v) => match *v {
            ciborium::Value::Text(d) => Ok(Value::String(d)),
            a => Err(Error::ParsingError(format!(
                "found {a:?} when expecting text"
            ))),
        },
        ciborium::Value::Array(v) => {
            let mut array_response = Vec::<Value>::new();
            for a in v {
                let r = parse_response(a)?;
                array_response.push(r);
            }
            Ok(json!(array_response))
        }
        ciborium::Value::Map(m) => {
            let mut map_response = serde_json::Map::<String, Value>::new();
            for (key, value) in m {
                if let ciborium::Value::Text(k) = key {
                    let parsed = parse_response(value)?;
                    map_response.insert(k, parsed);
                }
            }
            let json = json!(map_response);
            Ok(json)
        }
        ciborium::Value::Bytes(b) => Ok(json!(b)),
        ciborium::Value::Bool(b) => Ok(json!(b)),
        ciborium::Value::Integer(i) => Ok(json!(<ciborium::value::Integer as Into<i128>>::into(i))),
        a => Err(Error::ParsingError(format!(
            "found {a:?} when expecting anything but floats and nulls"
        ))),
    }
}

const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// Select the document to verify. An mDL is preferred when one is present, so
/// mDL behaviour is unchanged; otherwise the first document of any doctype is
/// used (an ISO/IEC 18013-5 or 23220 mdoc of another doctype).
fn get_document(device_response: &DeviceResponse) -> Result<&Document, Error> {
    let documents = device_response
        .documents
        .as_ref()
        .ok_or(ReaderError::DeviceTransmissionError)?;
    documents
        .iter()
        .find(|doc| doc.doc_type == MDL_DOCTYPE)
        .or_else(|| documents.iter().next())
        .ok_or(ReaderError::DocumentTypeError)
}

fn _validate_request(namespaces: device_request::Namespaces) -> Result<bool, Error> {
    // TODO: Check country name of certificate matches mdl

    // Check if request follows ISO18013-5 restrictions
    // A valid mdoc request can contain a maximum of 2 age_over_NN fields
    let age_over_nn_requested: Vec<(String, bool)> = namespaces
        .get("org.iso.18013.5.1")
        .map(|k| k.clone().into_inner())
        //To Do: get rid of unwrap
        .unwrap()
        .into_iter()
        .filter(|x| x.0.contains("age_over"))
        .collect();

    if age_over_nn_requested.len() > 2 {
        //To Do: Decide what should happen when more than two age_over_nn are requested
        return Err(Error::InvalidRequest);
    }

    Ok(true)
}

/// Return every disclosed namespace of the selected document, keyed by namespace.
/// For an mDL the core `org.iso.18013.5.1` namespace is still required.
pub fn parse_namespaces(
    device_response: &DeviceResponse,
) -> Result<BTreeMap<String, serde_json::Value>, Error> {
    let document = get_document(device_response)?;
    let namespaces = document
        .issuer_signed
        .namespaces
        .as_ref()
        .ok_or(Error::NoMdlDataTransmission)?
        .clone()
        .into_inner();

    if document.doc_type == MDL_DOCTYPE && !namespaces.contains_key(MDL_NAMESPACE) {
        return Err(Error::IncorrectNamespace);
    }

    let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
    for (namespace, items) in namespaces {
        let mut elements = BTreeMap::<String, serde_json::Value>::new();
        items
            .into_inner()
            .into_iter()
            .map(|item| item.into_inner())
            .for_each(|item| {
                if let Ok(val) = parse_response(item.element_value.clone()) {
                    elements.insert(item.element_identifier, val);
                }
            });
        parsed_response.insert(namespace, serde_json::to_value(elements)?);
    }
    Ok(parsed_response)
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn nested_response_values() {
        let domestic_driving_privileges = crate::cbor::from_slice(&hex::decode("81A276646F6D65737469635F76656869636C655F636C617373A46A69737375655F64617465D903EC6A323032342D30322D31346B6578706972795F64617465D903EC6A323032382D30332D3131781B646F6D65737469635F76656869636C655F636C6173735F636F64656243207822646F6D65737469635F76656869636C655F636C6173735F6465736372697074696F6E76436C6173732043204E4F4E2D434F4D4D45524349414C781D646F6D65737469635F76656869636C655F7265737472696374696F6E7381A27821646F6D65737469635F76656869636C655F7265737472696374696F6E5F636F64656230317828646F6D65737469635F76656869636C655F7265737472696374696F6E5F6465736372697074696F6E78284D555354205745415220434F5252454354495645204C454E534553205748454E2044524956494E47").unwrap()).unwrap();
        let json = parse_response(domestic_driving_privileges).unwrap();
        let expected = serde_json::json!(
          [
            {
              "domestic_vehicle_class": {
                "issue_date": "2024-02-14",
                "expiry_date": "2028-03-11",
                "domestic_vehicle_class_code": "C ",
                "domestic_vehicle_class_description": "Class C NON-COMMERCIAL"
              },
              "domestic_vehicle_restrictions": [
                {
                  "domestic_vehicle_restriction_code": "01",
                  "domestic_vehicle_restriction_description": "MUST WEAR CORRECTIVE LENSES WHEN DRIVING"
                }
              ]
            }
          ]
        );
        assert_eq!(json, expected)
    }

    // Helpers for the generic-doctype tests, also used by `reader_utils` tests.

    use crate::definitions::{
        device_response::Status,
        device_signed::{DeviceAuth, DeviceSigned},
        x509::trust_anchor::{TrustAnchor, TrustPurpose},
        IssuerSigned, ValidityInfo,
    };
    use crate::issuance::{Mdoc, Namespaces};
    use p256::ecdsa::{Signature, SigningKey};

    /// A custom (non-mDL) doctype; its namespace equals the doctype.
    pub(crate) const TEST_DOCTYPE: &str = "org.example.custom.1";

    /// A freshly generated IACA root (the only trust anchor), a document signer
    /// chain issued by it, and the document signer's key.
    pub(crate) fn trusted_signer() -> (TrustAnchorRegistry, X5Chain, SigningKey) {
        use crate::definitions::x509::test::{
            prepare_root_certificate, prepare_signer_certificate,
        };
        use signature::Signer;
        use x509_cert::{builder::Builder, spki::SignatureBitStringEncoding};

        let root_key = SigningKey::random(&mut rand::thread_rng());
        let signer_key = SigningKey::random(&mut rand::thread_rng());
        let issuer: x509_cert::name::Name = "CN=issuer,C=US".parse().unwrap();
        let crl_url = "http://example.com/crl".to_string();

        let mut root = prepare_root_certificate(&root_key, issuer.clone(), crl_url.clone());
        let signature: Signature = root_key.sign(&root.finalize().unwrap());
        let root = root
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        let mut signer = prepare_signer_certificate(&signer_key, &root_key, issuer, crl_url);
        let signature: Signature = root_key.sign(&signer.finalize().unwrap());
        let signer = signer
            .assemble(signature.to_der().to_bitstring().unwrap())
            .unwrap();

        let registry = TrustAnchorRegistry {
            anchors: vec![TrustAnchor {
                certificate: root,
                purpose: TrustPurpose::Iaca,
            }],
        };
        let x5chain = X5Chain::builder()
            .with_certificate(signer)
            .unwrap()
            .build()
            .unwrap();
        (registry, x5chain, signer_key)
    }

    /// A validity window from `now + from_days` to `now + until_days`.
    pub(crate) fn validity(from_days: i64, until_days: i64) -> ValidityInfo {
        let now = time::OffsetDateTime::now_utc();
        ValidityInfo {
            signed: now,
            valid_from: now + time::Duration::days(from_days),
            valid_until: now + time::Duration::days(until_days),
            expected_update: None,
        }
    }

    /// Elements of the custom-doctype namespace: text, boolean and array values.
    pub(crate) fn custom_namespaces() -> Namespaces {
        use ciborium::Value as Cbor;
        let elements = [
            ("given_name", Cbor::Text("Test".into())),
            ("family_name", Cbor::Text("Holder".into())),
            ("active", Cbor::Bool(true)),
            (
                "tags",
                Cbor::Array(vec![Cbor::Text("a".into()), Cbor::Text("b".into())]),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        [(TEST_DOCTYPE.to_string(), elements)].into_iter().collect()
    }

    /// Issue an mdoc whose signed MSO names `doc_type`. `namespaces: None` keeps the
    /// mDL namespaces of the crate's minimal test mdoc.
    pub(crate) fn issue(
        doc_type: &str,
        namespaces: Option<Namespaces>,
        validity_info: ValidityInfo,
        x5chain: X5Chain,
        signer: SigningKey,
    ) -> Mdoc {
        let mut builder = crate::issuance::mdoc::test::minimal_test_mdoc_builder()
            .doc_type(doc_type.to_string())
            .validity_info(validity_info);
        if let Some(namespaces) = namespaces {
            builder = builder.namespaces(namespaces);
        }
        builder
            .issue::<SigningKey, Signature>(x5chain, signer)
            .expect("issue test mdoc")
    }

    /// A response document presenting `mdoc` under `doc_type`. Device signing is a
    /// placeholder: these tests cover document selection and issuer authentication.
    pub(crate) fn document(mdoc: &Mdoc, doc_type: &str) -> Document {
        Document {
            doc_type: doc_type.to_string(),
            issuer_signed: IssuerSigned {
                namespaces: Some(mdoc.namespaces.clone()),
                issuer_auth: mdoc.issuer_auth.clone(),
            },
            device_signed: DeviceSigned {
                namespaces: Tag24::new(BTreeMap::new()).unwrap(),
                device_auth: DeviceAuth::DeviceSignature(mdoc.issuer_auth.clone()),
            },
            errors: None,
        }
    }

    pub(crate) fn device_response(documents: Vec<Document>) -> DeviceResponse {
        DeviceResponse {
            version: "1.0".to_string(),
            documents: NonEmptyVec::maybe_new(documents),
            document_errors: None,
            status: Status::OK,
        }
    }

    fn custom_document() -> Document {
        let (_, x5chain, signer) = trusted_signer();
        let mdoc = issue(
            TEST_DOCTYPE,
            Some(custom_namespaces()),
            validity(-1, 1),
            x5chain,
            signer,
        );
        document(&mdoc, TEST_DOCTYPE)
    }

    fn mdl_document() -> Document {
        let (_, x5chain, signer) = trusted_signer();
        let mdoc = issue(MDL_DOCTYPE, None, validity(-1, 1), x5chain, signer);
        document(&mdoc, MDL_DOCTYPE)
    }

    #[test]
    fn custom_doctype_only_response_is_selected() {
        let response = device_response(vec![custom_document()]);
        let (document, _, namespaces) = parse(&response).expect("custom doctype is parsed");
        assert_eq!(document.doc_type, TEST_DOCTYPE);
        assert_eq!(
            namespaces.keys().collect::<Vec<_>>(),
            vec![TEST_DOCTYPE],
            "only the custom namespace is returned"
        );
    }

    #[test]
    fn mixed_response_selects_the_mdl() {
        // The custom document comes first; the mDL is still the one selected.
        let response = device_response(vec![custom_document(), mdl_document()]);
        assert_eq!(get_document(&response).unwrap().doc_type, MDL_DOCTYPE);
        let (document, _, namespaces) = parse(&response).expect("mixed response is parsed");
        assert_eq!(document.doc_type, MDL_DOCTYPE);
        assert!(namespaces.contains_key(MDL_NAMESPACE));
        assert!(!namespaces.contains_key(TEST_DOCTYPE));
    }

    #[test]
    fn mdl_without_core_namespace_is_rejected() {
        let (_, x5chain, signer) = trusted_signer();
        let mdoc = issue(
            MDL_DOCTYPE,
            Some(custom_namespaces()),
            validity(-1, 1),
            x5chain,
            signer,
        );
        let response = device_response(vec![document(&mdoc, MDL_DOCTYPE)]);
        let result = parse_namespaces(&response);
        assert!(
            matches!(result, Err(Error::IncorrectNamespace)),
            "an mDL without {MDL_NAMESPACE} must be rejected: {result:?}"
        );
    }

    #[test]
    fn custom_namespace_elements_are_returned() {
        let response = device_response(vec![custom_document()]);
        let namespaces = parse_namespaces(&response).expect("custom namespace is parsed");
        assert_eq!(
            namespaces[TEST_DOCTYPE],
            serde_json::json!({
                "given_name": "Test",
                "family_name": "Holder",
                "active": true,
                "tags": ["a", "b"],
            })
        );
    }

    #[test]
    fn mdl_response_returns_core_and_aamva_namespaces() {
        let response = device_response(vec![mdl_document()]);
        let namespaces = parse_namespaces(&response).expect("mDL is parsed");
        assert_eq!(
            namespaces.keys().collect::<Vec<_>>(),
            vec![MDL_NAMESPACE, "org.iso.18013.5.1.aamva"]
        );
        assert_eq!(namespaces[MDL_NAMESPACE]["family_name"], "Smith");
    }
}
