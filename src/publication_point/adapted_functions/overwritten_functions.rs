// This file contains functions of rpki-rs which are modified to allow for deep manipulations

use bcder::encode::{PrimitiveContent, Values};
use bcder::{encode, Captured, Mode, OctetString, Oid, Tag};
use bytes::Bytes;
use chrono::{Duration, Utc};
use rpki::repository::cert::{KeyUsage, Overclaim, TbsCert};
use rpki::repository::crl::{CrlEntry, RevokedCertificates, TbsCertList};
use rpki::repository::crypto::{PublicKey, Signature, SignatureAlgorithm, Signer};
use rpki::repository::manifest::ManifestContent;
use rpki::repository::oid;
use rpki::repository::roa::{RoaBuilder, RoaIpAddressesBuilder};
use rpki::repository::x509::{Name, SignedData, Time, Validity};
use rpki::rrdp::{Delta, DeltaElement, NotificationFile, PublishElement, UpdateElement, WithdrawElement};

use crate::publication_point::adapted_functions::sigobj_a::{
    SignedAttrs as SignedAttrs_a, SignedObject as SignedObject_a, SignedObjectBuilder as SignedObjectBuilder_a,
};
use crate::publication_point::manual_tests::test_util::CustomPublishElement;
use crate::repository::KeyAndSigner;
use crate::repository::{self, RepoConfig};
use ring::digest;
use rpki::uri;
use rpki::xml;
use rpki::xml::decode::Name as XmlName;
use std::clone::Clone;
use std::io::{self, Write};

use rpki::repository::resources::{self, Asn, IpBlock, IpBlocksBuilder, IpResources};

use std::net::{IpAddr, Ipv4Addr};

// Set all necessary values of a signed object to then parse it
pub fn finalize_signed_object(
    signed_builder: SignedObjectBuilder_a,
    content_type: Oid<Bytes>,
    content: Bytes,
    ks: KeyAndSigner,
    hash_algo: &'static digest::Algorithm,
) -> SignedObject_a {
    let issuer_pub = ks.get_pub_key();

    // Produce signed attributes.
    //let message_digest = signed_builder.digest_algorithm().digest(&content).into();
    let message_digest = digest::digest(hash_algo, &content).into();
    let signed_attrs = SignedAttrs_a::new(
        &content_type,
        &message_digest,
        signed_builder.signing_time(),
        signed_builder.binary_signing_time(),
    );

    // Sign signed attributes with a one-off key.
    let (sig, key_info) = ks.sign_one_off(&signed_attrs.encode_verify(), "RSA");
    let signature = Signature::new(SignatureAlgorithm::default(), sig);
    let sid = key_info.clone().key_identifier();

    let b = issuer_pub.to_subject_name();

    // let r = encode::sequence(
    //     encode::set(
    //         encode::sequence((
    //             oid::AT_COMMON_NAME.encode(),
    //             PublicKeyCn(self.key_identifier()).encode(),
    //         ))
    //     )
    // );
    // let newname = Name::new("aaaah");
    // prev: n.clone()

    let n = signed_builder.issuer().unwrap_or_else(|| &b);
    // Make the certificate.
    let mut cert = TbsCert::new(
        signed_builder.serial_number(),
        n.clone(),
        // signed_builder.validity(),
        fake_validity(),
        signed_builder.clone().subject,
        key_info,
        KeyUsage::Ee,
        Overclaim::Refuse,
    );
    cert.set_authority_key_identifier(Some(issuer_pub.key_identifier()));
    cert.set_crl_uri(Some(signed_builder.crl_uri().clone()));
    cert.set_ca_issuer(Some(signed_builder.ca_issuer().clone()));
    cert.set_signed_object(Some(signed_builder.signed_object().clone()));
    cert.set_v4_resources(signed_builder.v4_resources().clone());
    cert.set_v6_resources(signed_builder.v6_resources().clone());
    cert.set_as_resources(signed_builder.as_resources().clone());

    let cert = into_cert(cert, ks);
    //let cert = cert.into_cert(signer, issuer_key).unwrap();

    let siob = SignedObject_a {
        digest_algorithm: signed_builder.digest_algorithm(),
        content_type,
        content: OctetString::new(content),
        cert,
        sid,
        signed_attrs,
        signature,
        message_digest,
        signing_time: signed_builder.signing_time(),
        binary_signing_time: signed_builder.binary_signing_time(),
    };
    siob
}

// This strucutre is used to provide a general value encoder for reference encoding of signed objects
// It is used to encode custom byte values for a signed object parameter
pub struct MaliciousBytesValue {
    pub value: Bytes,
}

impl Values for MaliciousBytesValue {
    fn encoded_len(&self, _: Mode) -> usize {
        self.value.as_ref().len()
    }

    /// Encodes the values in the given mode and writes them to `target`.
    fn write_encoded<W: io::Write>(&self, _: Mode, target: &mut W) -> Result<(), io::Error> {
        target.write_all(self.value.as_ref()).unwrap();
        Ok(())
    }
}

fn write_len_encoded<W: io::Write>(len: usize, target: &mut W) -> Result<(), io::Error> {
    if len < 0x80 {
        let buf = [len as u8];
        target.write_all(&buf)
    } else if len < 0x1_00 {
        let buf = [0x81, len as u8];
        target.write_all(&buf)
    } else if len < 0x1_0000 {
        let buf = [0x82, (len >> 8) as u8, len as u8];
        target.write_all(&buf)
    } else if len < 0x100_0000 {
        let buf = [0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        target.write_all(&buf)
    } else if len < 0x1_0000_0000 {
        let buf = [0x84, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        target.write_all(&buf)
    } else {
        panic!("excessive length")
    }
}

pub fn encode_octet_string<W: io::Write>(oc: &OctetString, target: &mut W) {
    let tag = Tag::OCTET_STRING;
    // let mut target = vec![];
    tag.write_encoded(false, target).unwrap();
    write_len_encoded(oc.as_ref().len(), target).unwrap();
    for slice in oc.as_ref().iter() {
        target.write_all(slice).unwrap();
    }
}

// Custom encoding of a signed object
// With this function, everything in the encoding of a signed object can be customized
pub fn encode_sig_custom(
    sigob: SignedObject_a,
    signed_data_oid: Option<Bytes>,
    content_tag: Option<Tag>,
    content_version: Option<Bytes>,
    digest_algo_set: Option<Bytes>,
    content_type_oid: Option<Bytes>,
    content_tag_encap_info: Option<Tag>,
    content: Option<Bytes>,
    cert_tag: Option<Tag>,
    cert_conent: Option<Bytes>,
    signer_info_version: Option<Bytes>,
    key_id: Option<Bytes>,
    digest_algo_signer: Option<Bytes>,
    signed_attr: Option<Bytes>,
    sig_algo: Option<Bytes>,
    signature: Option<&Bytes>,
) -> Bytes {
    // Define default values -> Transform them to bytes -> To malicious byte value -> Parse to parsing function
    let mut bvec = vec![];

    let signed_data_oid = match signed_data_oid {
        Some(value) => MaliciousBytesValue { value },
        None => {
            oid::SIGNED_DATA.encode().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let content_tag = match content_tag {
        Some(value) => value,
        None => Tag::CTX_0,
    };

    let mut bvec = vec![];
    let content_version = match content_version {
        Some(value) => MaliciousBytesValue { value },
        None => {
            3u8.encode().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let mut bvec = vec![];
    let digest_algo_set = match digest_algo_set {
        Some(value) => MaliciousBytesValue { value },
        None => {
            sigob.digest_algorithm.encode_set().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let mut bvec = vec![];
    let content_type_oid = match content_type_oid {
        Some(value) => MaliciousBytesValue { value },
        None => {
            sigob.content_type().encode().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let content_tag_encap_info = match content_tag_encap_info {
        Some(value) => value,
        None => Tag::CTX_0,
    };

    // let mut bvec = vec![];
    // let content = match content {
    //     Some(value) => MaliciousBytesValue { value },
    //     None => {
    //         sigob.content().encode_ref().write_encoded(Mode::Der, &mut bvec).unwrap();
    //         MaliciousBytesValue { value: Bytes::from(bvec) }

    //     }
    // };

    let cert_tag = match cert_tag {
        Some(value) => value,
        None => Tag::CTX_0,
    };

    let cert_conent = match cert_conent {
        Some(value) => MaliciousBytesValue { value },
        None => MaliciousBytesValue {
            value: sigob.cert().clone(),
        },
    };

    let mut bvec = vec![];
    let signer_info_version = match signer_info_version {
        Some(value) => MaliciousBytesValue { value },
        None => {
            3u8.encode().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let mut bvec = vec![];
    let key_id = match key_id {
        Some(value) => MaliciousBytesValue { value },
        None => {
            sigob.sid.encode_ref_as(Tag::CTX_0).write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let mut bvec = vec![];
    let digest_algo_signer = match digest_algo_signer {
        Some(value) => MaliciousBytesValue { value },
        None => {
            sigob.digest_algorithm.encode().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let mut bvec = vec![];
    let signed_attr = match signed_attr {
        Some(value) => MaliciousBytesValue { value },
        None => {
            sigob.signed_attrs.encode_ref().write_encoded(Mode::Der, &mut bvec).unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let mut bvec = vec![];
    let sig_algo = match sig_algo {
        Some(value) => MaliciousBytesValue { value },
        None => {
            sigob
                .signature
                .algorithm()
                .cms_encode()
                .write_encoded(Mode::Der, &mut bvec)
                .unwrap();
            MaliciousBytesValue { value: Bytes::from(bvec) }
        }
    };

    let signature = match signature {
        Some(value) => value,
        None => sigob.signature.value(),
    };

    let encoded = encode_ref_custom(
        signed_data_oid,
        content_tag,
        content_version,
        digest_algo_set,
        content_type_oid,
        content_tag_encap_info,
        sigob.content(),
        // content,
        cert_tag,
        cert_conent,
        signer_info_version,
        key_id,
        digest_algo_signer,
        signed_attr,
        sig_algo,
        signature,
    );

    encoded
}

pub struct Constructed_s<V> {
    /// The tag of the value.
    tag: Tag,

    /// A value encoder for the content of the value.
    inner: V,
}

impl<V> Constructed_s<V> {
    /// Creates a new constructed value encoder from a tag and content.
    ///
    /// The returned value will encode as a single constructed value with
    /// the given tag and whatever `inner` encodeds to as its content.
    pub fn new(tag: Tag, inner: V) -> Self {
        Constructed_s { tag, inner }
    }
}

impl<V: Values> Values for Constructed_s<V> {
    fn encoded_len(&self, mode: Mode) -> usize {
        let len = self.inner.encoded_len(mode);
        let len = len
            + match mode {
                Mode::Ber | Mode::Der => encoded_len_inner(len),
                Mode::Cer => todo!(),
            };
        self.tag.encoded_len() + len
    }

    fn write_encoded<W: io::Write>(&self, mode: Mode, target: &mut W) -> Result<(), io::Error> {
        self.tag.write_encoded(true, target)?;
        match mode {
            Mode::Ber | Mode::Der => {
                write_len_encoded(self.inner.encoded_len(mode), target);
                self.inner.write_encoded(mode, target)
            }
            Mode::Cer => {
                todo!();
            }
        }
    }
}

pub struct Constructed_c {
    /// The tag of the value.
    tag: Tag,

    /// A value encoder for the content of the value.
    inner: OctetString,
}

impl Constructed_c {
    /// Creates a new constructed value encoder from a tag and content.
    ///
    /// The returned value will encode as a single constructed value with
    /// the given tag and whatever `inner` encodeds to as its content.
    pub fn new(tag: Tag, inner: OctetString) -> Self {
        Constructed_c { tag, inner }
    }
}

pub fn encoded_len_inner(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x1_00 {
        2
    } else if len < 0x1_0000 {
        3
    } else if len < 0x100_0000 {
        4
    } else if len < 0x1_0000_0000 {
        5
    } else {
        panic!("excessive length")
    }
}

fn octet_string_enc_len(value: &OctetString, tag: Tag) -> usize {
    let len = value.as_ref().len();
    tag.encoded_len() + encoded_len_inner(len) + len
}

impl Values for Constructed_c {
    fn encoded_len(&self, mode: Mode) -> usize {
        let l = octet_string_enc_len(&self.inner, self.tag);
        // Remove (+ 1) to trigger problem
        let lg = l + encoded_len_inner(l) + 1;
        lg
    }

    fn write_encoded<W: io::Write>(&self, mode: Mode, target: &mut W) -> Result<(), io::Error> {
        let mut tmp_target = vec![];
        self.tag.write_encoded(true, &mut tmp_target)?;
        let l = octet_string_enc_len(&self.inner, self.tag);
        write_len_encoded(l, &mut tmp_target);

        encode_octet_string(&self.inner, &mut tmp_target);

        self.tag.write_encoded(true, target)?;
        write_len_encoded(l, target);

        encode_octet_string(&self.inner, target);
        Ok(())
    }

    fn explicit(self, tag: Tag) -> encode::Constructed<Self>
    where
        Self: Sized,
    {
        encode::Constructed::new(tag, self)
    }

    fn to_captured(&self, mode: Mode) -> Captured {
        let mut target = Vec::new();
        self.write_encoded(mode, &mut target).unwrap();
        Captured::empty(mode)
    }
}

pub fn alt_sequence<V: Values>(inner: V) -> impl Values {
    Constructed_s::new(Tag::SEQUENCE, inner)
}

pub fn alt_sequence_as<V: Values>(tag: Tag, inner: V) -> impl Values {
    Constructed_s::new(tag, inner)
}

pub fn encode_ref_custom<V: encode::Values>(
    signed_data_oid: V,
    content_tag: Tag,
    content_version: V,
    digest_algo_set: V,
    content_type_oid: V,
    content_tag_encap_info: Tag,
    content: &OctetString,
    // content: V,
    cert_tag: Tag,
    cert_conent: V,
    signer_info_version: V,
    key_id: V,
    digest_algo_signer: V,
    signed_attr: V,
    sig_algo: V,
    signature: &Bytes,
) -> Bytes {
    let r = alt_sequence((
        signed_data_oid, // contentType
        alt_sequence_as(
            content_tag, // content
            alt_sequence((
                content_version, // version
                digest_algo_set, // digestAlgorithms
                alt_sequence((
                    // encapContentInfo
                    content_type_oid,
                    Constructed_c {
                        tag: content_tag_encap_info,
                        inner: content.clone(),
                    }, // encode::sequence_as(content_tag_encap_info, content),
                )),
                alt_sequence_as(
                    cert_tag, // certificates
                    cert_conent,
                ),
                // crl -- omitted
                encode::set(
                    // signerInfo
                    alt_sequence((
                        // SignerInfo
                        signer_info_version, // version
                        key_id,
                        digest_algo_signer, // digestAlgorithm
                        signed_attr,        // signedAttrs
                        sig_algo,
                        // signatureAlgorithm
                        OctetString::encode_slice(
                            // signature
                            signature.clone(),
                        ),
                        // unsignedAttrs omitted
                    )),
                ),
            )),
        ),
    ))
    .to_captured(Mode::Der)
    .into_bytes();
    r
}

fn write_xml_publish(element: &PublishElement, content: &mut xml::encode::Content<impl io::Write>) -> Result<(), io::Error> {
    const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
    const PUBLISH: XmlName = XmlName::qualified(NS, b"publish");
    content
        .element(PUBLISH.into_unqualified())?
        .attr("uri", &element.uri())?
        .content(|content| content.base64(element.data().as_ref()))?;
    Ok(())
}

fn write_xml_update(element: &UpdateElement, content: &mut xml::encode::Content<impl io::Write>) -> Result<(), io::Error> {
    const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
    const PUBLISH: XmlName = XmlName::qualified(NS, b"publish");
    content
        .element(PUBLISH.into_unqualified())?
        .attr("uri", &element.uri())?
        .attr("hash", &element.hash())?
        .content(|content| content.base64(element.data().as_ref()))?;
    Ok(())
}

fn write_xml_withdraw(element: &WithdrawElement, content: &mut xml::encode::Content<impl io::Write>) -> Result<(), io::Error> {
    const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
    const WITHDRAW: XmlName = XmlName::qualified(NS, b"withdraw");
    content
        .element(WITHDRAW.into_unqualified())?
        .attr("uri", &element.uri())?
        .attr("hash", &element.hash())?;
    Ok(())
}

pub fn write_xml_delta_element(element: &DeltaElement, content: &mut xml::encode::Content<impl io::Write>) -> Result<(), io::Error> {
    match element {
        DeltaElement::Publish(p) => write_xml_publish(p, content),
        DeltaElement::Update(u) => write_xml_update(u, content),
        DeltaElement::Withdraw(w) => write_xml_withdraw(w, content),
    }
}

pub fn write_xml_delta(delta: Delta, custom_pub_elements: Vec<CustomPublishElement>, writer: &mut impl io::Write) -> Result<(), io::Error> {
    const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
    const DELTA: XmlName = XmlName::qualified(NS, b"delta");
    let mut writer = xml::encode::Writer::new(writer);
    writer
        .element(DELTA.into_unqualified())?
        .attr("xmlns", NS)?
        .attr("version", "1")?
        .attr("session_id", &delta.session_id())?
        .attr("serial", &delta.serial())?
        .content(|content| {
            for el in &delta.into_elements() {
                write_xml_delta_element(el, content)?;
            }
            for cel in &custom_pub_elements {
                cel.write_xml(content)?;
            }
            Ok(())
        })?;
    writer.done()
}

pub fn write_xml_notification(
    notification: NotificationFile,
    xmlns: Option<(&str, String)>,
    version: Option<(&str, String)>,
    session_id: Option<(&str, String)>,
    serial: Option<(&str, String)>,
    snapshot: Option<Vec<(&str, String)>>,
    deltas: Option<Vec<Vec<(&str, String)>>>,
    writer: &mut impl io::Write,
) -> Result<(), io::Error> {
    // TODO Also replace the xml tags with options
    // This is not trivial as they need to be static -> Not sure if it is even possible with function parameters
    // May require some Rust magic
    const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
    const NOTIFICATION: XmlName = XmlName::qualified(NS, b"notification");
    const SNAPSHOT: XmlName = XmlName::qualified(NS, b"snapshot");
    const DELTA: XmlName = XmlName::qualified(NS, b"delta");
    let ns = "http://www.ripe.net/rpki/rrdp";

    let xmlns = match xmlns {
        Some(val) => val,
        None => ("xmlns", ns.to_string()),
    };

    let version = match version {
        Some(val) => val,
        None => ("version", "1".to_string()),
    };

    let session_id = match session_id {
        Some(val) => val,
        None => {
            let sid = notification.clone().session_id().to_owned();
            let s = sid.clone().to_string().clone();
            ("session_id", s)
        }
    };

    let serial = match serial {
        Some(val) => val,
        None => ("serial", notification.serial().to_string()),
    };

    let snapshot_uri = match snapshot.clone() {
        Some(val) => {
            let v = &val[0];
            (v.0, v.clone().1)
        }

        None => ("uri", notification.snapshot().uri().to_string()),
    };

    let snapshot_hash = match snapshot {
        Some(val) => {
            let v = &val[1];
            (v.0, v.clone().1)
        }
        None => ("hash", notification.snapshot().hash().to_string()),
    };

    let deltas = match deltas {
        Some(val) => val,
        None => {
            let mut del_vals = vec![];
            for delta in notification.deltas() {
                let mut del = vec![];
                del.push(("serial", delta.serial().to_string()));
                del.push(("uri", delta.uri().to_string()));
                del.push(("hash", delta.hash().to_string()));
                del_vals.push(del);
            }
            del_vals
        }
    };

    let mut writer = xml::encode::Writer::new(writer);
    writer
        .element(NOTIFICATION.into_unqualified())?
        .attr(xmlns.0, xmlns.1.as_str())?
        .attr(version.0, version.1.as_str())?
        .attr(session_id.0, session_id.1.as_str())?
        .attr(serial.0, serial.1.as_str())?
        .content(|content| {
            // add snapshot
            content
                .element(SNAPSHOT.into_unqualified())?
                .attr(snapshot_uri.0, snapshot_uri.1.as_str())?
                .attr(snapshot_hash.0, snapshot_hash.1.as_str())?;

            // add deltas
            for delta in deltas {
                content
                    .element(DELTA.into_unqualified())?
                    .attr(delta[0].0, delta[0].1.as_str())?
                    .attr(delta[1].0, delta[1].1.as_str())?
                    .attr(delta[2].0, delta[2].1.as_str())?;
            }

            Ok(())
        })?;
    writer.done()
}

pub fn into_cert(cert: TbsCert, ks: KeyAndSigner) -> Bytes {
    let data = Captured::from_values(Mode::Der, cert.encode_ref());
    let sig = ks.sign(&data);
    let signature = Signature::new(SignatureAlgorithm::default(), sig);
    let sd = SignedData::new(data, signature);
    let ret = sd.encode_ref().to_captured(Mode::Der).into_bytes();
    ret
}

pub fn into_crl<C: IntoIterator<Item = CrlEntry>>(crl_list: TbsCertList<C>, ks: KeyAndSigner) -> Bytes
where
    <C as IntoIterator>::IntoIter: Clone,
{
    let tbs: TbsCertList<RevokedCertificates> = crl_list.into();
    let data = Captured::from_values(Mode::Der, tbs.encode_ref());
    let sig = ks.sign(&data);
    let signature = Signature::new(SignatureAlgorithm::default(), sig);

    let signed_data = SignedData::new(data, signature);
    let b = signed_data.encode_ref().to_captured(Mode::Der).into_bytes();
    b
}

pub fn into_manifest<C: IntoIterator<Item = CrlEntry>>(crl_list: TbsCertList<C>, ks: KeyAndSigner) -> Bytes
where
    <C as IntoIterator>::IntoIter: Clone,
{
    let tbs: TbsCertList<RevokedCertificates> = crl_list.into();
    let data = Captured::from_values(Mode::Der, tbs.encode_ref());
    let sig = ks.sign(&data);
    let signature = Signature::new(SignatureAlgorithm::default(), sig);

    let signed_data = SignedData::new(data, signature);
    let b = signed_data.encode_ref().to_captured(Mode::Der).into_bytes();
    b
}

// Manifest Related Functions
pub fn into_signed_object_mft(
    manifest_content: ManifestContent,
    mut sigobj: SignedObjectBuilder_a,
    ks: KeyAndSigner,
    hash_algo: &'static digest::Algorithm,
) -> SignedObject_a {
    // sigobj.build_v4_resource_blocks(|b| b.push(resources::Prefix::new(addr, 24)));
    // sigobj.build_as_resource_blocks(|b| b.push((Asn::from_u32(0), Asn::from_u32(1000))));

    sigobj.set_v4_resources_inherit();
    sigobj.set_v6_resources_inherit();

    sigobj.set_as_resources_inherit();
    let signed = finalize_signed_object(
        sigobj,
        Oid(oid::CT_RPKI_MANIFEST.0.into()),
        manifest_content.encode_ref().to_captured(Mode::Der).into_bytes(),
        ks,
        hash_algo,
    );

    signed
}

pub fn into_signed_object_roa(
    roa_builder: RoaBuilder,
    mut sigobj: SignedObjectBuilder_a,
    ks: KeyAndSigner,
    hash_algo: &'static digest::Algorithm,
    conf: &RepoConfig,
) -> SignedObject_a {
    let v4 = roa_builder.v4().to_resources();
    let v6 = roa_builder.v6().to_resources();
    sigobj.set_v4_resources(v4);
    sigobj.set_v6_resources(v6);

    // sigobj.build_v4_resource_blocks(|b| {
    //     for a in &conf.IPBlocks{
    //         // Either use absolute value or family id from asn
    //         if a.0 != 4 && a.0 != 1{
    //             continue;
    //         }
    //         b.push(a.1);
    //     }
    // });

    // sigobj.build_v6_resource_blocks(|b| {
    //     for a in &conf.IPBlocks{
    //         if a.0 != 6 && a.0 != 2{
    //             continue;
    //         }
    //         // b.push(a.1);
    //     }
    // });

    // sigobj.set_as_resources_inherit();
    let signed = finalize_signed_object(
        sigobj,
        Oid(oid::ROUTE_ORIGIN_AUTHZ.0.into()),
        roa_builder.to_attestation().encode_ref().to_captured(Mode::Der).into_bytes(),
        ks,
        hash_algo,
    );

    signed
}

fn fake_validity() -> Validity {
    let offset = Duration::from_std(std::time::Duration::from_secs(86400)).unwrap();
    let not_before = Time::now() - offset;
    let not_after = Time::new(Utc::now() + Duration::from_std(std::time::Duration::from_secs(1086400)).unwrap() + offset);
    if not_before < not_after {
        Validity::new(not_before, not_after)
    } else {
        Validity::new(not_after, not_before)
    }
}

fn fake_validity2() -> Validity {
    let offset = Duration::from_std(std::time::Duration::from_secs(386400)).unwrap();
    let not_before = Time::now() - offset;
    let not_after = Time::new(Utc::now() + Duration::from_std(std::time::Duration::from_secs(1086400)).unwrap() + offset);
    if not_before < not_after {
        Validity::new(not_before, not_after)
    } else {
        Validity::new(not_after, not_before)
    }
}

pub fn default_ref_manifest(
    mft_content: ManifestContent,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    mft_rsync: uri::Rsync,
    ks: KeyAndSigner,
    hash_algo: Option<&'static digest::Algorithm>,
) -> SignedObject_a {
    let algo = match hash_algo {
        Some(v) => v,
        None => &digest::SHA256,
    };
    let manifest_signed = into_signed_object_mft(
        mft_content,
        SignedObjectBuilder_a::new(repository::random_serial(), fake_validity(), crl_rsync, issuer_rsync, mft_rsync),
        ks,
        algo,
    );
    manifest_signed
}

pub fn encode_ref_manifest_content(
    mft_content: ManifestContent,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    mft_rsync: uri::Rsync,
    ks: KeyAndSigner,
    hash_algo: Option<&'static digest::Algorithm>,
) -> Bytes {
    let manifest_signed = default_ref_manifest(mft_content, crl_rsync, issuer_rsync, mft_rsync, ks, hash_algo);

    let final_bytes = encode_sig_custom(
        manifest_signed,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    final_bytes
}

/*
Create a signedData Object from a ROA builder
*/
pub fn default_ref_roa(
    roa_builder: RoaBuilder,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    roa_rsync: uri::Rsync,
    ks: KeyAndSigner,
    hash_algo: Option<&'static digest::Algorithm>,
    conf: &RepoConfig,
) -> SignedObject_a {
    let algo = match hash_algo {
        Some(v) => v,
        None => &digest::SHA256,
    };
    let roa_signed = into_signed_object_roa(
        roa_builder,
        SignedObjectBuilder_a::new(
            repository::random_serial(),
            Validity::from_secs(286400),
            crl_rsync,
            issuer_rsync,
            roa_rsync,
        ),
        ks,
        algo,
        conf,
    );
    roa_signed
}

/*
Encode a ROA from a ROA builder
*/
pub fn encode_ref_roa_builder(
    roa_builder: RoaBuilder,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    roa_rsync: uri::Rsync,
    ks: KeyAndSigner,
    hash_algo: Option<&'static digest::Algorithm>,
    conf: &RepoConfig,
) -> Bytes {
    let roa_signed = default_ref_roa(roa_builder, crl_rsync, issuer_rsync, roa_rsync, ks, hash_algo, conf);

    let final_bytes = encode_sig_custom(
        roa_signed, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    );
    final_bytes
}

/*
Encode a ROA from a RoaBuilder that is likely not valid
*/
pub fn encode_ref_roa_builder_invalid(
    roa_builder: RoaBuilder,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    roa_rsync: uri::Rsync,
    ks: KeyAndSigner,
    hash_algo: Option<&'static digest::Algorithm>,
    conf: &RepoConfig,
) -> Bytes {
    let roa_signed = default_ref_roa(roa_builder, crl_rsync, issuer_rsync, roa_rsync, ks, hash_algo, conf);

    let final_bytes = encode_sig_custom(
        roa_signed,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&Bytes::from("Fooo")),
    );
    final_bytes
}

/**
 * Generates an "empty" signed object builder, i.e. a generic builder
 */
pub fn generate_empty_signed_object_builder() -> SignedObjectBuilder_a {
    let crl_rsync = uri::Rsync::from_string("rsync://consts::domain/folder/object.crl".to_string()).unwrap();
    let issuer_rsync = uri::Rsync::from_string("rsync://consts::domain/folder/object.cer".to_string()).unwrap();
    let roa_rsync = uri::Rsync::from_string("rsync://consts::domain/folder/object.roa".to_string()).unwrap();

    SignedObjectBuilder_a::new(
        repository::random_serial(),
        Validity::from_secs(286400),
        crl_rsync,
        issuer_rsync,
        roa_rsync,
    )
}

pub fn signed_object_from_content_bytes_random<S: Signer>(
    content_type: Oid<Bytes>,
    content: Bytes,
    signer: &S,
    issuer_key: &S::KeyId,
) -> SignedObject_a {
    let builder = generate_empty_signed_object_builder();
    builder.finalize(content_type, content, signer, issuer_key).unwrap()
}

pub fn signed_object_from_content_bytes<S: Signer>(
    content_type: Oid<Bytes>,
    content: Bytes,
    signer: &S,
    issuer_key: &S::KeyId,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    roa_rsync: uri::Rsync,
    obj_type: &str,
    conf: &RepoConfig,
) -> SignedObject_a {
    let mut builder = SignedObjectBuilder_a::new(
        repository::random_serial(),
        Validity::from_secs(286400),
        crl_rsync,
        issuer_rsync,
        roa_rsync,
    );

    // Manually add an IPv4 address to the object
    let addr = Ipv4Addr::new(conf.DEFAULT_IPSPACE_FIRST_OCTET, conf.DEFAULT_IPSPACE_SEC_OCTET, 0, 0);

    if obj_type == "mft" || obj_type == "gbr" {
        builder.set_as_resources_inherit();
        builder.set_v4_resources_inherit();
        builder.set_v6_resources_inherit();
    } else {
        builder.build_v4_resource_blocks(|b| {
            for a in &conf.IPBlocks {
                // Either use absolute value or family id from asn
                if a.0 != 4 && a.0 != 1 {
                    continue;
                }
                b.push(a.1);
            }
        });

        builder.build_v6_resource_blocks(|b| {
            for a in &conf.IPBlocks {
                if a.0 != 6 && a.0 != 2 {
                    continue;
                }
                // b.push(a.1);
            }
        });
    }

    builder.finalize(content_type, content, signer, issuer_key).unwrap()
}

// Alternative Implementation that uses a fixed key for the EE certs to save time
pub fn signed_object_from_content_bytes_alt<S: Signer>(
    content_type: Oid<Bytes>,
    content: Bytes,
    signer: &S,
    issuer_key: &S::KeyId,
    crl_rsync: uri::Rsync,
    issuer_rsync: uri::Rsync,
    roa_rsync: uri::Rsync,
    ee_public_key: PublicKey,
    ee_key: openssl::pkey::PKey<openssl::pkey::Private>,
    obj_type: &str,
    conf: &RepoConfig,
) -> SignedObject_a {
    let mut builder = SignedObjectBuilder_a::new(
        repository::random_serial(),
        Validity::from_secs(286400),
        crl_rsync,
        issuer_rsync,
        roa_rsync,
    );

    // Manually add an IPv4 address to the object
    let addr = Ipv4Addr::new(conf.DEFAULT_IPSPACE_FIRST_OCTET, conf.DEFAULT_IPSPACE_SEC_OCTET, 0, 0);

    if obj_type == "mft" || obj_type == "gbr" {
        builder.set_as_resources_inherit();

        builder.set_v4_resources_inherit();
        builder.set_v6_resources_inherit();
    } else if obj_type == "roa" {
        builder.build_v4_resource_blocks(|b| {
            for a in &conf.IPBlocks {
                // Either use absolute value or family id from asn
                if a.0 != 4 && a.0 != 1 {
                    continue;
                }
                b.push(a.1);
            }
        });

        builder.build_v6_resource_blocks(|b| {
            for a in &conf.IPBlocks {
                if a.0 != 6 && a.0 != 2 {
                    continue;
                }
                //b.push(a.1);
            }
        });
    } else if obj_type == "aspa" {
        builder.build_as_resource_blocks(|b| b.push((Asn::from_u32(0), Asn::from_u32(1000))));
    } else {
        panic!("Unknown Type!");
    }

    // builder.set_v4_resources_inherit();
    // builder.set_v6_resources_inherit();

    // builder.set_as_resources_inherit();
    builder
        .finalize_alt(content_type, content, signer, issuer_key, ee_public_key, ee_key)
        .unwrap()
}
