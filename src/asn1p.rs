use std::{clone, fs};

use asn1;
use bytes::Bytes;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TbsCertList<'a> {
    pub serialNumber: Option<asn1::Tlv<'a>>,
    pub signature: Option<asn1::Tlv<'a>>,
    pub issuer: Option<asn1::SequenceOf<'a, asn1::SetOf<'a, TypeAndValue<'a>>>>,
    pub validity: Option<asn1::Tlv<'a>>,
    pub subject: Option<asn1::Tlv<'a>>,
    pub subjectPublicKeyInfo: Option<asn1::Tlv<'a>>,
    //nextUpdate: asn1::Tlv<'a>,
    //revokedCertificates: asn1::Tlv<'a>,
    #[explicit(0)]
    pub crlExtensions: Option<asn1::SequenceOf<'a, ExtensionValue<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TbsCertificateFull<'a> {
    // #[default(2)]
    pub version: Option<asn1::Tlv<'a>>,
    pub serialNumber: Option<asn1::Tlv<'a>>,
    pub signature: Option<AlgorithmIdentifier<'a>>,
    pub issuer: Option<asn1::SequenceOf<'a, asn1::SetOf<'a, TypeAndValueSpec<'a>>>>,
    pub validity: Option<Validity>,
    pub subject: Option<asn1::SequenceOf<'a, asn1::SetOf<'a, TypeAndValueSpec<'a>>>>,
    pub subjectPublicKeyInfo: Option<asn1::Tlv<'a>>,
    //nextUpdate: asn1::Tlv<'a>,
    //revokedCertificates: asn1::Tlv<'a>,
    #[explicit(3)]
    pub crlExtensions: Option<asn1::SequenceOf<'a, ExtensionValue<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Validity {
    pub notBefore: asn1::UtcTime,
    pub notAfter: asn1::UtcTime,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: asn1::Tlv<'a>,
    pub parameters: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CertificateRevocationList<'a> {
    pub tbsCertList: TbsCertList<'a>,
    pub signatureAlgorithm: AlgorithmIdentifier<'a>,
    pub signatureValue: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct tbsCertificate<'a> {
    // Potentially need to remove
    #[explicit[0]]
    pub version: Option<asn1::Tlv<'a>>,
    pub serialNumber: Option<asn1::Tlv<'a>>,
    pub signature: Option<asn1::Tlv<'a>>,
    pub issuer: Option<asn1::Tlv<'a>>,
    pub validity: Option<asn1::Tlv<'a>>,
    pub subject: Option<asn1::Tlv<'a>>,
    pub subjectPublicKeyInfo: Option<asn1::Tlv<'a>>,
    #[explicit(3)]
    pub resourceCertificateExtensions: Option<asn1::SequenceOf<'a, asn1::Tlv<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Certificate<'a> {
    pub tbsCert: tbsCertificate<'a>,
    pub signatureAlgorithm: asn1::Tlv<'a>,
    pub signatureValue: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CertificateFull<'a> {
    pub tbsCert: TbsCertificateFull<'a>,
    pub signatureAlgorithm: AlgorithmIdentifier<'a>,
    pub signatureValue: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CertificateT<'a> {
    pub tbsCert: asn1::Tlv<'a>,
    pub signatureAlgorithm: asn1::Tlv<'a>,
    pub signatureValue: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct tbsCertificate2<'a> {
    #[explicit(0)]
    pub version: Option<asn1::Tlv<'a>>,
    pub serialNumber: Option<asn1::Tlv<'a>>,
    pub signature: Option<asn1::Tlv<'a>>,
    pub issuer: Option<asn1::Tlv<'a>>,
    pub validity: Option<asn1::Tlv<'a>>,
    pub subject: Option<asn1::Tlv<'a>>,
    pub subjectPublicKeyInfo: Option<asn1::Tlv<'a>>,
    #[explicit(3)]
    pub resourceCertificateExtensions: Option<asn1::SequenceOf<'a, asn1::Tlv<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Certificate2<'a> {
    pub tbsCert: tbsCertificate2<'a>,
    pub signatureAlgorithm: asn1::Tlv<'a>,
    pub signatureValue: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct certificatePolicies<'a> {
    pub policies: asn1::SequenceOf<'a, PolicyInformation<'a>>,
}
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct PolicyInformation<'a> {
    pub policyIdentifier: asn1::ObjectIdentifier,
    pub policy: Option<asn1::IA5String<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Clone)]
pub struct RelativeDistinguishedName<'a> {
    pub content: asn1::SetOf<'a, TypeAndValue<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TypeAndValue<'a> {
    pub attrType: asn1::Tlv<'a>,
    pub attrValue: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct TypeAndValueSpec<'a> {
    pub attrType: asn1::ObjectIdentifier,
    pub attrValue: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]

pub struct ExtensionValue<'a> {
    pub identifier: asn1::ObjectIdentifier,
    #[default(false)]
    pub critical: bool,
    pub value: asn1::Tlv<'a>,
}
#[derive(asn1::Asn1Read, asn1::Asn1Write)]

pub struct AKIContent<'a> {
    #[implicit(0)]
    pub keyIdentifier: Option<&'a [u8]>,
    #[implicit(1)]
    pub authorityCertIssuer: Option<&'a [u8]>,
    #[implicit(2)]
    pub authorityCertSerialNumber: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]

pub struct SubPubKeyInfo<'a> {
    #[explicit(0)]
    pub keyIdentifier: Option<&'a [u8]>,
}
#[derive(asn1::Asn1Read, asn1::Asn1Write)]

pub struct SubjectInfoAccess<'a> {
    pub identifier: asn1::ObjectIdentifier,
    pub fields: asn1::OctetStringEncoded<asn1::SequenceOf<'a, InfoAccessField<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]

pub struct AuthorityInfoAccess<'a> {
    pub identifier: asn1::ObjectIdentifier,
    pub fields: asn1::OctetStringEncoded<asn1::SequenceOf<'a, InfoAccessField<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug)]

pub struct InfoAccessField<'a> {
    pub identifier: asn1::ObjectIdentifier,
    #[implicit(6)]
    pub val: Option<asn1::IA5String<'a>>,
}
#[derive(asn1::Asn1Read, asn1::Asn1Write)]

pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subjectPublicKey: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AuthorityKeyIdentifier<'a> {
    #[implicit(0)]
    pub keyIdentifier: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CrlDistributionPoints<'a> {
    pub identifier: asn1::ObjectIdentifier,
    pub crlDistributionPoints: asn1::OctetStringEncoded<asn1::SequenceOf<'a, DistributionPoint<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct DistributionPoint<'a> {
    #[implicit(0)]
    pub distributionPoint: Option<DistributionPointName<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct DistributionPointName<'a> {
    #[implicit(0)]
    pub fullname: Option<GeneralName<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct GeneralName<'a> {
    #[implicit(6)]
    pub UniformResourceIdentifier: Option<asn1::IA5String<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct BasicConstraints {
    pub ca: bool,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct EncapsulatedContentInfo<'a> {
    pub eContentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub eContent: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ROAInfo<'a> {
    pub eContentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub eContent: Option<asn1::OctetStringEncoded<ROA<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct MftInfo<'a> {
    pub eContentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub eContent: Option<asn1::OctetStringEncoded<Manifest<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ROAInfo2<'a> {
    pub eContentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub eContent: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct constructedROA<'a> {
    pub roa: asn1::OctetStringEncoded<ROA<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Clone)]
pub struct ROA<'a> {
    pub asID: u32,
    pub ipAddrBlocks: asn1::SequenceOf<'a, ROAIpAddrFamily<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedData<'a> {
    pub version: u8,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: EncapsulatedContentInfo<'a>,
    pub certificates: asn1::Tlv<'a>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataSpec<'a> {
    pub version: u8,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: EncapsulatedContentInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, Certificate<'a>>>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedAttribute<'a> {
    pub contentType: asn1::ObjectIdentifier,
    pub value: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Clone)]
pub struct SignerInfos<'a> {
    pub version: u8,
    #[implicit(0)]
    pub sid: Option<&'a [u8]>,
    pub digestAlgorithm: asn1::Tlv<'a>,
    #[implicit(0)]
    pub signedAttrs: Option<asn1::SequenceOf<'a, SignedAttribute<'a>>>,
    pub signatureAlgorithm: asn1::Tlv<'a>,
    pub signature: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ContentInfoSpec<'a> {
    pub contentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub content: Option<SignedDataSpec<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ContentInfo<'a> {
    pub contentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub content: Option<SignedDataRoa<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ContentInfoMft<'a> {
    pub contentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub content: Option<SignedDataMft<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ContentInfoMftFull<'a> {
    pub contentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub content: Option<SignedDataMftFull<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ContentInfoRoaFull<'a> {
    pub contentType: asn1::ObjectIdentifier,
    #[explicit(0)]
    pub content: Option<SignedDataRoaFull<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ContentInfo2<'a> {
    pub contentType: asn1::Tlv<'a>,
    #[explicit(0)]
    pub content: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataRoa<'a> {
    pub version: asn1::Tlv<'a>,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: ROAInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, Certificate<'a>>>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataMft<'a> {
    pub version: asn1::Tlv<'a>,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: MftInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, Certificate<'a>>>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataRoaFull<'a> {
    pub version: asn1::Tlv<'a>,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: ROAInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, CertificateFull<'a>>>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataMftFull<'a> {
    pub version: asn1::Tlv<'a>,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: MftInfo<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, CertificateFull<'a>>>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataRoa2<'a> {
    pub version: asn1::Tlv<'a>,
    pub digestAlgorithms: asn1::Tlv<'a>,
    pub encapContentInfo: asn1::Tlv<'a>,
    #[implicit(0)]
    pub certificates: Option<asn1::SetOf<'a, Certificate<'a>>>,
    pub signerInfos: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CertChoice<'a> {
    pub cert: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct CertificateSet<'a> {
    pub certificate: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataObject<'a> {
    pub typ: asn1::Tlv<'a>,
    #[explicit(0)]
    pub content: Option<SignedData<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct SignedDataObjectSpec<'a> {
    pub typ: asn1::Tlv<'a>,
    #[explicit(0)]
    pub content: Option<SignedDataSpec<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ipAddrBlocks<'a> {
    pub addressFamily: &'a [u8],
    pub addresses: Option<asn1::SequenceOf<'a, IpAddrBlockChoice<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ipAddrBlocksNone<'a> {
    pub addressFamily: &'a [u8],
    pub addresses: asn1::Null,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum IpAddrBlockChoice<'a> {
    addressPrefix(asn1::BitString<'a>),
    addressRange(IpAddrRange<'a>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct IpAddrBlockChoice2<'a> {
    #[implicit(0)]
    pub addressPrefix: Option<asn1::BitString<'a>>,
    #[implicit(1)]
    pub addressRange: Option<IpAddrRange<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct IpAddrRange<'a> {
    pub min: asn1::BitString<'a>,
    pub max: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ROAIpAddrFamily<'a> {
    pub addressFamily: &'a [u8],
    pub addresses: asn1::SequenceOf<'a, ROAIpAddress<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ROAIpAddress<'a> {
    pub address: asn1::BitString<'a>,
    pub maxLength: Option<u8>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct autonomousSystemIds<'a> {
    pub asIdsOrRanges: asn1::SequenceOf<'a, AsIdOrRange<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ASIdentifierChoice<'a> {
    #[explicit(0)]
    pub inherit: Option<asn1::Null>,
    #[explicit(1)]
    pub asIdsOrRanges: Option<asn1::SequenceOf<'a, AsIdOrRange<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AsIdOrRange<'a> {
    #[explicit(0)]
    pub AsRange: Option<AsRange<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AsRange<'a> {
    pub min: asn1::BigInt<'a>,
    pub max: asn1::BigInt<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Clone)]
pub struct Manifest<'a> {
    pub manifestNumber: asn1::BigInt<'a>,
    pub thisUpdateTime: asn1::GeneralizedTime,
    pub nextUpdateTime: Option<asn1::GeneralizedTime>,
    pub fileHashAlg: asn1::ObjectIdentifier,
    pub fileHash: asn1::SequenceOf<'a, FileAndHash<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Clone)]
pub struct FileAndHash<'a> {
    pub file: asn1::IA5String<'a>,
    pub hash: asn1::BitString<'a>,
}

pub fn fix_e_econtent(obj: Bytes) -> Option<Vec<u8>> {
    let new_obj = asn1::parse_single::<SignedDataObject>(&obj);
    if new_obj.is_err() {
        // println!("Error: Could not parse Object");
        return None;
    }

    let con = new_obj.unwrap().content.unwrap();

    return None;
}

pub fn extract_e_content_file(file_uri: &str) {
    let file_content = fs::read(file_uri).unwrap();
    extract_e_content(Bytes::from(file_content), None);
}

pub fn extract_e_content(obj: Bytes, obj_type: Option<&str>) -> Option<Vec<u8>> {
    let new_obj = asn1::parse_single::<SignedDataObject>(&obj);
    if new_obj.is_err() {
        println!("Error: Could not parse Object {}", base64::encode(&obj));
        return None;
    }
    let con = new_obj.unwrap().content.unwrap();
    let con_type = con.encapContentInfo.eContentType.to_string().clone();
    let t;
    if con_type == "1.2.840.113549.1.9.16.1.26" {
        t = "mft";
    } else if con_type == "1.2.840.113549.1.9.16.1.24" {
        t = "roa";
    } else if con_type == "1.2.840.113549.1.9.16.1.49" {
        t = "aspa";
    } else if con_type == "1.2.840.113549.1.9.16.1.35" {
        t = "gbr";
    } else {
        t = "unknown";
    }
    // println!("Info: Decoded Object with Type {} ({})", t, con_type);
    if obj_type.is_some() && obj_type.unwrap() != t {
        // println!("\n --> Error: Object Type does not match the given Type! ({} != {})\n", t, obj_type.unwrap_or("unknown"));
    }
    if con.encapContentInfo.eContent.is_none() {
        // println!("Error: Could not extract eContent");
        return None;
    }
    return Some(con.encapContentInfo.eContent.unwrap().data().to_vec());
}
