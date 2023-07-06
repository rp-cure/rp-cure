use crate::publication_point::constants;
use crate::publication_point::adapted_functions;
use crate::repository;
use crate::publication_point::rp_interaction;
use rpki::uri;

use rpki::xml;
use rpki::xml::decode::{Content, Error as XmlError, Name as XmlName, Reader};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use rpki::repository::crypto::{DigestAlgorithm, KeyIdentifier, PublicKey, PublicKeyFormat, SignatureAlgorithm, Signer};
use rpki::repository::manifest::{FileAndHash, Manifest, ManifestContent, ManifestHash};
use rpki::repository::resources::{Asn, Prefix};
use rpki::repository::x509::Time;
use rpki::rrdp::{Delta, DeltaElement, DeltaInfo, Hash, NotificationFile, PublishElement, Snapshot, UpdateElement, UriAndHash};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bcder::encode::{Primitive, PrimitiveContent, Values};
use bcder::{decode, encode, Captured, ConstOid, Ia5String, Mode, OctetString, Oid, Tag};
use oid::prelude::*;
use rpki::repository::oid as roid;

use std::env;
use std::fs;
use std::io;
use std::str;
use std::str::FromStr;

use rand::Rng;
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::publication_point::adapted_functions::sigobj_a::{SignedAttrs as SignedAttrs_a, SignedObject as SignedObject_a, SignedObjectBuilder as SignedObjectBuilder_a};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;

// This file contains all functions that are required to create the vulnerability tests
// It should abstract all underlying functions as much as possible to allow easy test-creation

pub fn get_cwd() -> String {
    env::current_dir().unwrap().into_os_string().into_string().unwrap()
}

pub fn run_all_rps(
    roa_ip: Option<Ipv4Addr>,
    prefix: Option<u8>,
    asn: Option<u32>,
    expect_contains: bool,
    test_name: String,
) -> Vec<TestResult> {
    let mut results = vec![];

    // Default parameters for if we do not care if the object was accepted
    let roa_ip = match roa_ip {
        Some(val) => val,
        None => Ipv4Addr::new(0, 0, 0, 0),
    };

    let prefix = match prefix {
        Some(val) => val,
        None => 16u8,
    };

    let asn = match asn {
        Some(val) => val,
        None => 1u32,
    };

    let (roa_routinator, output_routinator) = rp_interaction::run_update_routinator();
    let routinator_expected = rp_interaction::roas_contain_announcment(roa_routinator, roa_ip, prefix, asn) != expect_contains;

    let info_rout = &output_routinator;

    let result_routinator = TestResult::new(routinator_expected, "Routinator", info_rout.to_string(), test_name.clone());
    results.push(result_routinator);

    let (roa_octo, output_octo) = rp_interaction::run_update_octorpki();
    let octo_expected = rp_interaction::roas_contain_announcment(roa_octo, roa_ip, prefix, asn) != expect_contains;

    let info_octo = &output_octo;

    let result_octo = TestResult::new(octo_expected, "Octorpki", info_octo.to_string(), test_name.clone());
    results.push(result_octo);

    let (roa_fort, output_fort) = rp_interaction::run_update_fort();
    let fort_expected = rp_interaction::roas_contain_announcment(roa_fort, roa_ip, prefix, asn) != expect_contains;

    let info_fort = &output_fort;

    let result_fort = TestResult::new(fort_expected, "Fort", info_fort.to_string(), test_name.clone());
    results.push(result_fort);

    // let (roa_client, output_client) = rp_interaction::run_update_rpki_client();
    // let client_expected = rp_interaction::roas_contain_announcment(roa_client, roa_ip, prefix, asn) != expect_contains;

    // let info_client = &output_client;

    // let result_client = TestResult::new(client_expected, "Rpki-Client", info_client.to_string(), test_name.clone());
    // results.push(result_client);

    results
}

pub fn add_roa_wrapper(roa_string: &str) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let parent_cer_uri_l = "rsync://".to_string() + constants::DOMAIN + "/" + constants::BASE_REPO_DIR + "ta/" + "newca" + ".cer";
    let roa_base_uri = repository::base_repo_uri("newca", &conf);
    println!("Generating ROA: {}", roa_string);
    let ca_name = "newca";
    repository::add_roa(&roa_string, roa_base_uri, ca_name, &parent_cer_uri_l, &conf);
}

pub fn create_child_ca(ip_prefix: Prefix, asn_mi: u32, asn_ma: u32) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let parent_cert_key_uri_l = constants::BASE_KEY_DIR.to_string() + "newca.der";
    let parent_repo_uri_l = constants::BASE_REPO_DIR.to_string() + "newca/";
    let notification_uri = "https://".to_string() + constants::DOMAIN + "/" + constants::BASE_RRDP_DIR + "notification.xml";
    let ca_name = "malca";
    //let resource_block = Prefix::new(Ipv4Addr::new(10, 0, 10, 0), 16);
    let asn_min = Asn::from_u32(asn_mi);
    let asn_max = Asn::from_u32(asn_ma);
    let issuer_cer_uri = "rsync://".to_string() + constants::DOMAIN + "/" + constants::BASE_REPO_DIR + "ta/newca.cer";
    let parent_name = "newca";
    let parents_parent_name = "ta";
    let ta = false;

    repository::create_ca(
        &parent_cert_key_uri_l,
        &parent_repo_uri_l,
        &notification_uri,
        ca_name,
        ip_prefix,
        asn_min,
        asn_max,
        &issuer_cer_uri,
        parent_name,
        parents_parent_name,
        ta,
        "DSA",
        true,
        &conf,
        true,
    );
}

pub fn create_oid(oid: &str) -> (Bytes, Bytes) {
    let oid = ObjectIdentifier::try_from(oid).unwrap();
    let oid_vec: Vec<u8> = oid.into();

    let fake_oid = Oid(&oid_vec);

    let mut bvec_fake_set = vec![];
    let mut bvec_fake = vec![];

    let sq = encode::sequence(fake_oid.encode());
    encode::set(&sq).write_encoded(Mode::Der, &mut bvec_fake_set).unwrap();
    sq.write_encoded(Mode::Der, &mut bvec_fake).unwrap();

    let fake_bytes_set = Bytes::from(bvec_fake_set);
    let fake_bytes = Bytes::from(bvec_fake);

    (fake_bytes, fake_bytes_set)
}

// This function generates everything around a manipulated roa
// Roa string is needed to create filename
pub fn manipulated_roa_after(roa_string: &str, roa_content: Bytes) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let roa_base_uri = repository::base_repo_uri("newca", &conf);
    repository::after_roa_creation(roa_string, roa_base_uri, "newca", roa_content, true, &conf)
}

// This function generates everything needed to then manipulate a manifest
// i.e. create a fresh roa and generate a valid manifest that can then be manipulated
pub fn manipulated_mft_before(
    hash_algo: Option<&'static digest::Algorithm>,
) -> (Bytes, String, SignedObject_a, (Hash, String), (Hash, String), Bytes) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (roa_content, roa_str) = repository::create_random_roa(&conf);

    // Need to create hashes before we change the objects
    let mft_bef = repository::get_current_file_hash(".mft", "newca", &conf);
    let crl_bef = repository::get_current_file_hash(".crl", "newca", &conf);

    let (_, serial_number) = repository::get_current_session_notification(&conf);
    let serial_number = serial_number + 1;

    let crl_content = repository::create_default_crl(
        serial_number,
        vec![],
        &(constants::BASE_KEY_DIR.to_string() + "newca.der"),
        "newca",
        &conf,
    );

    (
        roa_content,
        roa_str,
        generate_default_signed_mft(hash_algo),
        mft_bef,
        crl_bef,
        crl_content,
    )
}

// This function generates everything around a manipulated manifest
pub fn manipulated_mft_after(
    mft_content: Bytes,
    roa_content: Bytes,
    roa_string: &str,
    mft_bef: (Hash, String),
    crl_bef: (Hash, String),
    crl_content: Bytes,
) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (session_id, serial_number) = repository::get_current_session_notification(&conf);
    let serial_number = serial_number + 1;

    // Write manifest content to disc
    repository::write_object_to_disc(
        &mft_content,
        "mft",
        &(constants::BASE_KEY_DIR.to_string() + "newca.der"),
        "newca",
        &conf,
    );

    let roa_uri = repository::base_repo_uri("newca", &conf) + repository::file_name_for_object(roa_string, ".roa").as_str();
    let rsync_uri_roa = uri::Rsync::from_str(&roa_uri).unwrap();

    let roa_file_name = repository::file_name_for_object(roa_string, ".roa");

    let (pub_el, up_el) = repository::create_delta_elements_single(
        "newca",
        roa_file_name.as_str(),
        roa_content,
        mft_content,
        crl_content,
        mft_bef.0,
        mft_bef.1,
        crl_bef.0,
        crl_bef.1,
        &conf,
    );

    repository::finalize_snap_notification(session_id, serial_number, pub_el, up_el, &conf);
}

// Base function for creating a manifest and delta elements
pub fn base_creation() -> (Vec<PublishElement>, Vec<UpdateElement>, String) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (roa_content, roa_string) = repository::create_random_roa(&conf);

    let (_, serial_number) = repository::get_current_session_notification(&conf);
    let serial_number = serial_number + 1;

    let (manifest_hash, file_name_mft) = repository::get_current_file_hash(".mft", "newca", &conf);
    let (crl_hash, file_name_crl) = repository::get_current_file_hash(".crl", "newca", &conf);

    let crl_content = repository::create_default_crl(
        serial_number,
        vec![],
        &(constants::BASE_KEY_DIR.to_string() + "newca.der"),
        "newca",
        &conf,
    );

    let roa_uri = repository::base_repo_uri("newca", &conf) + repository::file_name_for_object(&roa_string, ".roa").as_str();
    let rsync_uri_roa = uri::Rsync::from_str(&roa_uri).unwrap();

    let roa_file_name = repository::file_name_for_object(&roa_string, ".roa");

    let mft_content = repository::make_manifest("newca", "ta", &conf);

    let (pub_el, up_el) = repository::create_delta_elements_single(
        "newca",
        roa_file_name.as_str(),
        roa_content,
        mft_content,
        crl_content,
        manifest_hash,
        file_name_mft,
        crl_hash,
        file_name_crl,
        &conf,
    );
    (pub_el, up_el, roa_string)
}

// This function generates everything needed to then manipulate a Snapshot
pub fn manipulated_snapshot_before() -> (Snapshot, String, Vec<PublishElement>, Vec<UpdateElement>, String) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (pub_el, up_el, roa_string) = base_creation();
    let (session_id, serial_number) = repository::get_current_session_notification(&conf);
    let serial_number = serial_number + 1;
    let (snap, snap_uri) = repository::create_current_snapshot(session_id, serial_number, None, false, &conf, None, None);
    (snap, snap_uri, pub_el, up_el, roa_string)
}

// This function generates everything around a manipulated snapshot
pub fn manipulated_snapshot_after(snapshot_content: Bytes, snapshot_uri: String, pub_el: Vec<PublishElement>, up_el: Vec<UpdateElement>) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (session_id, serial) = repository::get_current_session_notification(&conf);
    let serial = serial + 1;
    repository::add_elements_to_delta(pub_el, up_el, session_id, serial, &conf).unwrap();

    let deltas = repository::get_deltas_in_repo(session_id, None, &conf);
    let notification = repository::create_notification(snapshot_content, deltas, &snapshot_uri, 5, session_id, serial, &conf);
    repository::write_notification_file(notification, &conf).unwrap();
}

// Same as snapshot before as delta and snapshot are independently created in the same step
pub fn manipulated_delta_before() -> (Vec<PublishElement>, Vec<UpdateElement>, String) {
    base_creation()
}

// This requires that the delta file was written to disc
// If you want to manipulate hash and/or uri of delta file, use the function to manipulate the notification.xml
pub fn manipulated_delta_after(snapshot: Snapshot, snapshot_uri: String, malicious_delta: repository::DeltaWrapper) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (session_id, serial) = repository::get_current_session_notification(&conf);
    let serial = serial + 1;
    let deltas = repository::get_deltas_in_repo(session_id, Some(vec![malicious_delta]), &conf);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = repository::create_notification(snapshot_bytes, deltas, &snapshot_uri, 5, session_id, serial, &conf);
    repository::write_notification_file(notification, &conf).unwrap();
}

// Create a valid Notification File with a random Roa
pub fn manipulated_notification_before() -> (NotificationFile, repository::DeltaWrapper, String) {
    let conf = repository::create_default_config("my.server.com".to_string());

    let (snapshot, snapshot_uri, pub_el, up_el, roa_string) = manipulated_snapshot_before();
    let (session_id, serial) = repository::get_current_session_notification(&conf);
    let serial = serial + 1;
    repository::add_elements_to_delta(pub_el, up_el, session_id, serial, &conf).unwrap();
    let deltas = repository::get_deltas_in_repo(session_id, None, &conf);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = repository::create_notification(snapshot_bytes, deltas.clone(), &snapshot_uri, 5, session_id, serial, &conf);

    repository::write_notification_file(notification.clone(), &conf).unwrap();

    (notification, deltas[0].clone(), roa_string)
}

// Write NotificationFile xml content to disc
pub fn manipulated_notification_after(vec: &[u8]) {
    let xml = unsafe { str::from_utf8_unchecked(vec.as_ref()) };
    let xml_bytes = xml.as_bytes();
    let file_uri = constants::BASE_RRDP_DIR.to_string() + "notification.xml";
    repository::create_directories(&file_uri);
    fs::write(&file_uri, &xml_bytes).unwrap();
}

// Search the repo iteratively for a path traversal, starting at the base folder
// The parameter folder_structure describes the structure of the file path if the path traversal worked
pub fn search_repo_for_path_traversal(file_name: &str, base_folder: &str, folder_structure: String) -> bool {
    let cwd = get_cwd();

    let mut base = cwd.clone();
    base.push_str("/rp/routinator/rpki-cache/");

    let paths = repository::repository_contains_file(base_folder, file_name, false);
    if paths.len() == 0 {
        println!("No traversal, object was not stored");
        return false;
    }

    for path in paths {
        // If the path to the file contains data/test.delta, we were able to traverse a directory up
        if path.contains(&(folder_structure.clone() + file_name)) {
            println!("Traversal found {}", path);
            return true;
        } else {
            //println!("No traversal for {}", path);
        }
    }
    false
}

// Generate a new Roa from a roa_str as a signed object
pub fn generate_default_signed_roa(roa_str: &str) -> SignedObject_a {
    let conf = repository::create_default_config("my.server.com".to_string());

    let uri = repository::base_repo_uri("newca", &conf);

    let mut roa_uri = uri.clone();

    let filename = repository::file_name_for_object(roa_str, ".roa");
    roa_uri.push_str(filename.as_str());

    let mut crl_uri = uri.clone();

    let cert_key_uri_l = constants::BASE_KEY_DIR.to_string() + "newca.der";
    let s = repository::read_cert_key(&cert_key_uri_l);

    let filename_crl = repository::get_filename_crl_mft(&cert_key_uri_l);
    crl_uri.push_str(&filename_crl);
    crl_uri.push_str(".crl");

    let signer_cer_uri = "rsync://".to_string() + constants::DOMAIN + "/" + constants::BASE_REPO_DIR + "ta/" + &filename_crl + ".cer";

    let issuer_rsync = uri::Rsync::from_str(&signer_cer_uri).unwrap();
    let crl_rsync = uri::Rsync::from_str(crl_uri.as_str()).unwrap();
    let roa_rsync = uri::Rsync::from_str(roa_uri.as_str()).unwrap();

    let (roa_builder, _) = repository::process_roa_string(roa_str).unwrap();

    let so = adapted_functions::overwritten_functions::default_ref_roa(roa_builder, crl_rsync.clone(), issuer_rsync.clone(), roa_rsync.clone(), s, None, &conf);
    so
}

// This is an auxilary function for path-traversal tests
// It checks all RP repos for path-traversals and returns the results
pub fn evaluate_path_traversal(file_name: &str, traversal_string: &str, structure: String) -> (String, String, String) {
    let cwd = get_cwd();

    let base_rout = cwd.clone() + "/rp/routinator/rpki-cache/";
    let base_fort = cwd.clone() + "/rp/fort/base/";
    let base_octo = cwd.clone() + "/rp/octorpki/base/";

    let res_rout = search_repo_for_path_traversal(&file_name, &base_rout, structure.clone());
    let res_fort = search_repo_for_path_traversal(&file_name, &base_fort, structure.clone());
    let res_octo = search_repo_for_path_traversal(&file_name, &base_octo, structure.clone());

    let mut rout_info = "".to_string();
    let mut octo_info = "".to_string();
    let mut fort_info = "".to_string();

    if res_rout {
        rout_info += traversal_string;
        rout_info += ", ";
    }
    if res_octo {
        octo_info += traversal_string;
        octo_info += ", ";
    }
    if res_fort {
        fort_info += traversal_string;
        fort_info += ", ";
    }

    (rout_info, octo_info, fort_info)
}

// Create a default manifest with the repo content as a signed object
pub fn generate_default_signed_mft(hash_algo: Option<&'static digest::Algorithm>) -> SignedObject_a {
    let algo = match hash_algo {
        Some(v) => v,
        None => &digest::SHA256,
    };
    let conf = repository::create_default_config("my.server.com".to_string());

    let serial = repository::random_serial();
    let storage_directory = constants::BASE_REPO_DIR.to_string() + "newca/";
    let snapshot_elements = repository::read_published_elements(Some(".mft".to_string()), storage_directory.as_str(), false, &conf, None);
    let mut vector = vec![];
    for element in &snapshot_elements {
        let file_name = repository::filename_from_uri(element.uri());
        let data = element.data();
        let digest = digest::digest(algo, &data);
        vector.push(FileAndHash::new(file_name, digest));
    }

    let content = ManifestContent::new(serial, Time::now(), Time::tomorrow(), DigestAlgorithm::default(), vector.iter());

    let cert_key_uri_l = constants::BASE_KEY_DIR.to_string() + "newca.der";

    let filename = repository::get_filename_crl_mft(&cert_key_uri_l);

    let storage_base_uri = "rsync://".to_string() + constants::DOMAIN + "/" + constants::BASE_REPO_DIR + "newca/";

    let mut mft_uri = storage_base_uri.clone();
    mft_uri.push_str(&filename);

    let mut crl_uri = mft_uri.clone();

    mft_uri.push_str(".mft");
    crl_uri.push_str(".crl");

    let signer_cer_uri = "rsync://".to_string() + constants::DOMAIN + "/" + constants::BASE_REPO_DIR + "ta/newca.cer";

    let mft_rsync = uri::Rsync::from_str(&mft_uri).unwrap();
    let crl_rsync = uri::Rsync::from_str(&crl_uri).unwrap();
    let issuer_rsync = uri::Rsync::from_str(&signer_cer_uri).unwrap();

    let s = repository::read_cert_key(&cert_key_uri_l);

    let so = adapted_functions::overwritten_functions::default_ref_manifest(content, crl_rsync.clone(), issuer_rsync.clone(), mft_rsync.clone(), s, None);
    so
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub report_id: u32,
    pub report_date: DateTime<Utc>,
    pub test_results: Vec<Vec<TestResult>>,
}

// A report for the test results
impl TestReport {
    pub fn new(test_results: Vec<Vec<TestResult>>) -> TestReport {
        let report_id: u32 = rand::thread_rng().gen_range(0..1000000);
        let report_date: DateTime<Utc> = Utc::now();

        TestReport {
            report_id,
            report_date,
            test_results,
        }
    }

    pub fn file_name(&self) -> String {
        let name = "".to_string() + self.report_id.to_string().as_str() + "_" + self.report_date.date().to_string().as_str() + ".json";
        name
    }

    pub fn create_json(&self) -> String {
        let res = serde_json::to_string_pretty(&self).unwrap();
        res
    }
}

pub struct CustomPublishElement {
    pub uri: String,
    pub data: Bytes,
}

// This describes a custom publish element in the delta file
// Necessary because the PublishElements by the rpki-rs library require a valid rsync uri to parse, but we want to be able to create malicious uris
impl CustomPublishElement {
    pub fn write_xml(&self, content: &mut xml::encode::Content<impl io::Write>) -> Result<(), io::Error> {
        const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
        const PUBLISH: XmlName = XmlName::qualified(NS, b"publish");
        content
            .element(PUBLISH.into_unqualified())?
            .attr("uri", &self.uri)?
            .content(|content| content.base64(self.data.as_ref()))?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_name: String,
    pub rp_client: String,
    pub failed: bool,
    pub information: String,
}

impl TestResult {
    pub fn new(failed: bool, rp_client: &str, information: String, test_name: String) -> TestResult {
        TestResult {
            failed,
            rp_client: rp_client.to_string(),
            information,
            test_name,
        }
    }
}
