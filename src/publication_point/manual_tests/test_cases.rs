use crate::publication_point::constants;
use crate::publication_point::adapted_functions::overwritten_functions;
use crate::repository;
use crate::publication_point::manual_tests::test_util;
use crate::publication_point::manual_tests::test_util::{CustomPublishElement, TestResult};
use std::str::FromStr;

use bcder::encode::{Primitive, PrimitiveContent, Values};
use bcder::{decode, encode, Captured, ConstOid, Ia5String, Mode, OctetString, Oid, Tag};
use bytes::Bytes;
use oid::prelude::*;
use ring::digest;
use rpki::repository::oid as roid;
use rpki::repository::resources::{Asn, Prefix};
use rpki::rrdp::{Delta, DeltaElement, DeltaInfo, Hash, NotificationFile, PublishElement, Snapshot, UpdateElement, UriAndHash};
use rpki::uri;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

pub fn test_fort_open_file() {
    // TODO Fort seems to open files according to Rsync URIs of issuer cert in Roa Cert, look if it checks the validity beforehand
}

// Run all available tests and generate a test report
pub fn run_all_tests() {
    let mut results = vec![];

    results.push(test_wrong_asn());
    results.push(test_mft_unknown_hash_algo());
    results.push(test_mft_unknown_sig_algo());
    results.push(test_mft_sha512_hash_algo());
    results.push(test_mft_sha512rsa_sig_algo());
    //results.push(test_delta_path_traversal());
    //results.push(test_roa_path_traversal());
    let report = test_util::TestReport::new(results);
    let file_name = report.file_name();
    let file_content = report.create_json();
    let path = test_util::get_cwd() + "/" + "reports/";

    fs::create_dir_all(&path);

    fs::write(path + file_name.as_str(), file_content).unwrap();
}

pub fn test_child_ca() {
    let prefix = Prefix::new(Ipv4Addr::new(10, 0, 10, 0), 16);

    test_util::create_child_ca(prefix, 10, 30);

    let conf = repository::create_default_config("my.server.com".to_string());

    let roa_str = repository::generate_random_roa_string(10, 0, 0, 0);

    let (b, _) = repository::process_roa_string(&roa_str).unwrap();

    let parent_cer_uri = "rsync://".to_string() + constants::DOMAIN + "/" + constants::BASE_REPO_DIR + "newca/malca.cer";

    let roa_base_uri = repository::base_repo_uri("malca", &conf);

    repository::add_roa(&roa_str, roa_base_uri, "malca", &parent_cer_uri, &conf);

    let results = test_util::run_all_rps(
        Some(Ipv4Addr::new(10, 0, 0, 0)),
        Some(24),
        Some(b.as_id().into_u32()),
        false,
        "Sig-Algo Test".to_string(),
    );
    print_results(results, "check");
}

// This function checks if every RP client works as expected by doing a normal RRDP run and checking if everything worked
pub fn sanity_check() -> bool {
    //repository::initialize_repo();

    let roa_string = "10.0.0.0/24 => 13959";
    test_util::add_roa_wrapper(&roa_string);

    let results = test_util::run_all_rps(
        Some(Ipv4Addr::new(10, 0, 0, 0)),
        Some(24),
        Some(13959),
        true,
        "Sanity Check".to_string(),
    );
    print_results(results.clone(), "Sanity check");
    if results[0].failed {
        println!("Routinator failed!");
        return false;
    }
    if results[1].failed {
        println!("Octorpki failed!");
        return false;
    }
    if results[2].failed {
        println!("Fort failed!");
        return false;
    }
    println!("Everything worked!");
    return true;
}

// Test if the clients detect if the ASN of a ROA is within the range allowed by the issuer certificate
// Note: The RFC does not specify that the ROA ASN has to be within the range of the cert
pub fn test_wrong_asn() -> Vec<TestResult> {
    let roa_string = "10.0.0.0/24 => 42000";
    test_util::add_roa_wrapper(&roa_string);

    let roa_string = "10.0.0.0/24 => 42001";
    test_util::add_roa_wrapper(&roa_string);

    let results = test_util::run_all_rps(
        Some(Ipv4Addr::new(10, 0, 0, 0)),
        Some(24),
        Some(42000),
        false,
        "Wrong ASN".to_string(),
    );

    print_results(results.clone(), "Wrong ASN");

    results
}

pub fn print_results(results: Vec<test_util::TestResult>, test_name: &str) {
    println!("Results for test {}", test_name);
    if results[0].failed == true {
        println!("\t !!!-> Test delivered UNEXPECTED results for Routinator");
    } else {
        println!("\t ----> Test delivered EXPECTED results for Routinator");
    }
    if results[1].failed == true {
        println!("\t !!!-> Test delivered UNEXPECTED results for Octorpki");
    } else {
        println!("\t ----> Test delivered EXPECTED results for Octorpki");
    }
    if results[2].failed == true {
        println!("\t !!!-> Test delivered UNEXPECTED results for Fort");
    } else {
        println!("\t ----> Test delivered EXPECTED results for Fort");
    }
    println!("");

    println!("\t Routinator Ouput: {}\n", results[0].information);
    println!("\t Octorpki Ouput: {}\n", results[1].information);
    println!("\t Fort Ouput: {}\n", results[2].information);
}

// Test the behaviour to an unknown hash algorithm identifier
pub fn test_mft_wrong_signature() {
    //repository::initialize_repo();

    let (roa_content, roa_string, so, mfb, crb, crl_content) = test_util::manipulated_mft_before(None);

    let fake_sig = "ffffffffffffffffffffff";
    let fake_sig_b = Bytes::from(fake_sig);

    let re = overwritten_functions::encode_sig_custom(
        so,
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
        Some(&fake_sig_b),
    );
    test_util::manipulated_mft_after(re, roa_content, &roa_string, mfb, crb, crl_content);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();
    // let results = test_util::run_all_rps(Some(ip), Some(24), Some(asid.into_u32()), false, "Wrong Signature".to_string());

    // print_results(results.clone(), "Wrong Signature");

    // results
}

// Test the behaviour to an unknown hash algorithm identifier
pub fn test_mft_unknown_hash_algo() -> Vec<TestResult> {
    //repository::initialize_repo();

    let (roa_content, roa_string, so, mfb, crb, crl_content) = test_util::manipulated_mft_before(None);

    // Real oid: "2.16.840.1.101.3.4.2.1"
    // Defined in RFC4055
    let fake_oid_val = "2.16.840.1.102.3.4.2.1";

    let (fake_bytes, fake_bytes_set) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
        None,
        None,
        None,
        Some(fake_bytes_set.clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(fake_bytes),
        None,
        None,
        None,
    );
    test_util::manipulated_mft_after(re, roa_content, &roa_string, mfb, crb, crl_content);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();
    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "Unknown Hash Algorithm".to_string(),
    );

    print_results(results.clone(), "Unknown Hash Algorithm");

    results
}

// Test the behaviour to an unsupported algorithm identifier
pub fn test_mft_sha512_hash_algo() -> Vec<TestResult> {
    let mut conf = repository::create_default_config("my.server.com".to_string());

    repository::initialize_repo(&mut conf, true, None);

    let (roa_content, roa_string, so, mfb, crb, crl_content) = test_util::manipulated_mft_before(Some(&digest::SHA512));

    // Real oid: "2.16.840.1.101.3.4.2.1"
    // Defined in RFC4055

    // OID of sha512
    let fake_oid_val = "2.16.840.1.101.3.4.2.3";
    let (fake_bytes, fake_bytes_set) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
        None,
        None,
        None,
        Some(fake_bytes_set.clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(fake_bytes),
        None,
        None,
        None,
    );

    test_util::manipulated_mft_after(re, roa_content, &roa_string, mfb, crb, crl_content);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();
    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "SHA512 Hash Algorithm".to_string(),
    );

    print_results(results.clone(), "SHA512 Hash Algorithm");
    results
}

// Test the behaviour to an unknown signature algorithm identifier
pub fn test_mft_unknown_sig_algo() -> Vec<TestResult> {
    let mut conf = repository::create_default_config("my.server.com".to_string());

    repository::initialize_repo(&mut conf, true, None);

    let (roa_content, roa_string, so, mfb, crb, crl_content) = test_util::manipulated_mft_before(None);

    // Real oid: "1.2.840.113549.1.1.11"
    // Defined in RFC4055

    let fake_oid_val = "2.2.840.113549.1.1.11";
    let (fake_bytes, fake_bytes_set) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
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
        Some(fake_bytes),
        None,
    );

    test_util::manipulated_mft_after(re, roa_content, &roa_string, mfb, crb, crl_content);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();
    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "Unknown Signature Algorithm".to_string(),
    );
    print_results(results.clone(), "Unknown Signature Algorithm");
    results
}

// Test the behaviour to an unsupported signature algorithm identifier
pub fn test_mft_sha512rsa_sig_algo() -> Vec<TestResult> {
    let mut conf = repository::create_default_config("my.server.com".to_string());

    repository::initialize_repo(&mut conf, true, None);

    let (roa_content, roa_string, so, mfb, crb, crl_content) = test_util::manipulated_mft_before(None);

    // Real oid: "1.2.840.113549.1.1.11"
    // Defined in RFC4055

    // OID of sha512withRsaEncryption
    let fake_oid_val = "1.2.840.113549.1.1.13";
    let (fake_bytes, fake_bytes_set) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
        None,
        None,
        None,
        Some(fake_bytes_set.clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(fake_bytes),
        None,
        None,
        None,
    );

    test_util::manipulated_mft_after(re, roa_content, &roa_string, mfb, crb, crl_content);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();
    let results = test_util::run_all_rps(Some(ip), Some(16), Some(asid.into_u32()), false, "SHA512RSA Algorithm".to_string());

    print_results(results.clone(), "SHA512RSA Algorithm");

    results
}

// Test if the clients are vulnerable to a path traversal over the ROA URI
pub fn test_roa_path_traversal() -> Vec<TestResult> {
    test_util::run_all_rps(None, None, None, false, "".to_string());

    let traversal_strings: Vec<&str> = constants::TRAVERSAL_STRINGS.split(",").collect();

    let test_name = "RRDP Path Traversal".to_string();

    let cwd = test_util::get_cwd();

    let base_info = "Found Path Traversal for: ".to_string();

    let mut rout_info = base_info.clone();
    let mut octo_info = base_info.clone();
    let mut fort_info = base_info.clone();

    let structure = "test/".to_string();

    for i in 0..traversal_strings.len() {
        let ind_tmp = i.to_string();
        let ind = ind_tmp.as_str();

        let mut conf = repository::create_default_config("my.server.com".to_string());

        repository::initialize_repo(&mut conf, true, None);
        test_util::run_all_rps(None, None, None, false, "".to_string());
        let (pub_el, up_el, roa_string) = test_util::manipulated_delta_before();

        let (by, _) = repository::create_random_roa(&conf);

        // Write the ROA into the repo so it will also be contained in the Snapshot
        let uri_l = cwd.clone() + "/" + constants::BASE_REPO_DIR + "test/a/test" + ind + ".roa";
        let uri_l2 = cwd.clone() + "/" + constants::BASE_REPO_DIR + "test/a/" + ind + ".roa";
        fs::create_dir_all(&(cwd.clone() + "/" + constants::BASE_REPO_DIR + "test/a/")).unwrap();
        fs::write(uri_l, &by).unwrap();
        fs::write(uri_l2, &by).unwrap();

        let (session_id, serial_number) = repository::get_current_session_notification(&conf);
        let serial_number = serial_number + 1;
        let (snap, snap_uri) = repository::create_current_snapshot(session_id, serial_number, None, true, &conf, None, None);

        // Generate a new, custom delta which includes all the published elements + a new manipulated ROA
        let uri = "rsync://".to_string()
            + constants::DOMAIN
            + "/"
            + constants::BASE_RRDP_DIR
            + "test/a/"
            + &traversal_strings[i]
            + "test"
            + ind
            + ".roa";

        // Create a new custom publish element to publish ROA in the delta file
        let element = CustomPublishElement {
            uri: uri.clone(),
            data: by,
        };
        let elements = vec![element];

        let (session_id, serial) = repository::get_current_session_notification(&conf);
        let serial = serial + 1;
        let delta = repository::create_delta_from_elements(pub_el, up_el, session_id, serial);

        let mut writer = vec![];
        overwritten_functions::write_xml_delta(delta.clone(), elements, &mut writer).unwrap();

        let mut file_uri = repository::uri_from_session_and_serial_random(session_id, serial, &conf);
        file_uri.push_str("delta.xml");
        repository::create_directories(&file_uri.to_string());

        let xml = unsafe { str::from_utf8_unchecked(writer.as_ref()) };
        let xml_bytes = xml.as_bytes();

        fs::write(&file_uri, xml_bytes).unwrap();

        // Need to generate Hash here because the malicious Delta file can not be parsed
        let hash = Hash::from_data(xml_bytes);
        let dau = repository::DeltaWrapper {
            delta,
            uri: file_uri,
            hash,
        };

        test_util::manipulated_delta_after(snap, snap_uri, dau);

        let _ = test_util::run_all_rps(None, None, None, false, "Roa Path Traversal".to_string());

        let file_name = "test".to_string() + ind + ".roa";

        let (r, o, f) = test_util::evaluate_path_traversal(&file_name, &traversal_strings[i], structure.clone());

        rout_info += &r;
        octo_info += &o;
        fort_info += &f;
    }

    let rout_expected = rout_info == base_info;
    let octo_expected = octo_info == base_info;
    let fort_expected = fort_info == base_info;

    let result_rout = TestResult::new(rout_expected, "Routinator", rout_info.to_string(), test_name.clone());
    let result_octo = TestResult::new(octo_expected, "Octorpki", octo_info.to_string(), test_name.clone());
    let result_fort = TestResult::new(fort_expected, "Fort", fort_info.to_string(), test_name.clone());

    let results = vec![result_rout, result_octo, result_fort];
    results
}

pub fn test_notification_serial() {
    let mut conf = repository::create_default_config("my.server.com".to_string());

    repository::initialize_repo(&mut conf, true, None);

    let (notification, delta, roa_string) = test_util::manipulated_notification_before();
    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let fake_serial = ("serial", "420".to_string());

    let mut writer = vec![];

    overwritten_functions::write_xml_notification(notification, None, None, None, Some(fake_serial), None, None, &mut writer).unwrap();

    test_util::manipulated_notification_after(&writer);

    let results = test_util::run_all_rps(Some(ip), Some(24), Some(asid.into_u32()), false, "Serial".to_string());

    print_results(results, "Serial");
}

pub fn test_notification_session() {
    let mut conf = repository::create_default_config("my.server.com".to_string());

    repository::initialize_repo(&mut conf, true, None);

    let (notification, delta, roa_string) = test_util::manipulated_notification_before();
    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let fake_session = ("session", "abcd-eeee".to_string());

    let mut writer = vec![];

    overwritten_functions::write_xml_notification(notification, None, None, Some(fake_session), None, None, None, &mut writer).unwrap();

    test_util::manipulated_notification_after(&writer);

    let results = test_util::run_all_rps(Some(ip), Some(24), Some(asid.into_u32()), false, "Session".to_string());

    print_results(results, "Session");
}

pub fn test_notification_version() {
    let mut conf = repository::create_default_config("my.server.com".to_string());

    repository::initialize_repo(&mut conf, true, None);

    let (notification, delta, roa_string) = test_util::manipulated_notification_before();
    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let fake_version = ("version", "42".to_string());

    let mut writer = vec![];

    overwritten_functions::write_xml_notification(notification, None, Some(fake_version), None, None, None, None, &mut writer).unwrap();

    test_util::manipulated_notification_after(&writer);

    let results = test_util::run_all_rps(Some(ip), Some(24), Some(asid.into_u32()), false, "Session".to_string());

    print_results(results, "Session");
}

// Test the behaviour to an unknown signature algorithm identifier
pub fn test_roa_unknown_sig_algo() -> Vec<TestResult> {
    //repository::initialize_repo();
    // TOOD Actually generate the object hash / signature with the newer algorithm to see what happens

    let conf = repository::create_default_config("my.server.com".to_string());

    let roa_string = repository::generate_random_roa_string(10, 0, 0, 0);

    let so = test_util::generate_default_signed_roa(&roa_string);
    // Real oid: "1.2.840.113549.1.1.11"
    // Defined in RFC4055

    let fake_oid_val = "2.2.840.113549.1.1.11";
    let (fake_bytes, _) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
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
        Some(fake_bytes),
        None,
    );

    repository::write_object_to_disc(&re, "roa", &roa_string, "newca", &conf);

    test_util::manipulated_roa_after(&roa_string, re);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "Unknown Signature Algorithm".to_string(),
    );
    print_results(results.clone(), "Roa unknown Signature Algorithm");
    results
}

// Test the behaviour to an unknown signature algorithm identifier
pub fn test_roa_sha512rsa_sig_algo() -> Vec<TestResult> {
    //repository::initialize_repo();
    let conf = repository::create_default_config("my.server.com".to_string());

    let roa_string = repository::generate_random_roa_string(0, 0, 0, 0);

    let so = test_util::generate_default_signed_roa(&roa_string);
    // Real oid: "1.2.840.113549.1.1.11"
    // Defined in RFC4055

    let fake_oid_val = "1.2.840.113549.1.1.13";
    let (fake_bytes, _) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
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
        Some(fake_bytes),
        None,
    );

    repository::write_object_to_disc(&re, "roa", &roa_string, "newca", &conf);

    test_util::manipulated_roa_after(&roa_string, re);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "Sha512RSA Signature Algorithm".to_string(),
    );
    print_results(results.clone(), "Unknown Signature Algorithm");
    results
}

pub fn test_roa_sha512_hash_algo() -> Vec<TestResult> {
    let conf = repository::create_default_config("my.server.com".to_string());

    let roa_string = repository::generate_random_roa_string(10, 0, 0, 0);

    let so = test_util::generate_default_signed_roa(&roa_string);

    let fake_oid_val = "2.16.840.1.101.3.4.2.3";
    let (fake_bytes, fake_bytes_set) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
        None,
        None,
        None,
        Some(fake_bytes_set.clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(fake_bytes),
        None,
        None,
        None,
    );

    repository::write_object_to_disc(&re, "roa", &roa_string, "newca", &conf);

    test_util::manipulated_roa_after(&roa_string, re);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "Roa Sha512 Hash Algorithm".to_string(),
    );

    print_results(results.clone(), "Unknown Hash Algorithm Roa");

    results
}

pub fn test_roa_unknown_hash() -> Vec<TestResult> {
    let conf = repository::create_default_config("my.server.com".to_string());

    let roa_string = repository::generate_random_roa_string(10, 0, 0, 0);

    let so = test_util::generate_default_signed_roa(&roa_string);

    let fake_oid_val = "2.16.840.1.102.3.4.2.1";
    let (fake_bytes, fake_bytes_set) = test_util::create_oid(&fake_oid_val);

    let re = overwritten_functions::encode_sig_custom(
        so,
        None,
        None,
        None,
        Some(fake_bytes_set.clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(fake_bytes),
        None,
        None,
        None,
    );

    repository::write_object_to_disc(&re, "roa", &roa_string, "newca", &conf);

    test_util::manipulated_roa_after(&roa_string, re);

    let (roa, ip) = repository::process_roa_string(&roa_string).unwrap();
    let asid = roa.as_id();

    let results = test_util::run_all_rps(
        Some(ip),
        Some(24),
        Some(asid.into_u32()),
        false,
        "Roa unknown Hash Algorithm".to_string(),
    );

    print_results(results.clone(), "Roa unknown Hash Algorithm Roa");

    results
}

// Test if the clients are vulnerable to a path traversal over the Delta URI
pub fn test_delta_path_traversal() -> Vec<TestResult> {
    test_util::run_all_rps(None, None, None, false, "".to_string());

    let traversal_strings: Vec<&str> = constants::TRAVERSAL_STRINGS.split(",").collect();

    let test_name = "Delta Path Traversal".to_string();

    let base_info = "Found Path Traversal for: ".to_string();

    let mut rout_info = base_info.clone();
    let mut octo_info = base_info.clone();
    let mut fort_info = base_info.clone();

    let cwd = test_util::get_cwd();

    let structure = "test/".to_string();

    for i in 0..traversal_strings.len() {
        let mut conf = repository::create_default_config("my.server.com".to_string());

        repository::initialize_repo(&mut conf, true, None);
        test_util::run_all_rps(None, None, None, false, "".to_string());

        let ind_tmp = i.to_string();
        let ind = ind_tmp.as_str();

        let (notification, delta, roa_string) = test_util::manipulated_notification_before();

        let session = delta.delta.session_id();
        let serial = delta.delta.serial();
        let elements = delta.delta.into_elements();

        // Create two delta files so the rp can always pull one, if the traversal works or does not work
        repository::write_delta_file(
            repository::create_delta(session, serial, elements.clone()),
            &(cwd.clone() + "/" + constants::BASE_RRDP_DIR + "test/a/" + "../test" + ind + ".delta"),
        )
        .unwrap();

        repository::write_delta_file(
            repository::create_delta(session, serial, elements),
            &(cwd.clone() + "/" + constants::BASE_RRDP_DIR + "test/a/" + "test" + ind + ".delta"),
        )
        .unwrap();

        let del_ref = &notification.deltas()[0];

        let del_serial = del_ref.serial();
        let del_hash = del_ref.hash();

        // Now we create a new uri with the path traversal
        // Place a path traversal in the uri of the delta file in the notification.xml file, to check if it is properly escaped or not stored anywhere
        let uri = "https://".to_string()
            + constants::DOMAIN
            + "/"
            + constants::BASE_RRDP_DIR
            + "test/a/"
            + &traversal_strings[i]
            + "test"
            + ind
            + ".delta";

        // Add a custom Delta with the path traversal in its URI
        let mut deltas = vec![];
        let delta = vec![("serial", del_serial.to_string()), ("uri", uri), ("hash", del_hash.to_string())];
        deltas.push(delta);

        // Now write a manipulated notifcation file with the changed delta
        let mut writer = vec![];
        overwritten_functions::write_xml_notification(notification, None, None, None, None, None, Some(deltas), &mut writer).unwrap();

        test_util::manipulated_notification_after(&writer);

        test_util::run_all_rps(None, None, None, false, "Delta Path Traversal".to_string());

        let file_name = "test".to_string() + ind + ".delta";

        let (r, o, f) = test_util::evaluate_path_traversal(&file_name, &traversal_strings[i], structure.clone());

        rout_info += &r;
        octo_info += &o;
        fort_info += &f;
    }

    let rout_expected = rout_info == base_info;
    let octo_expected = octo_info == base_info;
    let fort_expected = fort_info == base_info;

    let result_rout = TestResult::new(rout_expected, "Routinator", rout_info.to_string(), test_name.clone());
    let result_octo = TestResult::new(octo_expected, "Octorpki", octo_info.to_string(), test_name.clone());
    let result_fort = TestResult::new(fort_expected, "Fort", fort_info.to_string(), test_name.clone());

    let results = vec![result_rout, result_octo, result_fort];
    results
}
