use std::fs;

use bcder::{encode::Values, Mode};
use bytes::Bytes;
use chrono::Utc;

use crate::{
    consts,
    publication_point::repository::{self, KeyAndSigner},
    util,
};
use hex::FromHex;

use asn1_generator;

pub fn create_normal_repo() {
    let mut con = repository::create_default_config(consts::domain.to_string());
    repository::initialize_repo(&mut con, false, None);

    for i in 0..10 {
        let roa_string = con.DEFAULT_IPSPACE_FIRST_OCTET.to_string()
            + "."
            + &con.DEFAULT_IPSPACE_SEC_OCTET.to_string()
            + &".0.0/24 => ".to_string()
            + &i.to_string();
        repository::add_roa_str(&roa_string, true, &con);
    }
}

pub fn test_run() -> bool {
    println!("Info: Running Testrun to check if RPs work correctly...");

    create_normal_repo();
    util::run_rp_processes("info");
    let v = vec!["Routinator", "OctoRPKI", "Fort", "RPKI-Client"];

    let (vrps, _, _, cont) = util::get_rp_vrps();
    let mut fault = false;
    for i in 0..cont.len() {
        if cont[i].len() != 10 {
            println!("!--> Error in Testrun. {} doesnt seem to work correctly!!", v[i]);
            fault = true;
        }
    }
    if fault {
        println!("Debug Info VRPS:\n {:}", vrps);
        println!("!--> Error in Testrun. Fix RPs before running fuzzer!!");
        println!("Maybe webserver points to wrong location or permission problems on a cache folder?");
    }

    println!("Info: Testrun sucesful");
    util::clear_caches();

    fault
}

pub fn initialize_fuzzer() -> bool {
    util::clear_caches();
    let err = test_run();

    return err;
}

#[derive(PartialEq)]
pub enum OpType {
    MFT,
    ROA,
    CRL,
    CERTCA,
    CERTEE,
    SNAP,
    NOTI,
    ASPA,
    GBR,
}

pub fn test_generation() {
    util::create_example_roas(1);
    let conf = repository::create_default_config(consts::domain.to_string());

    let file_content = fs::read("./example.roa").unwrap();
    let mut tree = asn1_generator::connector::new_tree(file_content);

    // Fix encapContent Hash
    let data = tree.get_data_by_label("encapsulatedContent").unwrap();
    println!("Da {:?}", data);

    let hash = sha256::digest(&*data);
    let hash = <[u8; 32]>::from_hex(hash).unwrap().to_vec();
    println!("Hash {:?}", hash[0..20].to_vec());

    tree.set_data_by_label("messageDigest", hash, true);

    // Fix subjectKeyIdentifier and authorityKeyIdentifier
    let (parent_key, child_key) = load_key();
    let sub_key_id = <[u8; 20]>::from_hex(child_key.get_pub_key().key_identifier().to_string())
        .unwrap()
        .to_vec();

    let par_key_id = <[u8; 20]>::from_hex(parent_key.get_pub_key().key_identifier().to_string())
        .unwrap()
        .to_vec();

    tree.set_data_by_label("subjectKeyIdentifier", sub_key_id.clone(), true);
    tree.set_data_by_label("authorityKeyIdentifier", par_key_id.clone(), true);

    // Fix issuer name and subject name
    tree.set_data_by_label(
        "issuerName",
        parent_key.get_pub_key().key_identifier().to_string().as_bytes().to_vec(),
        true,
    );
    tree.set_data_by_label(
        "subjectName",
        child_key.get_pub_key().key_identifier().to_string().as_bytes().to_vec(),
        true,
    );

    // Fix SID in signedAttributes
    tree.set_data_by_label("signerIdentifier", sub_key_id, true);

    let mut new_bits: Vec<u8> = vec![0];
    new_bits.extend(child_key.get_pub_key().bits().to_vec());
    tree.set_data_by_label("subjectPublicKey", new_bits, true);

    // Fix time
    let now = Utc::now();
    let twenty_four_hours_ago = now - chrono::Duration::hours(24);
    let utc_time_string = twenty_four_hours_ago.format("%y%m%d%H%M%SZ").to_string();
    let not_before: Vec<u8> = utc_time_string.as_bytes().to_vec();

    let in_three_days = now + chrono::Duration::hours(72);
    let utc_time_string = in_three_days.format("%y%m%d%H%M%SZ").to_string();
    let not_after: Vec<u8> = utc_time_string.as_bytes().to_vec();

    tree.set_data_by_label("notBefore", not_before, true);
    tree.set_data_by_label("notAfter", not_after, true);

    // Fix CRL Location
    let storage_base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + &conf.CA_NAME + "/";
    let cert_key_uri = "data/keys/".to_string() + &conf.CA_NAME + ".der";
    let filename = repository::get_filename_crl_mft(&cert_key_uri);
    let crl_uri = storage_base_uri.clone() + &filename + ".crl";

    tree.set_data_by_label("crlDistributionPoint", crl_uri.as_bytes().to_vec(), true);

    tree.fix_sizes(true);

    // Fix signature on signedAttributes
    let data = tree.get_data_by_label("signerSignedAttributesField").unwrap();
    let data = data[2..].to_vec(); // Remove first two bytes because we need to change them

    let len = data.len();
    let mut res = Vec::with_capacity(len + 4);
    res.push(0x31); // SET
    if len < 128 {
        res.push(len as u8)
    } else if len < 0x10000 {
        res.push(2);
        res.push((len >> 8) as u8);
        res.push(len as u8);
    } else {
        res.push(3);
        res.push((len >> 16) as u8);
        res.push((len >> 8) as u8);
        res.push(len as u8);
    }
    res.extend_from_slice(data.as_ref());

    let sig = child_key.sign(&res).to_vec();
    tree.set_data_by_label("signerSignature", sig, true);

    // Fix signature on certificate
    let data = tree.encode_node(&tree.get_node_by_label("certificate").unwrap());
    let sig = parent_key.sign(&data).to_vec();
    let mut sig_bits: Vec<u8> = vec![0];
    sig_bits.extend(sig);

    tree.set_data_by_label("certificateSignature", sig_bits, true);

    // Make sure all ASN.1 sizes are correct
    tree.fix_sizes(true);

    // Write Object to Disc
    let conf = repository::create_default_config(consts::domain.to_string());

    println!("Data {}", base64::encode(tree.encode_tree()));
    let roa_content = Bytes::from(tree.encode_tree());

    let roa_string = "10.0.0.0/24 => 0";

    repository::write_object_to_disc(&roa_content, "roa", roa_string, "newca", &conf);

    let base_uri = repository::base_repo_uri(&conf.CA_NAME, &conf);

    repository::after_roa_creation(roa_string, base_uri, "newca", roa_content, false, &conf);

    // run rps
    util::run_rp_processes("info");
    // get vrps
    let (vrps, _, _, _) = util::get_rp_vrps();

    println!("{}", vrps);
}

pub fn load_key() -> (KeyAndSigner, KeyAndSigner) {
    let key_uri = "data/keys/newca.der";

    let ks = repository::read_cert_key(&key_uri);
    let key_uri2 = "fuzzing_keys/0_roa";
    let ks2 = repository::read_cert_key(&key_uri2);

    (ks, ks2)
}
