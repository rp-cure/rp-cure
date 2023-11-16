use std::{fs, time::Instant};

use bcder::{encode::Values, Mode};
use bytes::Bytes;
use chrono::Utc;
use rpki::repository::crypto::digest::sha1_digest;
use sha1::Sha1;

use crate::{
    consts,
    fuzzing_repo::{self, FuzzingObject, RepoInfo},
    publication_point::repository::{self, KeyAndSigner},
    util,
};
use asn1_generator;
use asn1_generator::parser::Tree;
use hex::FromHex;
use sha1::Digest;

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

pub fn create_asn1(tag: u8, data: Vec<u8>) {}

pub fn create_hash_list() {
    let name = "FB203CF59A2BAF2435CFD6E73A2F76786D797A28.crl";

    let value = b"0x124353";

    // asn1::parse_single(data);

    // asn1::Tlv::from(value)
}

// Adapt all fields of an object
pub fn initial_fix() {}

pub fn full_test() {
    let conf = repository::create_default_config(consts::domain.to_string());

    let parent_key_roa = load_key().0;
    let subject_key_roa = load_key().1;
    let subject_key_mft = repository::read_cert_key("data/keys/0.der");
    let subject_key_crl = repository::read_cert_key("data/keys/0.der");

    let subject_key_cert = repository::read_cert_key("data/keys/newca.der");

    let root_key = repository::read_cert_key("data/keys/ta.der");

    let key_uri = "data/keys/newca.der";

    let parent_key_mft = repository::read_cert_key(&key_uri);
    let parent_key_crl = repository::read_cert_key(&key_uri);

    let roa = fs::read("./example.roa").unwrap();
    let mft = fs::read("./example.mft").unwrap();
    let crl = fs::read("./example.crl").unwrap();
    let cert = fs::read("./example.cer").unwrap();

    let roa_tree = asn1_generator::connector::new_tree(roa, "roa");
    let mft_tree = asn1_generator::connector::new_tree(mft, "mft");
    let crl_tree = asn1_generator::connector::new_tree(crl, "crl");
    let cert_tree = asn1_generator::connector::new_tree(cert, "cert");

    let mut froa = FuzzingObject::new(
        OpType::ROA,
        parent_key_roa,
        subject_key_roa,
        roa_tree,
        "example.roa".to_string(),
        conf.clone(),
    );

    let filename_mft = repository::get_filename_crl_mft(&key_uri);

    let crl_uri = filename_mft.clone() + ".crl";
    let mft_uri = filename_mft.clone() + ".mft";

    let mut fmft = FuzzingObject::new(OpType::MFT, parent_key_mft, subject_key_mft, mft_tree, mft_uri, conf.clone());

    let mut fcrl = FuzzingObject::new(OpType::CRL, parent_key_crl, subject_key_crl, crl_tree, crl_uri, conf.clone());

    let mut fcer = FuzzingObject::new(
        OpType::CERTCA,
        root_key,
        subject_key_cert,
        cert_tree,
        "example.cer".to_string(),
        conf.clone(),
    );

    let mut repo = fuzzing_repo::FuzzingRepository {
        payloads: vec![froa],
        manifest: fmft,
        crl: fcrl,
        conf,
        certificate: fcer,
        repo_info: RepoInfo::default(),
    };

    repo.fix_all_objects(true);
    repo.mutate_objects(1);
    repo.write_to_disc();
    repo.update_parent();
    util::run_rp_processes("info");
    let (vrps, _, _, _) = util::get_rp_vrps();
    println!("{}", vrps);
}

pub fn test_generation() {
    let conf = repository::create_default_config(consts::domain.to_string());

    // let file_content = fs::read("./example.mft").unwrap();
    // let mut tree = asn1_generator::connector::new_tree(file_content, "mft");

    // let mut fo = FuzzingObject::new(OpType::MFT, load_key().0, load_key().1, tree, "example.mft".to_string(), conf);

    let file_content = fs::read("./example.roa").unwrap();
    let mut tree = asn1_generator::connector::new_tree(file_content, "roa");

    let mut fo = FuzzingObject::new(OpType::ROA, load_key().0, load_key().1, tree, "example.roa".to_string(), conf);

    fo.fix_fields(true, None);
    fo.fix_fields(true, None);

    let before = Instant::now();
    for i in 0..1 {
        // fo.mutate();
    }
    let end = before.elapsed();
    println!("Elapsed time {:?}", end);

    // println!("Mutations {:?}", fo.tree.mutations);

    // println!("{}", base64::encode(fo.tree.encode()));
    let roa_content = Bytes::from(fo.tree.encode());

    let roa_string = "10.0.0.0/24 => 1776";

    repository::write_object_to_disc(&roa_content, "roa", roa_string, "newca", &fo.conf);

    let base_uri = repository::base_repo_uri(&fo.conf.CA_NAME, &fo.conf);

    repository::after_roa_creation(roa_string, base_uri, "newca", roa_content, false, &fo.conf);

    // run rps
    util::run_rp_processes("info");
    // get vrps
    let (vrps, _, _, _) = util::get_rp_vrps();

    println!("{}", vrps);
}

pub fn test_repository() {}

pub fn load_key() -> (KeyAndSigner, KeyAndSigner) {
    let key_uri = "data/keys/newca.der";

    let ks = repository::read_cert_key(&key_uri);
    let key_uri2 = "fuzzing_keys/0_roa";
    let ks2 = repository::read_cert_key(&key_uri2);

    (ks, ks2)
}
