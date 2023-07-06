/*
This class contains interface fucntions to ease the creation of the fuzzing environment

*/
use crate::publication_point::{
    repository::{self, KeyAndSigner},
    rp_interaction::{
        self, run_update_fort_p_server, run_update_octorpki_p_server, run_update_routinator_p_server, run_update_rpki_client_p_server,
        RoaContents,
    }, constants,
};

use bytes::Bytes;
use repository::RepoConfig;

use core::panic;
use rand::distributions::{Alphanumeric, DistString};
use std::{any::Any, collections::HashSet, process::Child};

use bcder::{Oid, ConstOid};
use repository::RPConfig;
use rpki::repository::{
    crypto::{softsigner::OpenSslSigner, PublicKey},
    oid,
};

use crate::publication_point::adapted_functions::overwritten_functions;

use rpki::uri;

use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
};
use std::str::FromStr;

use std::time::{Duration, Instant};

use asn1;
use rpki::repository::crypto::softsigner::KeyId;
use serde_json::{Result, Value};

pub fn parse_crl() {
    //asn1::parse(data, f);

    let json_s = r#"{"signature": ["1.2.840.113549.1.1.1", null], "issuer": null, "this_update": null, "next_update": null, "revoked_certs": [], "authority_key_id": "2.5.29.35", "crl_number": 42}"#;
    let v: Value = serde_json::from_str(json_s).unwrap();

    println!("{:?}", v["crl_number"]);
}

pub fn init_everything(base_folder: &str) -> RepoConfig {
    let mut conf = repository::create_default_config_abs("my.server.com".to_string(), base_folder.to_string(), "".to_string());

    let key_uri_2 = conf.BASE_KEY_DIR_l.clone() + "newca2" + ".der";
    repository::make_cert_key(&key_uri_2, "RSA");
    let session_id = repository::initialize_repo(&mut conf, false, None);
    println!("Repo Initialized");
    conf
}

pub fn run_rp_server(rp_name: &str, conf: &RPConfig) -> Child {
    if rp_name == "fort" {
        return run_update_fort_p_server(conf);
    } else if rp_name == "routinator" {
        return run_update_routinator_p_server(conf);
    } else if rp_name == "octorpki" {
        return run_update_octorpki_p_server(conf);
    } else if rp_name == "rpki-client" {
        return run_update_rpki_client_p_server(conf);
    } else {
        panic!("Not supported yet!");
    }
}

pub fn run_rp(rp_name: &str, conf: &RPConfig) -> (Vec<RoaContents>, String) {
    if rp_name == "routinator" {
        return rp_interaction::run_update_routinator_p(conf);
    } else if rp_name == "fort" {
        return rp_interaction::run_update_fort_p(conf);
    } else if rp_name == "octorpki" {
        return rp_interaction::run_update_octorpki_p(conf);
    } else if rp_name == "rpki-client" {
        return rp_interaction::run_update_rpki_client_p(conf);
    } else {
        return (vec![], "".to_string());
    }
}

// Create a certain amount of random ROAs with random names to avoid clashes
pub fn make_random_roas(amount: i32, conf: &RepoConfig) -> (Vec<Bytes>, Vec<String>) {
    let mut set = HashSet::new();
    let mut set_n = HashSet::new();

    for _ in 0..amount {
        let (roa, _) = repository::create_random_roa(&conf);
        let name = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        set.insert(roa);
        set_n.insert(repository::file_name_for_object(&name, ".roa"));
    }
    (set.into_iter().collect(), set_n.into_iter().collect())
}

/*
Generate all required other Objects for a ROA
*/
pub fn generate_for_roas(roa_bytes: Vec<Bytes>, names: Vec<String>, conf: &RepoConfig) {
    repository::after_roas_creation(names, roa_bytes, "ta", conf, true);
}

pub fn generate_keys_for_fuzzing(conf: &RepoConfig, amount: u32) -> Vec<KeyAndSigner> {
    let key_folder = conf.BASE_l.clone() + "fuzzing_keys/";
    let start = Instant::now();

    let mut ee_ks = vec![];

    for i in 7889..amount {
        let filename = key_folder.clone() + &i.to_string();
        let ks = repository::make_cert_key(&filename, "RSA");
        ee_ks.push(ks);
    }

    let duration = start.elapsed();
    // println!("Time elapsed in expensive_function() is: {:?}", duration);
    ee_ks
}

pub fn load_ee_ks_roa(conf: &RepoConfig, amount: u32) -> (Vec<PKey<Private>>, Vec<PublicKey>) {
    let key_folder = conf.BASE_l.clone() + "fuzzing_keys_roa/";
    let signer = OpenSslSigner::new();

    let mut priv_keys = vec![];
    let mut pub_keys = vec![];

    for i in 0..amount {
        let filename = key_folder.clone() + &i.to_string() + "roa";
        let (priv_key, pub_key) = repository::pub_and_priv_key(&filename);

        priv_keys.push(priv_key);
        pub_keys.push(pub_key);
        // let keyid = repository::fill_signer(&filename, &signer);
        // ee_keyids.push(keyid);
    }
    (priv_keys, pub_keys)
}

pub fn load_ee_ks(conf: &RepoConfig, amount: u32, roa: bool) -> (Vec<PKey<Private>>, Vec<PublicKey>) {
    let key_folder = conf.BASE_l.clone() + "fuzzing_keys/";
    let signer = OpenSslSigner::new();

    let mut priv_keys = vec![];
    let mut pub_keys = vec![];

    for i in 0..amount {
        let filename;
        if roa{
            filename = key_folder.clone() + &i.to_string() + "_roa";
        }
        else{
            filename = key_folder.clone() + &i.to_string();
        }
        let (priv_key, pub_key) = repository::pub_and_priv_key(&filename);

        priv_keys.push(priv_key);
        pub_keys.push(pub_key);
        // let keyid = repository::fill_signer(&filename, &signer);
        // ee_keyids.push(keyid);
    }
    (priv_keys, pub_keys)
}

/*
Generate an SignedData Object from encodedContent in DER encoded Bytes, either a Manifest or a ROA
*/
pub fn generate_signed_data_from_bytes(
    content: Bytes,
    conf: &RepoConfig,
    obj_type: &str,
    file_desc: &str,
    valid: bool,
    index: u32,
    ks: &KeyAndSigner,
    ee_key: openssl::pkey::PKey<openssl::pkey::Private>,
    ee_public_key: PublicKey,
    ca_name: &str,
    fixed_name: Option<&str>
) -> Bytes {
    let parent_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/" + ca_name + ".cer";

    let key_uri = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";
    //let ks = repository::read_cert_key(&key_uri);
    //let ks2 = repository::read_cert_key(&key_file);

    let oid_val;
    if obj_type == "roa" {
        oid_val = Oid(oid::ROUTE_ORIGIN_AUTHZ.0.into());
    } else if obj_type == "mft" {
        oid_val = Oid(oid::CT_RPKI_MANIFEST.0.into());
    }
    else if obj_type == "aspa" {
        oid_val = Oid(oid::CT_ASPA.0.into());
    }
    else if obj_type == "gbr" {
        oid_val = Oid(constants::GBR.0.into());
    }
    else {
        panic!("Not supported yet!");
    }

    // Uri of Repo of this CA
    let uri = repository::base_repo_uri(ca_name, conf);

    let mut object_uri = uri.clone();
    let filename;

    if fixed_name.is_some(){
        filename = fixed_name.unwrap().to_string();
    }
    else{
        if obj_type == "roa" {
            filename = repository::file_name_for_object(&file_desc, ".roa");
        } else if obj_type == "mft" {
            filename = repository::get_filename_crl_mft(&key_uri) + ".mft";
            // filename = "lala.mft".to_string();
        }
        else if obj_type == "aspa" {
            filename = repository::file_name_for_object(&file_desc, ".asa");
        }
        else if obj_type == "gbr" {
            filename = repository::file_name_for_object(&file_desc, ".gbr");
        }
        else {
            panic!("Not supported yet!");
        }
    }

    

    object_uri.push_str(filename.as_str());
    let uri_rsync = uri::Rsync::from_str(&object_uri).unwrap();

    let mut crl_uri = uri.clone();

    crl_uri.push_str(repository::get_filename_crl_mft(&key_uri).as_str());
    crl_uri.push_str(".crl");

    let issuer_rsync = uri::Rsync::from_str(&parent_cer_uri).unwrap();
    let crl_rsync = uri::Rsync::from_str(crl_uri.as_str()).unwrap();

    let signed_object = overwritten_functions::signed_object_from_content_bytes_alt(
        oid_val,
        content,
        &ks.signer,
        &ks.keyid.unwrap(),
        crl_rsync,
        issuer_rsync,
        uri_rsync,
        ee_public_key,
        ee_key,
        obj_type,
        conf
    );

    let mut sig = None;
    let c = Bytes::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    if !valid {
        sig = Some(&c);
    }

    let bytes = overwritten_functions::encode_sig_custom(
        signed_object,
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
        sig,
    );

    bytes
}
