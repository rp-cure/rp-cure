use crate::coverage_interface;
use crate::fuzzing::processing;
use crate::generation_interface::OpType;
use crate::process_util;
use crate::process_util::CoverageObject;
use crate::process_util::ObjectFactory;
use crate::process_util::SerializableObject;
use crate::publication_point::fuzzing_interface::generate_for_roas;
use crate::publication_point::fuzzing_interface::load_ee_ks;
use crate::publication_point::repository::after_roas_creation;
use crate::publication_point::repository::KeyAndSigner;
use crate::FuzzConfig;
use bcder::encode::Values;
use bcder::Mode;
use bytes::Bytes;
use core::panic;
use ipnet::Ipv4Net;
use rand::{thread_rng, Rng};
use regex::Regex;
use rpki::repository::crypto::DigestAlgorithm;
use rpki::repository::crypto::PublicKey;
use rpki::repository::manifest::FileAndHash;
use rpki::repository::manifest::ManifestContent;
use rpki::repository::resources;
use rpki::repository::resources::Asn;
use rpki::repository::resources::IpBlock;
use rpki::repository::resources::Prefix;
use rpki::repository::x509::Time;
use std::cmp::min;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::fs::metadata;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::process::Child;
use std::vec;

use crate::publication_point::fuzzing_interface;
use crate::publication_point::repository;
use crate::publication_point::repository::RepoConfig;

use crate::publication_point::repository::RPConfig;
use std::process::Command;
use std::{env, str};

use crate::publication_point::rp_interaction::RoaContents;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use rpki::repository::crypto::softsigner::KeyId;
use rpki::repository::{crypto::softsigner::OpenSslSigner, oid};
use std::thread;

use chrono;
use rand::distributions::Alphanumeric;
use std::fs::read_dir;

use crate::publication_point::rp_interaction;

pub fn read_rp_log(rp_name: &str) -> String {
    let cws = get_cwd() + "/";

    let rp_output_raw = fs::read_to_string(cws.clone() + "output/" + rp_name + ".error");
    if rp_output_raw.is_err() {
        println!(
            "Error in reading rp log. Filename: {}, Error: {}",
            cws.clone() + "output/" + rp_name + ".error",
            rp_output_raw.err().unwrap()
        );
        return "".to_string();
    } else {
        return rp_output_raw.unwrap();
    }
}

pub fn create_cas(amount: u32, confs: Vec<&RepoConfig>, notification_uris: Option<Vec<String>>) -> (Vec<KeyAndSigner>, RepoConfig) {
    // If amount is negative -> Use individual configs
    // If amount is positive -> Use same config for [amount] CAs
    if amount == 0 {}

    let iteration_amount = match amount == 0 {
        true => confs.len(),
        false => amount.try_into().unwrap(),
    };

    let mut cert_keys = vec![];

    // Use default conf to track CA-Tree because otherwise borrowing doesnt work
    let mut default_conf = repository::create_default_config(consts::domain.to_string());

    for i in 0..iteration_amount {
        let mut conf = match amount == 0 {
            true => confs[i],
            false => confs[0],
        };
        let parent_cert_key_uri_l = conf.BASE_KEY_DIR_l.clone() + "ta.der";
        let parent_repo_uri_l = conf.BASE_REPO_DIR_l.to_string() + "ta/";

        let notification_uri_b = "https://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_RRDP_DIR_l + "notification.xml";
        let resource_block = Prefix::new(
            Ipv4Addr::new(conf.DEFAULT_IPSPACE_FIRST_OCTET, conf.DEFAULT_IPSPACE_SEC_OCTET, 0, 0),
            conf.DEFAULT_IPSPACE_PREFIX,
        );
        let asn_min = Asn::from_u32(0);
        let asn_max = Asn::from_u32(1000);

        let issuer_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_TA_DIR + "ta.cer";
        let parent_name = "ta";
        let parents_parent_name = "root";
        let ta = false;

        let ca_name = match amount == 0 {
            true => conf.CA_NAME.clone(),
            false => "ca".to_string() + &i.to_string(),
        };
        let ca_name = "ca".to_string() + &i.to_string();
        default_conf.CA_TREE.insert(ca_name.to_string(), "ta".to_string());

        let notification_uri;
        if notification_uris.clone().is_some() {
            let x = notification_uris.clone().unwrap();
            notification_uri = x[i as usize].clone();
        } else {
            notification_uri = notification_uri_b.clone();
        }

        // TODO Disable new keys
        let cert_key = repository::create_ca(
            &parent_cert_key_uri_l,
            &parent_repo_uri_l,
            &notification_uri,
            &ca_name,
            resource_block,
            asn_min,
            asn_max,
            &issuer_cer_uri,
            parent_name,
            parents_parent_name,
            ta,
            "RSA",
            false,
            &conf,
            false,
        );

        cert_keys.push(cert_key);
    }

    repository::make_manifest("ta", "root", &default_conf);
    let (ses, ser) = repository::get_current_session_notification(&default_conf);
    let (snapshot, n) = repository::create_current_snapshot(ses, ser, None, true, &default_conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = repository::create_notification(snapshot_bytes, vec![], n.as_str(), 5, ses, ser, &default_conf);
    repository::write_notification_file(notification, &default_conf).unwrap();

    (cert_keys, default_conf)
}

pub fn get_cwd() -> String {
    env::current_dir().unwrap().into_os_string().into_string().unwrap()
}

use std::time::{Duration, Instant};

use crate::consts;

pub fn random_file_name() -> String {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(12).map(char::from).collect();
    return rand_string + ".dump";
}

// Serialize Byte Vector to a random file in obj_cache folder
pub fn serialize_data(val: &Vec<(String, Vec<u8>)>) -> String {
    let s = serde_json::to_string(&val).unwrap();
    let filename = get_cwd() + "/obj_cache/" + &random_file_name();
    fs::write(&filename, s).unwrap();
    filename
}

pub fn serialize_data_new(val: &Vec<(String, Vec<u8>)>) -> String {
    let mut filenames = vec![];
    let mut contents = vec![];

    for (a, b) in val {
        filenames.push(a.to_owned());
        contents.push(b.to_owned());
    }

    let ob = SerializableObject {
        filenames,
        contents,
        mfts: None,
        crls: None,
        roas: None,
        roa_names: None,
        id: 3,
    };

    serde_json::to_string(&ob).unwrap()
}

pub fn test_for_crash(folder: &str) {
    for p in fs::read_dir(folder).unwrap() {
        let bind = p.unwrap().path();
        let path = bind.to_str().unwrap();
        println!("Testing crash {}", path);
        read_serialized_data(path);
    }
}

pub fn read_serialized_data_new(factory: &mut ObjectFactory) -> Vec<(String, Vec<u8>)> {
    let sobj = factory.get_object();

    if sobj.is_none() {
        return vec![];
    }

    let sobj = sobj.unwrap();
    // let filenames = sobj.filenames;
    // let data = sobj.contents;

    // let mut ret = vec![];

    // for i in 0..filenames.len() {
    //     ret.push((filenames[i].clone(), data[i].clone()));
    // }
    // ret
    vec![]
}

pub fn read_serialized_data(filename: &str) -> Vec<(String, Vec<u8>)> {
    // Short sleep to ensure file has finished writing
    // thread::sleep(Duration::from_millis(10));
    let s = fs::read_to_string(filename).unwrap();
    // println!("Read file: {}", filename);
    // println!("Content: {}", s);

    let c = serde_json::from_str::<Vec<(String, Vec<u8>)>>(&s);
    if c.is_err() {
        println!(
            "Error: File {} could not be read. Maybe wrong file type? ({})",
            filename,
            c.err().unwrap()
        );
        return vec![];
    }
    c.unwrap()
}

pub fn decb64(uri: &str) -> Option<Bytes> {
    let con = fs::read_to_string(uri);
    if con.is_err() {
        return None;
    }
    let d = base64::decode(&con.unwrap().trim());
    if d.is_err() {
        return None;
    }
    Some(Bytes::from(d.unwrap()))
}

/*
Read files from a folder and return the filename together with the filecontent
*/
pub fn read_files_from_folder(folder: &str, amount: u32) -> Vec<(String, Bytes)> {
    let md = metadata(folder).unwrap();

    let mut objects = HashSet::new();
    let obj;

    if md.is_file() {
        let con = decb64(folder);
        if con.is_some() {
            obj = (folder.to_string(), con.unwrap());
        } else {
            obj = (folder.to_string(), Bytes::from(fs::read(folder).unwrap()));
        }
        objects.insert(obj);
    } else {
        let paths = fs::read_dir(folder).unwrap();

        let mut read_amount = 0;
        for path in paths {
            if read_amount >= amount {
                break;
            }

            read_amount += 1;

            let p = path.unwrap().path();
            let mut f = File::open(&p).expect("no file found");
            let metadata = fs::metadata(&p).expect("unable to read metadata");
            let mut buffer = vec![0; metadata.len() as usize];
            f.read(&mut buffer).expect("buffer overflow");
            let b = Bytes::from(buffer);
            objects.insert((p.file_name().unwrap().to_str().unwrap().to_string(), b));
        }
    }
    let obj_vec: Vec<(String, Bytes)> = objects.into_iter().collect();
    obj_vec
}

pub fn move_files_data<T>(folder: String, filepaths: &Vec<(String, T)>, dont_move: bool) {
    // For Debugging
    // let dont_move = false;
    if dont_move {
        return;
    }

    for filepath in filepaths {
        let p = folder.clone() + &filepath.0;
        fs::remove_file(p).unwrap();
    }
}

pub fn check_process(process_name: &str) -> String {
    let cmd = "pgrep ".to_string() + process_name;
    str::from_utf8(&Command::new("sh").arg("-c").arg(&cmd).output().unwrap().stdout)
        .unwrap()
        .to_string()
}

// Generate only the objects without writing anything to disc
pub fn create_fort_config() -> RPConfig {
    let cwd = get_cwd();

    let mut binary_location = cwd.clone();
    let mut outfile = cwd.clone();
    let mut logfile = cwd.clone();
    let mut cache_folder = cwd.clone();
    let mut tal_folder = cwd.clone();
    let mut ssl_cert = cwd.clone();

    binary_location += "/rp/bin/fort";
    outfile += "/output/vrps_fort.txt";
    logfile += "/output/fort";
    cache_folder += "/rpki_cache_fort/";
    tal_folder += "/data/tals/";
    ssl_cert += "/certs/";

    RPConfig {
        binary_location,
        outfile,
        logfile,
        ssl_cert,
        tal_folder,
        cache_folder,
    }
}

pub fn create_octorpki_config() -> RPConfig {
    let cwd = get_cwd();

    let mut binary_location = cwd.clone();
    let mut outfile = cwd.clone();
    let mut logfile = cwd.clone();
    let mut cache_folder = cwd.clone();
    let mut tal_folder = cwd.clone();
    let mut ssl_cert = cwd.clone();

    binary_location += "/rp/bin/octorpki";
    outfile += "/output/vrps_octo.txt";
    logfile += "/output/octorpki";
    cache_folder += "/rpki_cache_octo/";
    tal_folder += "/data/tals/ta.tal";
    ssl_cert += "/certs/";

    RPConfig {
        binary_location,
        outfile,
        logfile,
        ssl_cert,
        tal_folder,
        cache_folder,
    }
}

pub fn create_client_config() -> RPConfig {
    let cwd = get_cwd();

    let mut binary_location = cwd.clone();
    let mut outfile = cwd.clone();
    let mut logfile = cwd.clone();
    let mut cache_folder = cwd.clone();
    let mut tal_folder = cwd.clone();
    let mut ssl_cert = cwd.clone();

    binary_location += "/rp/bin/rpki-client";
    outfile += "/output/";
    logfile += "/output/client";
    cache_folder += "/rpki_cache_client/";
    tal_folder += "/data/tals/ta.tal";
    ssl_cert += "/certs/";

    RPConfig {
        binary_location,
        outfile,
        logfile,
        ssl_cert,
        tal_folder,
        cache_folder,
    }
}

pub fn create_routinator_config() -> RPConfig {
    let cwd = get_cwd();

    // Routinator needs a path to the ssl key as the ssl certificate of our webserver is self-signed
    //let ssl_pem = "/home/niklas/Desktop/rpki-rp-testing-tool/certbundle.pem";
    let mut binary_location = cwd.clone();
    let mut outfile = cwd.clone();
    let mut logfile = cwd.clone();
    let mut cache_folder = cwd.clone();
    let mut tal_folder = cwd.clone();
    let mut ssl_cert = cwd.clone();

    binary_location += "/rp/bin/routinator";
    outfile += "/output/vrps_routinator.txt";
    logfile += "/output/routinator";
    cache_folder += "/rpki_cache_routinator/";
    tal_folder += "/data/tals/";
    ssl_cert += "/certs/certs.pem";

    RPConfig {
        binary_location,
        outfile,
        logfile,
        ssl_cert,
        tal_folder,
        cache_folder,
    }
}

pub fn fileamount_in_folder(dir: &str) -> usize {
    let paths = read_dir(dir).unwrap();
    paths.count()
}

pub fn start_processes(
    binary_location: &str,
    obj_type: &str,
    folder_opt: Option<Vec<String>>,
    amount: u32,
    raw: bool,
) -> (Vec<Child>, Vec<String>) {
    let bf = "data/corpus/";
    let mut f = vec![];

    for i in 0..5 {
        // f.push(bf.to_string() + obj_type + "-corpus_" + &i.to_string() + "/");
        f.push(bf.to_string() + obj_type + "-corpus_" + &i.to_string() + "/");
        // f.push(bf.to_string() + obj_type + "-seed-corpus_" + &i.to_string() + "/");
    }
    let folders;
    if folder_opt.is_some() {
        folders = folder_opt.unwrap();
    } else {
        folders = f;
    }

    let dont_move = false;

    let proc_amount = folders.len();
    let proc_amount = 3;

    let max_file_amount = 500;

    let mut children = vec![];
    println!("Starting {} Processes", proc_amount);
    for i in 0..proc_amount {
        let folder = &folders[i % folders.len()];
        let child = Command::new(binary_location)
            .arg("sign")
            .arg(&("--typ=".to_string() + obj_type))
            .arg(&("--uri=".to_string() + folder))
            .arg(&("--dont-move=".to_string() + &dont_move.to_string()))
            .arg(&("--id=".to_string() + &i.to_string()))
            .arg(&("--amount=".to_string() + &amount.to_string()))
            .arg(&("--raw=".to_string() + &raw.to_string()))
            .spawn()
            .expect("failed to execute child");
        println!("Info: Started Process on Folder {}: PID {}", folder, child.id());
        children.push(child);
    }
    (children, folders)
}

pub fn start_generation(binary_location: &str, obj_type: &str, obj_amount: &str) -> Vec<Child> {
    let mut children = vec![];
    let amount = 1;
    println!("Starting {} Processes", amount);

    for i in 0..amount {
        let child = Command::new(binary_location)
            .arg("generate")
            .arg(&("--typ=".to_string() + obj_type))
            .arg(&("--amount=".to_string() + obj_amount))
            .spawn()
            .expect("failed to execute child");
        children.push(child);
    }
    children
}

pub fn start_signing(binary_location: &str) -> Vec<Child> {
    let mut children = vec![];
    let amount = 1;
    println!("Starting {} Processes", amount);

    for i in 0..amount {
        let child = Command::new(binary_location)
            .arg("signing")
            .arg(&i.to_string())
            .spawn()
            .expect("failed to execute child");
        children.push(child);
    }
    children
}

pub fn report_inconsistency(vprs: &str, filename: &str) {
    let cws = get_cwd() + "/";
    let reports = cws.clone() + "crash_reports/";
    fs::create_dir_all(reports.clone());

    let mut file_content = "Inconsistency Occured at ".to_string();
    file_content += &chrono::offset::Local::now().to_string();
    file_content += " \n";
    file_content += "VRPs: ";
    file_content += vprs;
    file_content += " \n";
    file_content += "Filename: ";
    file_content += filename;
    file_content += " \n";

    let mut file = File::create(reports + filename).expect("Unable to create file");
    file.write_all(file_content.as_bytes()).expect("Unable to write data");
}

pub fn report_crash(rp_name: &str, obj_type: &str, file_name: &str, send_msg: bool) -> String {
    let release_build = true;

    if send_msg {
        send_telegram_msg(rp_name);
    }

    let cws = get_cwd() + "/";
    let reports = cws.clone() + "crash_reports/";
    fs::create_dir_all(reports);

    let mut file_content = "Crash Occured at ".to_string();
    file_content += &chrono::offset::Local::now().to_string();
    file_content += " \n";
    file_content += "Relying Party Name: ";
    file_content += rp_name;
    file_content += " \n";
    file_content += "Object Type: ";
    file_content += obj_type;
    file_content += " \n";
    file_content += "Serialized File Name: ";
    file_content += file_name;
    file_content += " \n";
    file_content += "Info: Current Repo Version in 'data' Folder caused the Crash. \n";
    file_content += "\n";
    file_content += "Relying Party Log: \n\n";

    let rp_output_raw = fs::read_to_string(cws.clone() + "output/" + rp_name + ".error");
    // rp_output_raw.unwrap();
    if rp_output_raw.is_err() {
        file_content += " -> !!! RP OUTPUT COULD NOT BE READ !!! \n";
    } else {
        file_content += &rp_output_raw.unwrap();
    }
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(12).map(char::from).collect();

    // let report_uri = cws.clone() + "crash_reports/crash_report_" + rp_name + "_" + &chrono::offset::Local::now().timestamp().to_string() + ".txt";
    let report_uri = cws.clone() + "crash_reports/crash_report_" + rp_name + "_" + &rand_string + ".txt";

    fs::write(&report_uri, &file_content).unwrap();

    // println!(
    //     "{}",
    //     "\n\n--> Found RP Crash, report written to ".to_string() + &report_uri + "\n\n"
    // );
    file_content
    //process::exit(1);
}

pub fn check_client_crash(filename: &str) -> bool {
    let cws = get_cwd() + "/";
    let outfile = cws + "output/json";

    let b = std::path::Path::new(&outfile).exists();
    if !b {
        report_crash("rpki-client", "roa", filename, false);
    }

    fs::remove_file(&outfile);
    return !b;
}

pub fn check_crash(proc: &mut Child, rp_name: &str, file_name: &str, obj_type: &str) -> i32 {
    match proc.try_wait() {
        Ok(Some(status)) => {
            println!("Crashed with status {}", status.to_string());
            report_crash(&rp_name, obj_type, file_name, false);
            return 1;
        }
        Ok(None) => {}
        Err(e) => {}
    };

    return 0;
}

pub fn send_telegram_msg(rp_name: &str) {
    let chat_id_niklas = "803914362";
    //let chat_id_dona = "5110996092";
    let token = "5930316350:AAGwn1fiByY2G2Jl2YiktR1DH6ZETEIxj3s";
    let uri = "https://api.telegram.org/bot".to_string() + token + "/sendMessage";
    let message = "⚠ Alert: ".to_string() + &to_uppercase(rp_name) + " has crashed";

    let client = reqwest::blocking::Client::new();
    let params_n = [("chat_id", chat_id_niklas), ("text", &message)];
    client.post(uri.clone()).form(&params_n).send().unwrap();
}

fn to_uppercase(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

pub fn remove_folder_content(folder: &str) {
    let paths = fs::read_dir(folder);
    if paths.is_err() {
        return;
    }
    let paths = paths.unwrap();
    for path in paths {
        let p = path.unwrap().path();
        if p.is_file() {
            fs::remove_file(p).unwrap();
        } else {
            remove_folder_content(p.to_str().unwrap());
        }
    }
}

pub fn clear_repo(conf: &RepoConfig, _: u32) {
    let r = get_cwd() + "/" + &conf.BASE_REPO_DIR_l.clone() + &conf.CA_NAME;
    let cwd = get_cwd();

    remove_folder_content(&r);
    fs::remove_dir_all(&r);
    fs::create_dir_all(&r);
    remove_folder_content(&(cwd.clone() + "/rpki_cache_client"));
    remove_folder_content(&(cwd.clone() + "/rpki_cache_octo"));
    remove_folder_content(&(cwd.clone() + "/rpki_cache_fort"));
    remove_folder_content(&(cwd.clone() + "/rpki_cache_routinator"));

    fs::remove_dir_all(cwd.clone() + "/rpki_cache_client").unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_octo").unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_fort").unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_routinator").unwrap();

    fs::create_dir_all(cwd.clone() + "/rpki_cache_client");
    fs::create_dir_all(cwd.clone() + "/rpki_cache_octo");
    fs::create_dir_all(cwd.clone() + "/rpki_cache_fort");
    fs::create_dir_all(cwd.clone() + "/rpki_cache_routinator");
}

/**
 * Create a manifest from the CRL content to have valid parsing of the CRL
 *
 */
pub fn custom_manifest(ca_name: &str, filenames: Vec<&str>, contents: Vec<Bytes>, conf: &RepoConfig) -> Bytes {
    let serial = repository::random_serial();
    let parent_name = &conf.CA_TREE[ca_name];

    let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";

    let storage_base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + ca_name + "/";

    let filename = repository::get_filename_crl_mft(&cert_key_uri);

    let mut mft_uri = storage_base_uri.clone();
    mft_uri.push_str(&filename);

    let mut crl_uri = mft_uri.clone();

    mft_uri.push_str(".mft");
    crl_uri.push_str(".crl");

    let mut issuer_cer = "rsync://".to_string() + &conf.DOMAIN + "/";

    // If the parent is root -> It has to be treated differently
    if parent_name == "root" {
        issuer_cer.push_str((conf.BASE_TAL_DIR.clone() + "root.cer").as_str());
    } else {
        issuer_cer.push_str((conf.BASE_REPO_DIR.clone() + &parent_name + "/" + ca_name + ".cer").as_str());
    }

    let mut vector = vec![];
    let algo = DigestAlgorithm::sha256();

    for i in 0..filenames.len() {
        let digest = algo.digest(&contents[i]);
        vector.push(FileAndHash::new(filenames[i], digest));
    }
    let content = ManifestContent::new(serial, Time::now(), Time::tomorrow(), DigestAlgorithm::default(), vector.iter());

    let e = content.encode_ref().to_captured(Mode::Der).into_bytes();

    e
}

pub fn create_manifest(
    conf: &RepoConfig,
    ca_name: &str,
    file_desc: &str,
    priv_key: PKey<Private>,
    pub_key: PublicKey,
    ca_signer: &KeyAndSigner,
    index: u32,
    crl_content: Bytes,
    roa_content: (Bytes, String),
) -> Bytes {
    let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";
    let storage_base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + ca_name + "/";
    let filename = repository::get_filename_crl_mft(&cert_key_uri);
    let mut crl_uri = storage_base_uri.clone();
    crl_uri.push_str(&filename);
    crl_uri.push_str(".crl");

    let mft_content = custom_manifest(
        ca_name,
        vec![&(filename + ".crl"), &roa_content.1],
        vec![crl_content, roa_content.0],
        conf,
    );

    let re = fuzzing_interface::generate_signed_data_from_bytes(
        mft_content,
        &conf,
        "mft",
        file_desc,
        true,
        index.try_into().unwrap(),
        &ca_signer,
        priv_key,
        pub_key,
        ca_name,
        None,
    );
    re
}

pub fn clear_repo_full(conf: &RepoConfig, _: u32) {
    let r = get_cwd() + "/" + &conf.BASE_REPO_DIR_l.clone();
    let cwd = get_cwd();
    remove_folder_content(&r);

    fs::create_dir_all(&r).unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_client").unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_octo").unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_fort").unwrap();
    fs::remove_dir_all(cwd.clone() + "/rpki_cache_routinator").unwrap();
}

pub fn create_example_mfts(
    cert_keys: &Vec<KeyAndSigner>,
    amount: u32,
    roas: &Vec<(Bytes, String)>,
    crls: &Vec<(Bytes, String)>,
    conf: &RepoConfig,
) -> Vec<(Bytes, String)> {
    let (priv_keys, pub_keys) = load_ee_ks(conf, amount, false);

    let mut ret = vec![];
    for o in 0..amount {
        let i = o as usize;
        let ca_name = "ca".to_string() + &i.to_string();
        let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";
        let mft = create_manifest(
            &conf,
            &ca_name,
            &cert_key_uri,
            priv_keys[i].clone(),
            pub_keys[i].clone(),
            &cert_keys[i],
            i.try_into().unwrap(),
            crls[i].0.clone().into(),
            roas[i].clone(),
        );
        let name = cert_keys[i].get_pub_key().key_identifier().to_string() + ".mft";
        ret.push((mft, name));
    }
    ret
}

pub fn create_example_crls(cert_keys: &Vec<KeyAndSigner>, amount: u32, conf: &RepoConfig) -> Vec<(Bytes, String)> {
    let mut ret = vec![];
    for i in 0..amount {
        let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + &("ca".to_string() + &i.to_string()) + ".der";
        let crl_bytes = repository::create_default_crl_i(1, vec![], &cert_key_uri, &("ca".to_string() + &i.to_string()), false, conf);
        let name = cert_keys[i as usize].get_pub_key().key_identifier().to_string() + ".crl";
        ret.push((crl_bytes, name));
    }
    ret
}

pub fn create_example_roas(amount: u32) -> Vec<(Bytes, String)> {
    let mut ret = vec![];
    let conf = repository::create_default_config(consts::domain.to_string());
    let (priv_keys, pub_keys) = load_ee_ks(&conf, amount, true);
    // let (cert_keys, _) = create_cas(amount, vec![&mut conf], None);

    for i in 0..amount {
        let ca_name = "ca".to_string() + &i.to_string();
        // let parent_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + &conf.CA_TREE[&ca_name] + "/" + &ca_name + ".cer";
        let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + "newca" + ".der";
        let cert_key = repository::read_cert_key(&cert_key_uri);
        let ca_name = "newca".to_string();

        let roa_string = "10.0.0.0/24 => ".to_string() + &i.to_string();

        // TODO remove this
        let roa_string = "10.0.0.0/24 => 1776".to_string(); // + &i.to_string();

        let (roa_builder, _) = repository::process_roa_string(&roa_string).unwrap();
        let roa_bytes = roa_builder.to_attestation().encode_ref().to_captured(Mode::Der).into_bytes();
        let fname = ca_name.clone() + &i.to_string() + ".roa";
        let re = fuzzing_interface::generate_signed_data_from_bytes(
            roa_bytes,
            &conf,
            "roa",
            &roa_string,
            true,
            i.try_into().unwrap(),
            // &cert_keys[i as usize],
            &cert_key,
            priv_keys[i as usize].clone(),
            pub_keys[i as usize].clone(),
            &ca_name,
            None,
        );

        let roa_name = repository::file_name_for_object(&roa_string, ".roa");
        ret.push((re, roa_name));
    }
    ret
}

pub fn get_request(uri: &str) -> Option<String> {
    println!("Running request: {}", uri);
    let res_t = reqwest::blocking::get(uri);
    if res_t.is_err() {
        println!("{}", res_t.err().unwrap());
        return None;
    }
    let mut res = res_t.unwrap();
    let mut body = String::new();
    //let mut body = String::new();
    let r = res.read_to_string(&mut body);
    if r.is_err() {
        println!("{}", r.err().unwrap());
        return None;
    }

    println!("Response: {}", body);
    return Some(body);
}

pub fn create_csv_data(data: Option<String>, csv: bool) -> (String, Vec<RoaContents>) {
    let tmp;
    let mut ret = "".to_string();
    if data.is_none() {
        return (ret, vec![]);
    }
    if csv {
        tmp = rp_interaction::parse_output_csv(&data.unwrap());
    } else {
        tmp = rp_interaction::parse_output_json(&data.unwrap());
    }
    for d in &tmp {
        ret += &(d.ip_addr.to_string() + "," + &d.prefix.to_string() + "," + &d.as_id.to_string() + "\n");
    }

    (ret, tmp)
}

// Returns if the VRPS are identical
pub fn store_vrps(serialized_file_name: &str) -> (bool, String) {
    let folder = get_cwd() + "/vrps_log/";
    let tmp = serialized_file_name.split(".").collect::<Vec<&str>>()[0];
    let tmp2 = tmp.split("/").collect::<Vec<&str>>();
    let name = tmp2.last().unwrap();
    let fname = folder.clone() + &name + ".vrps";
    let (vrps, iden, _, _) = get_rp_vrps();
    let dont_store = false;

    // If we do not want to store or the objects are identical anyway -> Do not store them
    if dont_store || iden {
        return (iden, "".to_string());
    }

    fs::create_dir_all(folder);
    fs::write(fname, vrps).unwrap();
    (iden, name.to_string())
}
fn hashset(data: &Vec<RoaContents>) -> HashSet<u32> {
    data.iter().map(|x| x.as_id.into_u32()).collect::<HashSet<u32>>()
}

pub fn get_rp_vrps() -> (String, bool, Vec<String>, Vec<Vec<RoaContents>>) {
    // ROUTINATOR curl 127.0.0.1:8888/csv

    let cws = get_cwd() + "/";
    // let routinator_uri = "http://127.0.0.1:8888/csv";
    // let octo_uri = "http://127.0.0.1:8887".to_string() + &cws.clone() + "output/vrps_octo.txt";

    let rt_uri = cws.clone() + "/output/vrps_routinator.txt";
    let rt_raw = fs::read_to_string(rt_uri);
    let mut routinator_data = "\n".to_string();
    let mut rout_con = vec![];
    if rt_raw.is_ok() {
        (routinator_data, rout_con) = create_csv_data(Some(rt_raw.unwrap()), true);
    }
    if routinator_data == "" {
        routinator_data = "\n".to_string();
    }

    let octo_uri = cws.clone() + "/output/vrps_octo.txt";
    let octo_raw = fs::read_to_string(octo_uri);
    let mut octo_data = "\n".to_string();
    let mut octo_con = vec![];
    if octo_raw.is_ok() {
        (octo_data, octo_con) = create_csv_data(Some(octo_raw.unwrap().clone()), false);
    }
    if octo_data == "" {
        octo_data = "\n".to_string();
    }

    let fort_uri = cws.clone() + "/output/vrps_fort.txt";
    let fort_raw = fs::read_to_string(fort_uri);
    let mut fort_data = "\n".to_string();
    let mut fort_con = vec![];
    if fort_raw.is_ok() {
        (fort_data, fort_con) = create_csv_data(Some(fort_raw.unwrap()), true);
    }
    if fort_data == "" {
        fort_data = "\n".to_string();
    }

    let client_uri = cws.clone() + "/output/csv";
    let client_raw = fs::read_to_string(client_uri);
    let mut client_data = "\n".to_string();
    let mut client_con = vec![];
    if client_raw.is_ok() {
        (client_data, client_con) = create_csv_data(Some(client_raw.unwrap()), true);
    }
    if client_data == "" {
        client_data = "\n".to_string();
    }

    let a =
        hashset(&rout_con) == hashset(&octo_con) && hashset(&rout_con) == hashset(&fort_con) && hashset(&rout_con) == hashset(&client_con);
    let b = hashset(&octo_con) == hashset(&fort_con) && hashset(&octo_con) == hashset(&client_con);
    let c = hashset(&fort_con) == hashset(&client_con);

    let lr = rout_con.len();
    let lo = octo_con.len();
    let lf = fort_con.len();
    let lc = client_con.len();

    let max_len = lr.max(lo).max(lf).max(lc);
    let mut smaller_rps = vec![];
    if lr < max_len {
        smaller_rps.push("routinator".to_string());
    }
    if lo < max_len {
        smaller_rps.push("octorpki".to_string());
    }
    if lf < max_len {
        smaller_rps.push("fort".to_string());
    }
    if lc < max_len {
        smaller_rps.push("client".to_string());
    }

    let mut ret = "".to_string();

    // println!("Max length is {}", max_len);

    if max_len == 1 {
        ret += &("Routinator:\n ".to_string() + &routinator_data + "");
        ret += &("Octorpki:\n ".to_string() + &octo_data + "");
        ret += &("Fort:\n ".to_string() + &fort_data + "");
        ret += &("Client:\n ".to_string() + &client_data + "");
    } else {
        ret += &("Routinator:\n ".to_string() + &routinator_data + "\n\n");
        ret += &("Octorpki:\n ".to_string() + &octo_data + "\n\n");
        ret += &("Fort:\n ".to_string() + &fort_data + "\n\n");
        ret += &("Client:\n ".to_string() + &client_data + "\n\n");
    }

    let v = rout_con.len() == octo_con.len() && fort_con.len() == client_con.len() && fort_con.len() == rout_con.len();

    if !v {
        // println!("Routinator");
        // for v in &rout_con{
        //     println!("{}", roa_con_to_string(&v));
        // }
        // println!("Octo");
        // for v in &octo_con{
        //     println!("{}", roa_con_to_string(&v));
        // }
        // println!("Fort");
        // for v in &fort_con{
        //     println!("{}", roa_con_to_string(&v));
        // }
        // println!("Client");
        // for v in &client_con{
        //     println!("{}", roa_con_to_string(&v));
        // }
    }

    // println!("VRPS Length Routinator: {}", rout_con.len());
    // println!("VRPS Length Octo: {}", octo_con.len());
    // println!("VRPS Length Fort: {}", fort_con.len());
    // println!("VRPS Length Client: {}", client_con.len());

    let identical = a && b && c && v;

    // println!("VRPS Identical {}", identical);

    (ret, identical, smaller_rps, vec![rout_con, octo_con, fort_con, client_con])
}

pub fn roa_con_to_string(c: &RoaContents) -> String {
    let mut ret = "".to_string();
    ret += &c.ip_addr.to_string();
    ret += ",";
    ret += &c.prefix.to_string();
    ret += ",";
    ret += &c.as_id.to_string();
    ret += "\n";
    ret
}

pub fn get_rp_vrps_server() -> (String, bool) {
    // ROUTINATOR curl 127.0.0.1:8888/csv

    let cws = get_cwd() + "/";
    let routinator_uri = "http://127.0.0.1:8888/csv";
    let octo_uri = "http://127.0.0.1:8887".to_string() + &cws.clone() + "output/vrps_octo.txt";

    let rt_raw = get_request(routinator_uri);
    let (routinator_data, rout_con) = create_csv_data(rt_raw, true);

    let octo_raw = get_request(&octo_uri);
    let (octo_data, octo_con) = create_csv_data(octo_raw, false);

    let fort_uri = cws.clone() + "/output/vrps_fort.txt";
    let fort_raw = fs::read_to_string(fort_uri);
    let mut fort_data = "".to_string();
    let mut fort_con = vec![];
    if fort_raw.is_ok() {
        (fort_data, fort_con) = create_csv_data(Some(fort_raw.unwrap()), true);
    }

    let client_uri = cws.clone() + "/output/csv";
    let client_raw = fs::read_to_string(client_uri);
    let mut client_data = "".to_string();
    let mut client_con = vec![];
    if client_raw.is_ok() {
        (client_data, client_con) = create_csv_data(Some(client_raw.unwrap()), true);
    }

    let mut ret = "".to_string();
    ret += &("Routinator: ".to_string() + &routinator_data + "\n\n");
    ret += &("Octorpki: ".to_string() + &octo_data + "\n\n");
    ret += &("Fort: ".to_string() + &fort_data + "\n\n");
    ret += &("Client: ".to_string() + &client_data + "\n\n");

    let a =
        hashset(&rout_con) == hashset(&octo_con) && hashset(&rout_con) == hashset(&fort_con) && hashset(&rout_con) == hashset(&client_con);
    let b = hashset(&octo_con) == hashset(&fort_con) && hashset(&octo_con) == hashset(&client_con);
    let c = hashset(&fort_con) == hashset(&client_con);
    let identical = a && b && c;

    (ret, identical)
}

pub fn get_fileamount_folders(folders: Vec<String>) -> u32 {
    let mut total = 0;
    for folder in folders {
        total += read_dir(folder).unwrap().count();
    }
    total.try_into().unwrap()
}

pub fn clear_caches() {
    let cws = get_cwd() + "/";
    remove_folder_content(&(cws.clone() + "rpki_cache_client"));
    remove_folder_content(&(cws.clone() + "rpki_cache_octo"));
    remove_folder_content(&(cws.clone() + "rpki_cache_fort"));
    remove_folder_content(&(cws.clone() + "rpki_cache_routinator"));

    fs::create_dir_all(cws.clone() + "/rpki_cache_client");
    fs::create_dir_all(cws.clone() + "/rpki_cache_octo");
    fs::create_dir_all(cws.clone() + "/rpki_cache_fort");
    fs::create_dir_all(cws.clone() + "/rpki_cache_routinator");
}

pub fn check_rp_crash() -> Vec<(String, bool)> {
    let fc = create_client_config().outfile + "vrps_client.txt";
    let fr = create_routinator_config().outfile;
    let fo = create_octorpki_config().outfile;
    let ff = create_fort_config().outfile;

    let c_crash = !Path::new(&fc).exists();
    let r_crash = !Path::new(&fr).exists();
    let o_crash = !Path::new(&fo).exists();
    let f_crash = !Path::new(&ff).exists();
    vec![
        ("client".to_string(), c_crash),
        ("routinator".to_string(), r_crash),
        ("octorpki".to_string(), o_crash),
        ("fort".to_string(), f_crash),
    ]
}

pub fn run_rp_mp(name: &str, log_level: &str) -> Child {
    if name == "routinator" {
        let routinator_conf = create_routinator_config();
        rp_interaction::run_update_routinator_p_non_blocking(&routinator_conf, log_level)
    } else if name == "fort" {
        let fort_conf = create_fort_config();
        rp_interaction::run_update_fort_p_non_blocking(&fort_conf, log_level)
    } else if name == "octorpki" {
        let octo_conf = create_octorpki_config();
        rp_interaction::run_update_octorpki_p_non_blocking(&octo_conf, log_level)
    } else if name == "rpki-client" {
        let client_conf = create_client_config();
        rp_interaction::run_update_rpki_client_p_non_blocking(&client_conf, log_level)
    } else {
        panic!("Unknown rp name");
    }
}
pub fn check_process_running(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(Some(status)) => {
            // println!("Status {}", status);
            return false;
        }
        Ok(None) => {
            return true;
        }
        Err(e) => {
            return true;
        }
    };
}

pub fn run_rp_processes(log_level: &str) -> Vec<(String, bool)> {
    let mut children = vec![];
    children.push(run_rp_mp("fort", log_level));
    children.push(run_rp_mp("rpki-client", log_level));
    children.push(run_rp_mp("octorpki", log_level));
    children.push(run_rp_mp("routinator", log_level));

    let start = Instant::now();
    let mut already_finished = vec![];

    loop {
        let mut finished = true;
        for i in 0..children.len() {
            let child = &mut children[i];
            let r = check_process_running(child);
            if r {
                finished = false;
            } else {
                let elapsed = start.elapsed();
                if !already_finished.contains(&i) {
                    already_finished.push(i);
                    // println!("{} finished in {}ms", i, elapsed.as_millis());
                }
            }
        }
        if finished {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    // This is necessary because client always writes outfile to outfile/csv
    let client_conf = create_client_config();
    fs::copy(
        &(client_conf.outfile.clone() + "csv"),
        &(client_conf.outfile.clone() + "vrps_client.txt"),
    );

    check_rp_crash()
}

pub fn handle_crashes(pot_crashes: Vec<(String, bool)>, obj_type: &str, file_name: &str) -> Vec<(String, String, usize)> {
    let mut crash_info = vec![];
    for p in pot_crashes {
        if p.1 {
            let (crashfile, crashline);
            if p.0 == "routinator" {
                (crashfile, crashline) = get_crash_line_rt().unwrap();
            } else {
                (crashfile, crashline) = ("lala".to_string(), 0);
            }

            report_crash(&p.0, obj_type, file_name, false);
            crash_info.push((p.0, crashfile, crashline));
        }
    }
    crash_info
}

pub fn generate_ca_conf(ca_name: String) -> repository::RepoConfig {
    let domain = consts::domain.to_string();
    let base_dir = "data/".to_string() + &domain + "/";
    let first_octet = 10;
    let second_octet = 0;
    let prefix = 16;
    let as_min = 0;
    let as_max = 1000;
    let ssl_pem_uri_l = "certs/".to_string() + &domain + ".crt";

    let ipv4 = vec![Ipv4Net::new(Ipv4Addr::new(first_octet, second_octet, 0, 0), prefix).unwrap()];
    let ipblocks = vec![(
        4,
        IpBlock::from(resources::Prefix::new(Ipv4Addr::new(first_octet, second_octet, 0, 0), prefix)),
    )];

    let mut c = repository::RepoConfig::new(
        base_dir,
        domain.clone(),
        first_octet,
        second_octet,
        prefix,
        as_min,
        as_max,
        ssl_pem_uri_l,
        ca_name.clone(),
        &("_".to_string() + &ca_name),
        ipv4,
        ipblocks,
    );
    c.BASE_KEY_DIR = "data/keys/".to_string();
    c.BASE_TAL_DIR = "data/tals/".to_string();
    c.BASE_TA_DIR = "data/".to_string() + &domain + "/tal/";

    let c = c.default_locals_a("".to_string(), domain);
    c
}

pub fn store_files_xml(files: &Vec<(String, Bytes)>, filename: &str) {
    let mut v = vec![];
    for f in files {
        v.push((f.0.clone(), f.1.to_vec()));
    }
    let s = serde_json::to_string(&v).unwrap();
    fs::write(&filename, s).unwrap();
}

pub fn send_coverage(function_coverage: f64, line_coverage: f64, function_hashes: HashSet<u64>, batch_id: u64) {
    let obj = CoverageObject {
        function_coverage,
        line_coverage,
        function_hashes,
        batch_id,
    };

    let data = serde_json::to_string(&obj).unwrap();

    process_util::send_new_data_s(data, "/tmp/coverage");
}

pub fn start_fuzzing_xml(
    obj_type: &str,
    folders: Vec<String>,
    obj_per_iteration: u32,
    clear_repo_fn: &dyn Fn(&RepoConfig, u32),
    create_file_fn: &dyn Fn(Vec<&RepoConfig>, Vec<(String, Bytes)>),
    dont_move: bool,
) {
    let mut proc_amount = 0;

    let totalfiles = get_fileamount_folders(folders.clone());

    println!("Info: Found {} objects", totalfiles.to_string());

    println!("Info: Starting Fuzzer");

    println!("\nRunning...\n");

    let mut conf = repository::create_default_config(consts::domain.to_string());

    repository::initialize_repo(&mut conf, false, None);

    let mut confs: Vec<RepoConfig> = vec![];
    for i in 0..obj_per_iteration {
        let ca_name = "ca".to_string() + &i.to_string();

        let mut repo_conf = generate_ca_conf(ca_name.clone());
        confs.push(repo_conf);
    }

    let mut nconfs = vec![];
    for i in 0..confs.len() {
        nconfs.push(&confs[i]);
    }

    let mut totalprocessed = 0;
    let absstart = Instant::now();

    create_cas(0, nconfs.clone(), None);
    for folder in folders.clone() {
        loop {
            let start = Instant::now();

            clear_repo_fn(&conf, 0);
            let files = read_files_from_folder(&folder.clone(), obj_per_iteration);
            if files.len() == 0 {
                break;
            }
            create_file_fn(nconfs.clone(), files.clone());

            let crashes = run_rp_processes("info");

            let (vrps, iden, _, _) = get_rp_vrps();
            let r = &random_file_name();
            let filename = get_cwd() + "/inconsistent_files/" + r;

            let c = handle_crashes(crashes, obj_type, &filename);
            if !c.is_empty() {
                store_files_xml(&files, &(filename));
            }
            if !c.is_empty() || !iden {
                println!("Found inconsistency!");
                // store_files_xml(&files, &(filename + ".dump"));
            }
            // if !c && !iden{
            //     report_inconsistency(&vrps, r);
            // }

            proc_amount += obj_per_iteration;
            totalprocessed += obj_per_iteration;

            move_files_data(folder.to_string(), &files, dont_move);
            let end = start.elapsed();

            // println!("Elapsed Time is {:?}", end);
            if proc_amount > 9000 {
                let td: f32 = totalprocessed as f32 / totalfiles as f32;
                if td == 1 as f32 {
                    println!("Finished!");
                    // return;
                }
                let fac: f64 = (1 as f32 / td - 1 as f32).into();

                if absstart.elapsed().as_secs() < 1 {
                    continue;
                }
                let t_total = absstart.elapsed().as_secs() as f64 * fac;
                if t_total > 0 as f64 {
                    let dur = Duration::from_secs_f64(t_total);
                    println!(
                        "Progress {}%, remaining time estimate {}s {}m {}h [Elapsed Time: {:?}]",
                        (td * 100 as f32).to_string(),
                        (dur.as_secs_f64() % 60 as f64).floor(),
                        ((dur.as_secs_f64() % 3600 as f64) / 60.0).floor(),
                        (dur.as_secs_f64() / 3600.0).floor(),
                        absstart.elapsed()
                    );
                } else {
                    println!("Time is up now");
                }

                proc_amount = 0;
            }
        }
    }
}

fn print_progress(totalprocessed: u32, totalfiles: u32, proc_amount: u32, absstart: Instant) {
    if proc_amount > 9000 {
        let td: f32 = totalprocessed as f32 / totalfiles as f32;
        if td == 1 as f32 {
            println!("Finished!");
            // return;
        }
        let fac: f64 = (1 as f32 / td - 1 as f32).into();

        if absstart.elapsed().as_secs() < 1 {
            return;
        }
        let t_total = absstart.elapsed().as_secs() as f64 * fac;
        if t_total > 0 as f64 {
            let dur = Duration::from_secs_f64(t_total);
            println!(
                "Progress {}%, remaining time estimate {}s {}m {}h [Elapsed Time: {:?}]",
                (td * 100 as f32).to_string(),
                (dur.as_secs_f64() % 60 as f64).floor(),
                ((dur.as_secs_f64() % 3600 as f64) / 60.0).floor(),
                (dur.as_secs_f64() / 3600.0).floor(),
                absstart.elapsed()
            );
        } else {
            println!("Time is up now");
        }
    }
}

fn analyse_output(data: String) -> io::Result<(String, usize)> {
    let re = Regex::new(r"thread '.*' panicked at '.*', (.*):\d+").unwrap();

    for cap in re.captures_iter(&data) {
        let file_line = &cap[1];
        let split: Vec<&str> = file_line.split(':').collect();
        let file_name = split[0].to_string();
        let line_number: usize = split[1].parse().unwrap();
        return Ok((file_name, line_number));
    }

    Err(io::Error::new(io::ErrorKind::Other, "No match found"))
}

pub fn get_crash_line_rt() -> io::Result<(String, usize)> {
    let s = fs::read_to_string("output/routinator.error").unwrap();
    analyse_output(s)
}

pub fn start_fuzzing(conf: FuzzConfig, factory: &mut ObjectFactory) {
    let mut proc_amount = 0;

    println!("Info: Starting Fuzzer");

    println!("\nRunning...\n");

    let mut totalprocessed: u32 = 0;
    let absstart = Instant::now();

    let cws = get_cwd() + "/";
    let incon_file_dir = cws.clone() + "inconsistent_files/";

    fs::create_dir_all(&incon_file_dir).unwrap_or_default();
    fs::create_dir_all(&(cws.clone() + "crash_reports/")).unwrap_or_default();

    let mut all_crashes = vec![];

    loop {
        let new_obj = factory.get_object();

        if new_obj.is_none() {
            thread::sleep(Duration::from_millis(200));
            continue;
        }

        let obj = new_obj.unwrap();

        // println!("Batch size is {}", obj.contents.len());

        clear_repo(&conf.repo_conf, 0);

        obj.write_to_disc();

        // processing::handle_serialized_object(obj.clone(), &conf.repo_conf, &conf.typ.to_string());
        // println!("Info: Running objects with length {}", obj.contents.len());
        let crashes = run_rp_processes("info");

        let start = Instant::now();
        let (fcov, lcov, fhashes) = coverage_interface::get_coverage("routinator");
        let elapsed = start.elapsed();
        // println!("Time elapsed in coverage: {:?}", elapsed);

        fs::remove_file("routinator.profdata");

        send_coverage(fcov, lcov, fhashes, obj.batch_id);

        let r = &random_file_name();
        let (identical, vrps_name) = store_vrps(r);

        let crash_file_name = incon_file_dir.clone() + "crash-" + &vrps_name + ".dump";
        let crash = handle_crashes(crashes, &conf.typ.to_string(), &crash_file_name);

        proc_amount += conf.amount;
        totalprocessed += conf.amount;

        if !crash.is_empty() {
            let mut was_new = false;
            for c in crash.clone() {
                if !all_crashes.contains(&c) {
                    was_new = true;
                    all_crashes.push(c);
                }
            }

            if was_new {
                println!("Logging a new crash in {}", crash_file_name);
                println!("All crashes: {:?}", all_crashes);
                fs::write(crash_file_name, serde_json::to_string(&obj).unwrap()).unwrap();
            } else {
                // println!("Knew all crashes already {:?}", crash);
            }
        } else if !identical {
            let non_iden_file_name = incon_file_dir.clone() + "incon-" + &vrps_name + ".dump";
            // println!("Inconsistency: {}", non_iden_file_name);
            // fs::write(non_iden_file_name, serde_json::to_string(&obj).unwrap()).unwrap();
        }
    }
}
