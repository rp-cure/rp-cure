use chrono::Duration;
use rpki::{repository, uri};
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use rpki::repository::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::repository::crl::{CrlEntry, TbsCertList};
use rpki::repository::crypto::softsigner::{KeyId, OpenSslSigner};
use rpki::repository::crypto::{DigestAlgorithm, KeyIdentifier, PublicKey, SignatureAlgorithm, Signer};
use rpki::repository::manifest::{FileAndHash, ManifestContent};
use rpki::repository::resources::{self, Asn, IpBlock, Prefix};
use rpki::repository::roa::RoaBuilder;
use rpki::repository::x509::{Name, Serial, Time, Validity};
use rpki::rrdp::{Delta, DeltaElement, DeltaInfo, Hash, NotificationFile, PublishElement, Snapshot, UpdateElement, UriAndHash};
use std::net::{Ipv4Addr, Ipv6Addr};
use walkdir::WalkDir;

use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;

use crate::fuzzing_loop::random_id;
use crate::publication_point::adapted_functions;
use crate::publication_point::manual_tests::test_util::get_cwd;

use bytes::Bytes;

use std::path::Path;
use std::{cmp, error, fmt, fs, io, str};

use openssl::rsa::Rsa;

extern crate base64;
use uuid::Uuid;

use sha256::{digest_bytes, digest_file};

use rand::Rng;

use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sign::Signer as OSigner;

use std::collections::HashMap;

pub fn get_user_dir() -> String {
    dirs::home_dir().unwrap().into_os_string().into_string().unwrap() + "/"
}

pub fn generate_random_roa_string(o1: u8, o2: u8, o3: u8, o4: u8) -> String {
    let first_octet = o1;

    let second_octet = o2; //constants::DEFAULT_IPSPACE_SEC_OCTET;

    let third_octet = o3; //rand::thread_rng().gen_range(0..255);

    let fourth_octet = o4;

    let as_numer = rand::thread_rng().gen_range(0..10000);

    let mut roa_string = "".to_string();

    roa_string.push_str(first_octet.to_string().as_str());
    roa_string.push_str(".");
    roa_string.push_str(second_octet.to_string().as_str());
    roa_string.push_str(".");
    roa_string.push_str(third_octet.to_string().as_str());
    roa_string.push_str(".");
    roa_string.push_str(fourth_octet.to_string().as_str());
    roa_string.push_str("/24 => ");
    roa_string.push_str(Asn::from(as_numer).to_string().as_str());
    roa_string
}

pub fn random_serial() -> Serial {
    let val: u64 = rand::thread_rng().gen_range(0..300000);
    val.into()
}

pub fn generate_random_bytes() -> String {
    let mut bytes = [0; 8];
    openssl::rand::rand_bytes(&mut bytes).unwrap();
    hex::encode(bytes)
}

pub fn create_repo_structure(conf: &RepoConfig) {
    fs::remove_dir_all(&conf.BASE_DATA_DIR_l);

    fs::create_dir_all(&conf.BASE_RRDP_DIR_l).unwrap();

    fs::create_dir_all(&conf.BASE_KEY_DIR_l).unwrap();
    fs::create_dir_all(&conf.BASE_REPO_DIR_l).unwrap();

    fs::create_dir_all(&conf.BASE_TAL_DIR_l).unwrap();
    fs::create_dir_all(&conf.BASE_TA_DIR_l).unwrap();

    // fs::remove_dir_all("./rp/routinator/outputs/");
    // fs::remove_dir_all("./rp/routinator/rpki-cache/");

    // fs::create_dir_all("./rp/routinator/outputs/").unwrap();
    // fs::create_dir_all("./rp/routinator/rpki-cache/tals/").unwrap();
    // fs::create_dir_all("./rp/routinator/rpki-cache/repository/").unwrap();
}

pub fn initialize_additional_folder(conf: &RepoConfig) {
    let serial_number = 0;
    let session_id = Uuid::new_v4();

    create_repo_structure(conf);
    let (snapshot, snapshot_file) = create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = create_notification(snapshot_bytes, vec![], snapshot_file.as_str(), 5, session_id, serial_number, conf);
    write_notification_file(notification, conf).unwrap();

    let ca_name = &conf.CA_NAME;
    let parent_name = "ta";
    let rsa_key_uri_l = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";

    create_default_crl(0, vec![], &rsa_key_uri_l, ca_name, conf);
    make_manifest(ca_name, parent_name, conf);
}
// Careful! This wipes the entire Repo content!
pub fn initialize_repo(conf: &mut RepoConfig, new_cas: bool, session_id: Option<Uuid>) -> Uuid {
    // This creates a RPKI repository with a Trust Anchor CA (TA) and a normal child CA (newca)
    let serial_number = 1;
    let session_id = session_id.unwrap_or(Uuid::new_v4());

    create_repo_structure(conf);
    create_default_ta(new_cas, conf);

    // TODO RE-ENABLE
    create_default_ca(new_cas, conf);
    //create_multiple_cas(new_cas, conf);

    // if new_cas {
    create_default_tal(conf);
    // }
    let (snapshot, snapshot_file) = create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = create_notification(snapshot_bytes, vec![], snapshot_file.as_str(), 5, session_id, serial_number, conf);
    write_notification_file(notification, conf).unwrap();
    session_id
}

// Using the alt function is very not pretty, change this in the future
pub fn roa_string_from_content(att: adapted_functions::roa_alt::RouteOriginAttestation) -> String {
    let mut iter = att.iter();

    let f = iter.next().unwrap();

    format!("{}/{} => {}", f.address(), f.address_length(), att.as_id())
}

pub fn process_roa_string(roa_string: &str) -> Result<(RoaBuilder, Ipv4Addr), Error> {
    // Create a Roa Builder from a ROA string
    // The string has the form of 1.1.1.1/24 => ASNUMBER
    let (ip, rest) = roa_string.split_once("/").unwrap();
    let mut ip_vec = vec![];
    for element in ip.split(".") {
        let tmp = element.parse::<u8>().unwrap();
        ip_vec.push(tmp);
    }
    if ip_vec.len() != 4 {
        return Err(Error::BadScheme);
    }
    let (prefix_i, as_i) = rest.split_once("=").unwrap();

    let prefix = prefix_i.trim().parse::<u8>().unwrap();

    // 1.. to remove the = sign
    let as_s = as_i[1..].to_string();
    let as_trim = as_s.trim();

    let mut roa_builder = RoaBuilder::new(Asn::from_str(as_trim).unwrap());
    let ip = Ipv4Addr::new(ip_vec[0], ip_vec[1], ip_vec[2], ip_vec[3]);
    roa_builder.push_v4_addr(ip, prefix, None);
    Ok((roa_builder, ip))
}

pub fn get_file_path_ca(ca_name: &str, cert_key_uri: &str, conf: &RepoConfig) -> (String, String) {
    // Return the default file path for the ca's mft and crl
    let mut base_uri_mft = base_repo_uri(ca_name, conf);

    let mut base_uri_crl = base_uri_mft.clone();

    let file_base_name_ca = get_filename_crl_mft(&cert_key_uri);

    base_uri_mft.push_str(file_base_name_ca.clone().as_str());
    base_uri_crl.push_str(file_base_name_ca.clone().as_str());

    base_uri_mft.push_str(".mft");
    base_uri_crl.push_str(".crl");

    (base_uri_mft, base_uri_crl)
}

// The Filename is generated from the Public-Key identifier of the cert key
pub fn get_filename_crl_mft(cert_key_path: &str) -> String {
    let ks = read_cert_key(cert_key_path);
    let pubkey = ks.get_pub_key();
    pubkey.key_identifier().to_string()
}

// Create a tbs cert for a crl
pub fn create_crl_tbs(
    signature_algo: SignatureAlgorithm,
    issuer: Name,
    this_update: Time,
    next_update: Time,
    revoked_certs: Vec<CrlEntry>,
    auth_key_id: KeyIdentifier,
    crl_number: Serial,
    ks: KeyAndSigner,
) -> Bytes {
    let crl_cert = TbsCertList::new(
        signature_algo,
        issuer,
        this_update,
        next_update,
        revoked_certs,
        auth_key_id,
        crl_number,
    );

    adapted_functions::overwritten_functions::into_crl(crl_cert, ks)
}

pub fn write_object_to_disc(file_content: &Bytes, object_type: &str, additional_info: &str, ca_name: &str, conf: &RepoConfig) -> String {
    // Additional Info contains the additional information required for different objects
    // E.g. mft and crl require the uri of the cert of the objects, roas require the ip/as string

    let mut file_uri = conf.BASE_REPO_DIR_l.clone() + ca_name + "/";

    if object_type == "crl" || object_type == "mft" {
        file_uri.push_str(&get_filename_crl_mft(additional_info));
        file_uri.push_str(".");
        file_uri.push_str(object_type);
    } else if object_type == "roa" || object_type == "aspa" || object_type == "gbr" {
        let ext;
        // Aspa only has .asa as extension
        if object_type == "aspa" {
            ext = "asa";
        } else {
            ext = object_type;
        }
        // file_uri.push_str(&random_serial().to_string());
        file_uri.push_str(&file_name_for_object(additional_info, &(".".to_string() + ext)));
    } else {
        // If it is not a known object -> Asume additional_info contains file_name
        file_uri.push_str(additional_info);
    }

    // Create parent folders and file
    let path = std::path::Path::new(&file_uri);
    let prefix = path.parent().unwrap();
    std::fs::create_dir_all(prefix).unwrap();
    fs::write(file_uri.clone(), file_content).unwrap();
    file_uri
}

// This creates a default valid crl for the repo of the given CA
pub fn create_default_crl(serial: u64, crl_entries: Vec<CrlEntry>, cert_key_path: &str, ca_name: &str, conf: &RepoConfig) -> Bytes {
    create_default_crl_i(serial, crl_entries, cert_key_path, ca_name, true, conf)
}

// This creates a default valid crl for the repo of the given CA
pub fn create_default_crl_i(
    serial: u64,
    crl_entries: Vec<CrlEntry>,
    cert_key_path: &str,
    ca_name: &str,
    write_to_disc: bool,
    conf: &RepoConfig,
) -> Bytes {
    let ks = read_cert_key(cert_key_path);

    let pubkey = ks.get_pub_key();

    let file_content = create_crl_tbs(
        Default::default(),
        pubkey.to_subject_name(),
        Time::now(),
        Time::tomorrow(),
        crl_entries,
        pubkey.key_identifier(),
        serial.into(),
        ks,
    );
    if write_to_disc {
        write_object_to_disc(&file_content, "crl", cert_key_path, ca_name, conf);
    }

    file_content
}

// Create a new file_uri for an object in the rpki, in the same strucutre as Krill
pub fn uri_from_session_and_serial(session_id: Uuid, serial: u64, random_bytes: &str, conf: &RepoConfig) -> String {
    let file_uri =
        conf.BASE_RRDP_DIR_l.clone() + session_id.to_string().as_str() + "/" + serial.to_string().as_str() + "/" + random_bytes + "/";
    file_uri
}

// Create a new file_uri for an object in the rpki, in the same strucutre as Krill
pub fn uri_from_session_and_serial_random(session_id: Uuid, serial: u64, conf: &RepoConfig) -> String {
    let random = generate_random_bytes();
    let file_uri = uri_from_session_and_serial(session_id, serial, &random, conf);
    file_uri
}

// Find all deltas in the repository
// Some tests require additional deltas that can not be parsed
// So this function also takes additional deltas
pub fn get_deltas_in_repo(session_id: Uuid, additional_deltas: Option<Vec<DeltaWrapper>>, conf: &RepoConfig) -> Vec<DeltaWrapper> {
    let path = Path::new(&conf.BASE_RRDP_DIR_l);
    let p = path.join(session_id.to_string());
    let delta_paths = find_files_with_name(&p, "delta.xml");

    let (deltas, hashes) = parse_deltas_from_paths(delta_paths.clone());

    let mut del_paths = vec![];

    let end = cmp::min(delta_paths.len(), deltas.len());

    for i in 0..end {
        let delta = deltas[i].clone();
        let uri = delta_paths[i].to_string();
        let du = DeltaWrapper {
            delta,
            uri,
            hash: hashes[i],
        };
        del_paths.push(du);
    }
    if additional_deltas.is_some() {
        del_paths.extend(additional_deltas.unwrap());
    }

    let deltas = sort_deltas(del_paths);

    deltas
}

// Sort deltas by their serial number
pub fn sort_deltas(mut deltas: Vec<DeltaWrapper>) -> Vec<DeltaWrapper> {
    deltas.sort_by_key(|delta| delta.delta.serial());
    deltas
}

// Parse in Deltas from paths
pub fn parse_deltas_from_paths(paths: Vec<String>) -> (Vec<Delta>, Vec<Hash>) {
    let mut deltas = vec![];
    let mut hashes = vec![];
    for path in paths {
        let p = Path::new(&path);
        let file = fs::read(p).unwrap();
        let hash = Hash::from_data(file.as_slice());
        hashes.push(hash);

        let delta = Delta::parse(file.as_slice());
        if delta.is_ok() {
            deltas.push(delta.unwrap());
        } else {
        }
    }
    (deltas, hashes)
}

// Find files in the directory structure with a given filename
// Returns the paths to the files
pub fn find_files_with_name(session_path: &Path, filename: &str) -> Vec<String> {
    let mut filenames = vec![];
    for dir in fs::read_dir(session_path).unwrap() {
        let dirs = fs::read_dir(dir.unwrap().path()).unwrap();
        for serial_dir in dirs {
            let randoms = fs::read_dir(&serial_dir.unwrap().path()).unwrap();
            for entry in randoms {
                let en = entry.unwrap();
                if en.file_type().unwrap().is_file() && en.path().file_name().unwrap() == filename {
                    filenames.push(en.path().into_os_string().into_string().unwrap());
                    continue;
                } else if en.file_type().unwrap().is_dir() {
                    let files = fs::read_dir(en.path());
                    for file in files.unwrap() {
                        let fu = file.unwrap();
                        if fu.path().file_name().unwrap() == filename {
                            filenames.push(fu.path().into_os_string().into_string().unwrap());
                        }
                    }
                }
            }
        }
    }

    filenames
}

// Create a single Delta.xml and write it to the file system
pub fn create_delta(session_id: Uuid, serial: u64, elements: Vec<DeltaElement>) -> Delta {
    let delta = Delta::new(session_id, serial, elements);
    delta
}

// Write Delta file to filesystem in the same structure as Krill
pub fn write_delta_file(delta: Delta, file_uri: &str) -> io::Result<()> {
    let mut vec = vec![];
    delta.write_xml(&mut vec).unwrap();
    let xml = unsafe { str::from_utf8_unchecked(vec.as_ref()) };
    let xml_bytes = xml.as_bytes();
    create_directories(&file_uri.to_string());
    fs::write(file_uri, xml_bytes)
}

fn normalize_uri(uri: String) -> String {
    let uri = uri.replace("\\", "/");
    let uri = uri.replace("./", "");
    uri
}

// Create Notification.xml and write it to the file-system
// This requires the current Snapshot and Delta Files
// Delta_amount sets the amount of last delta files included in the notification
pub fn create_notification(
    snapshot_content: Bytes,
    deltas: Vec<DeltaWrapper>,
    snapshot_file: &str,
    delta_amount: usize,
    session_id: Uuid,
    serial: u64,
    conf: &RepoConfig,
) -> NotificationFile {
    let mut snapshot_uri = "https://".to_string() + &conf.DOMAIN + "/";
    let delta_file = snapshot_uri.clone();
    snapshot_uri.push_str(snapshot_file);

    let snapshot_uri = normalize_uri(snapshot_uri);

    let snapshot_hash = Hash::from_data(&snapshot_content);

    let uri = local_to_uri(snapshot_uri, &conf);

    let snapshot_info = UriAndHash::new(uri::Https::from_string(uri).unwrap(), snapshot_hash);

    let mut delta_infos = vec![];
    if deltas.len() > 0 {
        let l = deltas.len() as i128 - delta_amount as i128;
        for i in cmp::max(l, 0)..=deltas.len() as i128 - 1 {
            let index = i as usize;
            let delta = deltas[index].clone();
            let delta_hash = delta.hash;
            let mut delta_uri = delta_file.clone();
            delta_uri.push_str(delta.uri.clone().as_str());
            delta_uri = normalize_uri(delta_uri);
            delta_uri = local_to_uri(delta_uri, &conf);
            let delta_info = DeltaInfo::new(delta.delta.serial(), uri::Https::from_string(delta_uri).unwrap(), delta_hash);

            delta_infos.push(delta_info);
        }
    }

    let notification = NotificationFile::new(session_id, serial, snapshot_info, delta_infos);
    notification
}

// Creates a Sha256 Hash from the given Bytes Array
pub fn create_hash_content(file_content: &[u8]) -> std::string::String {
    digest_bytes(file_content)
}

// Creates a Sha256 Hash from the given Bytes Array
pub fn create_hash_file(file_uri_l: &str) -> std::string::String {
    digest_file(file_uri_l).unwrap()
}

// Reads in the current notification file to get the Session ID and Serial Number
pub fn get_current_session_notification(conf: &RepoConfig) -> (Uuid, u64) {
    // It might be usefull to store it seperately
    let not = conf.BASE_RRDP_DIR_l.clone() + "notification.xml";
    let path = Path::new(&not);

    if !path.exists() {
        let uuid = Uuid::new_v4();
        let serial = 1;
        return (uuid, serial);
    }
    let not_raw = fs::read(path).unwrap();
    let notfile = NotificationFile::parse(not_raw.as_slice()).unwrap();
    (notfile.session_id(), notfile.serial())
}

// Read in the File and generate its Hash
// This is required as update-elements in the Delta.xml File require the Hash of the previous object, the object they are updating
pub fn get_current_file_hash(file_extension: &str, ca_name: &str, conf: &RepoConfig) -> (Hash, String) {
    let folder = conf.BASE_REPO_DIR_l.clone() + ca_name + "/";
    let paths = fs::read_dir(folder).unwrap();
    let mut read_amount = 0;
    // This could be expanded to allow for multiple manifests / better error handling if no manifest exists
    for path in paths {
        read_amount += 1;
        let p1 = path.unwrap();
        let file_name = p1.file_name().into_string().unwrap();
        if file_name.contains(file_extension) {
            let file_content = fs::read(&p1.path()).unwrap();
            return (Hash::from_data(&file_content), file_name);
        }
    }

    // If no manifest exists yet -> Return empty hash
    return (Hash::from_str("").unwrap(), "".to_string());
}

// This only generates a random ROA and writes it to disc, without generating the other RRDP files
pub fn create_random_roa(conf: &RepoConfig) -> (Bytes, String) {
    let parent_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/" + &conf.CA_NAME + ".cer";
    let roa_string = generate_random_roa_string(10, 0, 0, 0);
    // println!("Generating random ROA: {}", roa_string);
    let ca_name = &conf.CA_NAME;
    (
        make_default_roa(
            &parent_cer_uri,
            &roa_string,
            &(conf.BASE_KEY_DIR_l.clone() + ca_name + ".der"),
            ca_name,
            true,
            None,
            conf,
        ),
        roa_string,
    )
}

// This only generates a random ROA and writes it to disc, without generating the other RRDP files
pub fn create_random_roa_ca(conf: &RepoConfig, ca_name: &str) -> (Bytes, String) {
    let parent_cer_uri =
        "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + &conf.CA_TREE.get(ca_name).unwrap() + "/" + ca_name + ".cer";
    let roa_string = generate_random_roa_string(10, 0, 0, 0);
    println!("Generating random ROA: {}", roa_string);
    (
        make_default_roa(
            &parent_cer_uri,
            &roa_string,
            &(conf.BASE_KEY_DIR_l.clone() + ca_name + ".der"),
            ca_name,
            true,
            None,
            conf,
        ),
        roa_string,
    )
}

// This generates a random ROA and all required rrdp files
pub fn add_roa_str(roa_string: &str, new_session: bool, conf: &RepoConfig) {
    let roa_base_uri = base_repo_uri(&conf.CA_NAME, conf);

    let parent_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/" + &conf.CA_NAME + ".cer";
    let ca_name = &conf.CA_NAME;
    add_roa_i(&roa_string, roa_base_uri, ca_name, &parent_cer_uri, new_session, conf);
}

// This generates a random ROA and all required rrdp files
pub fn add_random_roa(conf: &RepoConfig) {
    let roa_base_uri = base_repo_uri(&conf.CA_NAME, conf);

    let parent_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/" + &conf.CA_NAME + ".cer";
    let roa_string = generate_random_roa_string(10, 0, 0, 0);
    println!("Generating random ROA: {}", roa_string);
    let ca_name = &conf.CA_NAME;
    add_roa(&roa_string, roa_base_uri, ca_name, &parent_cer_uri, conf);
}

// This generates a random ROA and all required rrdp files
pub fn add_random_roa_ca(conf: &RepoConfig, ca_name: &str) {
    let roa_base_uri = base_repo_uri(ca_name, conf);

    let parent_cer_uri =
        "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + &conf.CA_TREE.get(ca_name).unwrap() + "/" + ca_name + ".cer";
    let roa_string = generate_random_roa_string(10, 0, 0, 0);
    println!("Generating random ROA: {}", roa_string);
    //let ca_name = &conf.CA_NAME;
    add_roa(&roa_string, roa_base_uri, ca_name, &parent_cer_uri, conf);
}

// This generates will add an invalid ROA
pub fn add_random_roa_invalid(conf: &RepoConfig) {
    let roa_base_uri = base_repo_uri(&conf.CA_NAME, conf);

    let parent_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/" + &conf.CA_NAME + ".cer";
    let roa_string = generate_random_roa_string(10, 0, 0, 0);

    println!("Generating random ROA: {}", roa_string);

    let ca_name = &conf.CA_NAME;

    let roa_content = make_default_roa(
        &parent_cer_uri,
        &roa_string,
        &(conf.BASE_KEY_DIR.to_string() + ca_name + ".der"),
        ca_name,
        false,
        None,
        conf,
    );
    after_roa_creation(&roa_string, roa_base_uri, ca_name, roa_content, false, conf);
}

pub fn add_roa(roa_string: &str, roa_base_uri: String, ca_name: &str, parent_cer_uri_l: &str, conf: &RepoConfig) {
    add_roa_i(roa_string, roa_base_uri, ca_name, parent_cer_uri_l, false, conf);
}

// Add a new roa to the repo
pub fn add_roa_i(roa_string: &str, roa_base_uri: String, ca_name: &str, parent_cer_uri_l: &str, new_session: bool, conf: &RepoConfig) {
    let roa_content = make_default_roa(
        parent_cer_uri_l,
        &roa_string,
        &(conf.BASE_KEY_DIR.to_string() + ca_name + ".der"),
        ca_name,
        true,
        None,
        conf,
    );
    after_roa_creation(roa_string, roa_base_uri, ca_name, roa_content, new_session, conf);
}

// Create all elements for the Delta file after a single change
pub fn create_delta_elements_multi_update(
    ca_name: &str,
    roa_contents: Vec<Bytes>,
    manifest_content: Bytes,
    crl_content: Bytes,
    roa_hash: Vec<Hash>,
    manifest_hash: Hash,
    roa_file_names: Vec<String>,
    file_name_mft: String,
    crl_hash: Hash,
    file_name_crl: String,
    conf: &RepoConfig,
) -> (Vec<PublishElement>, Vec<UpdateElement>) {
    let mut base_uri_mft = base_repo_uri(ca_name, conf);
    let mut base_uri_crl = base_uri_mft.clone();
    let base_uri_roa = base_uri_mft.clone();

    base_uri_mft.push_str(file_name_mft.as_str());
    base_uri_crl.push_str(file_name_crl.as_str());

    let rsync_uri_mft = uri::Rsync::from_str(&base_uri_mft).unwrap();

    let new_elements_delta = vec![];

    let mut update_elements_delta = vec![];

    for i in 0..roa_contents.len() {
        let rsync_uri_roa_s = base_uri_roa.clone() + &roa_file_names[i].clone();
        let rsync_uri_roa = uri::Rsync::from_str(&rsync_uri_roa_s).unwrap();

        update_elements_delta.push(UpdateElement::new(rsync_uri_roa, roa_hash[i], roa_contents[i].clone()));
    }

    let rsync_uri_crl = uri::Rsync::from_str(&base_uri_crl).unwrap();

    update_elements_delta.push(UpdateElement::new(rsync_uri_mft, manifest_hash, manifest_content));

    update_elements_delta.push(UpdateElement::new(rsync_uri_crl, crl_hash, crl_content));

    (new_elements_delta, update_elements_delta)
}

pub fn create_delta_elements_multi_publish(
    ca_name: &str,
    roa_contents: Vec<Bytes>,
    manifest_content: Bytes,
    crl_content: Bytes,
    manifest_hash: Hash,
    roa_file_names: Vec<String>,
    file_name_mft: String,
    crl_hash: Hash,
    file_name_crl: String,
    conf: &RepoConfig,
) -> (Vec<PublishElement>, Vec<UpdateElement>) {
    let mut base_uri_mft = base_repo_uri(ca_name, conf);
    let mut base_uri_crl = base_uri_mft.clone();
    let base_uri_roa = base_uri_mft.clone();

    base_uri_mft.push_str(file_name_mft.as_str());
    base_uri_crl.push_str(file_name_crl.as_str());

    let rsync_uri_mft = uri::Rsync::from_str(&base_uri_mft).unwrap();

    let mut update_elements_delta = vec![];

    let mut new_elements_delta = vec![];

    for i in 0..roa_contents.len() {
        let rsync_uri_roa_s = base_uri_roa.clone() + &roa_file_names[i].clone();
        let rsync_uri_roa = uri::Rsync::from_str(&rsync_uri_roa_s).unwrap();
        new_elements_delta.push(PublishElement::new(rsync_uri_roa, roa_contents[i].clone()));
    }

    let rsync_uri_crl = uri::Rsync::from_str(&base_uri_crl).unwrap();

    update_elements_delta.push(UpdateElement::new(rsync_uri_mft, manifest_hash, manifest_content));

    update_elements_delta.push(UpdateElement::new(rsync_uri_crl, crl_hash, crl_content));

    (new_elements_delta, update_elements_delta)
}

// Create all elements for the Delta file after a single change
pub fn create_delta_elements_single(
    ca_name: &str,
    roa_file_name: &str,
    roa_content: Bytes,
    manifest_content: Bytes,
    crl_content: Bytes,
    manifest_hash: Hash,
    file_name_mft: String,
    crl_hash: Hash,
    file_name_crl: String,
    conf: &RepoConfig,
) -> (Vec<PublishElement>, Vec<UpdateElement>) {
    let roa_contents = vec![roa_content];
    let roa_file_names = vec![roa_file_name.to_string()];

    create_delta_elements_multi_publish(
        ca_name,
        roa_contents,
        manifest_content,
        crl_content,
        manifest_hash,
        roa_file_names,
        file_name_mft,
        crl_hash,
        file_name_crl,
        conf,
    )
}

pub fn refresh_roas_in_repo(conf: &RepoConfig) {
    let roa_files = repository_contains_file(&conf.BASE_DATA_DIR, ".roa", true);

    let ca_name = &conf.CA_NAME;

    let cert_key_uri_l = &(conf.BASE_KEY_DIR.to_string() + ca_name + ".der");

    let (manifest_hash, file_name_mft) = get_current_file_hash(".mft", ca_name, conf);
    let (crl_hash, file_name_crl) = get_current_file_hash(".crl", ca_name, conf);

    let (session_id, serial_number) = get_current_session_notification(conf);
    let serial_number = serial_number + 1;

    let mut base_uri_mft = base_repo_uri(ca_name, conf);
    let mut base_uri_crl = base_uri_mft.clone();

    base_uri_mft.push_str(file_name_mft.as_str());
    base_uri_crl.push_str(file_name_crl.as_str());

    let rsync_uri_mft = uri::Rsync::from_str(&base_uri_mft).unwrap();
    let rsync_uri_crl = uri::Rsync::from_str(&base_uri_crl).unwrap();

    let crl_content = create_default_crl(
        serial_number,
        vec![],
        &(conf.BASE_KEY_DIR.clone() + ca_name + ".der"),
        ca_name,
        conf,
    );
    let manifest_content = make_manifest(&conf.CA_NAME, "ta", conf);

    let ca_issuer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/" + &conf.CA_NAME + ".cer";

    let issuer_rsync = uri::Rsync::from_str(&ca_issuer_uri).unwrap();

    let mut hashes = vec![];
    let mut file_name_roa = vec![];
    let mut roa_contents = vec![];

    for roa_file in roa_files {
        let ks = read_cert_key(&cert_key_uri_l);

        let c: Vec<String> = vec![roa_file.clone().split("/").collect()];
        let b = &c[c.len() - 1];
        file_name_roa.push(b.clone());
        let der = fs::read(&roa_file).unwrap();
        let der_bytes = Bytes::from(der.clone());
        hashes.push(Hash::from_data(&der));

        let roa = adapted_functions::roa_alt::Roa::decode(der_bytes, true).unwrap();
        let content = roa.content;
        let roa_str = roa_string_from_content(content);
        let (roa_build, _) = process_roa_string(&roa_str).unwrap();

        let roa_content = adapted_functions::overwritten_functions::encode_ref_roa_builder(
            roa_build,
            rsync_uri_crl.clone(),
            issuer_rsync.clone(),
            rsync_uri_mft.clone(),
            ks,
            None,
            conf,
        );
        write_object_to_disc(&roa_content, "roa", &roa_str, ca_name, conf);

        roa_contents.push(roa_content);
    }

    let (new_elements_delta, update_elements_delta) = create_delta_elements_multi_update(
        ca_name,
        roa_contents,
        manifest_content,
        crl_content,
        hashes,
        manifest_hash,
        file_name_roa,
        file_name_mft,
        crl_hash,
        file_name_crl,
        conf,
    );

    finalize_snap_notification(session_id, serial_number, new_elements_delta, update_elements_delta, conf);
}

// This function handles everything after multiple ROAs were created
pub fn after_roas_creation(roa_file_names: Vec<String>, roa_contents: Vec<Bytes>, parent_name: &str, conf: &RepoConfig, new_session: bool) {
    let mut serial_number = 1;
    let mut session_id = Uuid::new_v4();
    if !new_session {
        (session_id, serial_number) = get_current_session_notification(conf);
        serial_number = serial_number + 1;
    }

    let crl_content = create_default_crl(
        serial_number,
        vec![],
        &(conf.BASE_KEY_DIR.clone() + &conf.CA_NAME + ".der"),
        &conf.CA_NAME,
        conf,
    );

    let manifest_content;

    manifest_content = make_manifest(&conf.CA_NAME, parent_name, conf);

    let new_elements_delta;
    let update_elements_delta;
    if !new_session {
        let (manifest_hash, file_name_mft) = get_current_file_hash(".mft", &conf.CA_NAME, conf);
        let (crl_hash, file_name_crl) = get_current_file_hash(".crl", &conf.CA_NAME, conf);

        (new_elements_delta, update_elements_delta) = create_delta_elements_multi_publish(
            &conf.CA_NAME,
            roa_contents,
            manifest_content,
            crl_content,
            manifest_hash,
            roa_file_names,
            file_name_mft,
            crl_hash,
            file_name_crl,
            conf,
        );
    } else {
        new_elements_delta = vec![];
        update_elements_delta = vec![];
    }

    finalize_snap_notification(session_id, serial_number, new_elements_delta, update_elements_delta, conf);
}

pub fn after_roa_creation(
    roa_string: &str,
    mut roa_base_uri: String,
    ca_name: &str,
    roa_content: Bytes,
    new_session: bool,
    conf: &RepoConfig,
) {
    // These steps represent a serial iteration of rrdp
    // New roa -> New mft -> New CRL -> New Delta -> New Snapshot -> New Notification
    let roa_filename = file_name_for_object(roa_string, ".roa");

    let (session_id, serial_number) = get_current_session_notification(conf);
    let serial_number = serial_number + 1;

    let crl_content = create_default_crl(
        serial_number,
        vec![],
        &(conf.BASE_KEY_DIR.clone() + ca_name + ".der"),
        ca_name,
        conf,
    );

    roa_base_uri.push_str(roa_filename.as_str());

    let manifest_content = make_manifest(ca_name, &conf.CA_TREE.get(ca_name).unwrap(), conf);

    if !new_session {
        let (manifest_hash, file_name_mft) = get_current_file_hash(".mft", ca_name, conf);
        let (crl_hash, file_name_crl) = get_current_file_hash(".crl", ca_name, conf);

        let (new_elements_delta, update_elements_delta) = create_delta_elements_single(
            ca_name,
            &roa_filename,
            roa_content,
            manifest_content,
            crl_content,
            manifest_hash,
            file_name_mft,
            crl_hash,
            file_name_crl,
            conf,
        );

        finalize_snap_notification(session_id, serial_number, new_elements_delta, update_elements_delta, conf);
    } else {
        finalize_snap_notification(session_id, serial_number, vec![], vec![], conf);
    }
}

// Create current snapshot with the objects
pub fn create_current_snapshot_objects(objects: Vec<(String, Vec<u8>)>, conf: &RepoConfig) -> (Bytes, String, Uuid) {
    let mut new_elements = vec![];
    for obj in objects {
        let base_path = "rsync://".to_string() + &conf.DOMAIN_l + "/" + obj.0.as_str();

        let content = Bytes::from(obj.1);
        let uri_l = normalize_uri(base_path);

        let uri = local_to_uri(uri_l, &conf);

        new_elements.push(PublishElement::new(uri::Rsync::from_string(uri).unwrap(), content));
    }

    let session_id = Uuid::new_v4();
    let serial = 1;

    let snapshot = Snapshot::new(session_id, serial, new_elements);
    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);
    let mut filename = uri_from_session_and_serial_random(session_id, serial, conf);
    filename.push_str("snapshot.xml");

    (snapshot_bytes, filename, session_id)
}

pub fn create_snapshot_notification_objects(objects: Vec<(String, Vec<u8>)>, conf: &RepoConfig) -> (String, Vec<u8>, String, Vec<u8>) {
    let (snapshot_bytes, snapshot_filename, session_id) = create_current_snapshot_objects(objects, conf);
    let notification = create_notification(snapshot_bytes.clone(), vec![], &snapshot_filename, 5, session_id, 1, conf);

    let mut vec = vec![];
    notification.write_xml(&mut vec).unwrap();
    // let notification_bytes = Bytes::from(vec);
    let notification_filename = conf.BASE_RRDP_DIR_l.clone() + "notification.xml";

    (snapshot_filename, snapshot_bytes.to_vec(), notification_filename, vec)
}

pub fn finalize_snap_notification(
    session_id: Uuid,
    serial_number: u64,
    new_elements_delta: Vec<PublishElement>,
    update_elements_delta: Vec<UpdateElement>,
    conf: &RepoConfig,
) {
    // The last step in the process -> Create the current snapshot and notifiation file
    let (snapshot, snapshot_uri) = create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    // let (session_id, serial) = get_current_session_notification(conf);
    // let serial = serial + 1;

    let notification;
    if new_elements_delta.len() > 0 || update_elements_delta.len() > 0 {
        add_elements_to_delta(new_elements_delta, update_elements_delta, session_id, serial_number, conf).unwrap();

        let deltas = get_deltas_in_repo(session_id, None, conf);

        notification = create_notification(snapshot_bytes, deltas, &snapshot_uri, 5, session_id, serial_number, conf);
    } else {
        notification = create_notification(snapshot_bytes, vec![], &snapshot_uri, 5, session_id, serial_number, conf);
    }
    write_notification_file(notification, conf).unwrap();
}

// Write notification file to disc
pub fn write_notification_file(notification: NotificationFile, conf: &RepoConfig) -> io::Result<()> {
    let mut vec = vec![];
    notification.write_xml(&mut vec).unwrap();
    let xml = unsafe { str::from_utf8_unchecked(vec.as_ref()) };
    let xml_bytes = xml.as_bytes();

    write_notification_file_bytes(&xml_bytes, conf)
}

pub fn write_notification_file_bytes(notification: &[u8], conf: &RepoConfig) -> io::Result<()> {
    let file_uri = conf.BASE_RRDP_DIR_l.clone() + "notification.xml";
    create_directories(&file_uri);

    fs::write(&file_uri, &notification)
}

// The Rsync URI describes the storage location -> This deductes the storage location from a uri
pub fn filename_from_uri(uri: &uri::Rsync) -> String {
    let u = uri.to_string();
    let u2 = u.split("/");
    let uri_vec: Vec<&str> = u2.collect();
    let file_name = uri_vec.last();
    file_name.unwrap().to_string()
}

pub fn make_manifest_objects(ca_name: &str, parent_name: &str, conf: &RepoConfig, objects: Vec<(String, Vec<u8>)>) -> Bytes {
    let serial = random_serial();

    // Keys are stored as ca_name.der
    let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";

    let ks = read_cert_key(&cert_key_uri);

    let storage_base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + ca_name + "/";

    let filename = get_filename_crl_mft(&cert_key_uri);

    let mut mft_uri = storage_base_uri.clone();
    mft_uri.push_str(&filename);

    let mut crl_uri = mft_uri.clone();

    mft_uri.push_str(".mft");
    crl_uri.push_str(".crl");

    let mft_rsync = uri::Rsync::from_str(&mft_uri).unwrap();
    let crl_rsync = uri::Rsync::from_str(&crl_uri).unwrap();

    let mut issuer_cer = "rsync://".to_string() + &conf.DOMAIN + "/";

    // If the parent is root -> It has to be treated differently
    if parent_name == "root" {
        issuer_cer.push_str((conf.BASE_TAL_DIR.clone() + "root.cer").as_str());
    } else {
        issuer_cer.push_str((conf.BASE_REPO_DIR.clone() + parent_name + "/" + ca_name + ".cer").as_str());
    }

    let issuer_rsync = uri::Rsync::from_str(&issuer_cer).unwrap();
    let mut vector = vec![];
    for element in &objects {
        let data = &element.1;
        let algo = DigestAlgorithm::sha256();
        let digest = algo.digest(&data);
        vector.push(FileAndHash::new(element.0.clone(), digest));
    }

    let content = ManifestContent::new(serial, Time::now(), Time::tomorrow(), DigestAlgorithm::default(), vector.iter());

    let file_content =
        adapted_functions::overwritten_functions::encode_ref_manifest_content(content, crl_rsync, issuer_rsync, mft_rsync, ks, None);

    file_content
}

pub fn make_manifest_i(ca_name: &str, parent_name: &str, conf: &RepoConfig, excluded: Option<Vec<String>>) -> Bytes {
    let serial = random_serial();

    // Keys are stored as ca_name.der
    let cert_key_uri = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";

    let ks = read_cert_key(&cert_key_uri);

    let storage_base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + ca_name + "/";

    let filename = get_filename_crl_mft(&cert_key_uri);

    let mut mft_uri = storage_base_uri.clone();
    mft_uri.push_str(&filename);

    let mut crl_uri = mft_uri.clone();

    mft_uri.push_str(".mft");
    crl_uri.push_str(".crl");

    let mft_rsync = uri::Rsync::from_str(&mft_uri).unwrap();
    let crl_rsync = uri::Rsync::from_str(&crl_uri).unwrap();

    let storage_diectory_l = conf.BASE_REPO_DIR_l.clone() + ca_name + "/";

    let mut issuer_cer = "rsync://".to_string() + &conf.DOMAIN + "/";

    // If the parent is root -> It has to be treated differently
    if parent_name == "root" {
        issuer_cer.push_str((conf.BASE_TAL_DIR.clone() + "root.cer").as_str());
    } else {
        issuer_cer.push_str((conf.BASE_REPO_DIR.clone() + parent_name + "/" + ca_name + ".cer").as_str());
    }

    let issuer_rsync = uri::Rsync::from_str(&issuer_cer).unwrap();

    let snapshot_elements = read_published_elements(Some(filename + ".mft"), storage_diectory_l.as_str(), false, conf, None);

    let mut vector = vec![];
    let excluding = match excluded {
        Some(ex) => ex,
        None => vec![],
    };
    for element in &snapshot_elements {
        let file_name = filename_from_uri(element.uri());
        if excluding.contains(&file_name) {
            continue;
        }
        let data = element.data();
        let algo = DigestAlgorithm::sha256();
        let digest = algo.digest(&data);
        vector.push(FileAndHash::new(file_name, digest));
    }

    vector.reverse();

    let content = ManifestContent::new(
        serial,
        Time::now() - Duration::from_std(std::time::Duration::from_secs(7000)).unwrap(),
        Time::tomorrow() + Duration::from_std(std::time::Duration::from_secs(7000)).unwrap(),
        DigestAlgorithm::default(),
        vector.iter(),
    );

    let file_content =
        adapted_functions::overwritten_functions::encode_ref_manifest_content(content, crl_rsync, issuer_rsync, mft_rsync, ks, None);

    write_object_to_disc(&file_content, "mft", &cert_key_uri, ca_name, conf);

    file_content
}

// Make new manifest
pub fn make_manifest(ca_name: &str, parent_name: &str, conf: &RepoConfig) -> Bytes {
    make_manifest_i(ca_name, parent_name, conf, None)
}

// Generate the Filename for RPKI Objects -> This uses the same names as Krill
pub fn file_name_for_object(object_string: &str, file_extension: &str) -> String {
    let mut hex_encoded = hex::encode(object_string);
    hex_encoded.push_str(file_extension);
    hex_encoded
}

pub fn base_repo_uri(ca_name: &str, conf: &RepoConfig) -> String {
    let domain = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + ca_name + "/";
    domain
}

// Create a new Route Origin Attestation
pub fn make_default_roa(
    ca_issuer_uri: &str,
    roa_string: &str,
    cert_key_uri_l: &str,
    ca_name: &str,
    write_to_disc: bool,
    roa_name: Option<&str>,
    conf: &RepoConfig,
) -> Bytes {
    // Create a Roa with the Cert Key
    let ks = read_cert_key(&cert_key_uri_l);
    // Uri of Repo of this CA
    let uri = base_repo_uri(ca_name, conf);

    let mut roa_uri = uri.clone();
    let filename = file_name_for_object(&roa_string, ".roa");
    roa_uri.push_str(filename.as_str());
    let uri_rsync = uri::Rsync::from_str(&roa_uri).unwrap();

    let (roa_builder, _) = process_roa_string(roa_string).unwrap();

    let mut crl_uri = uri.clone();

    crl_uri.push_str(get_filename_crl_mft(cert_key_uri_l).as_str());
    crl_uri.push_str(".crl");

    let issuer_rsync = uri::Rsync::from_str(ca_issuer_uri).unwrap();
    let crl_rsync = uri::Rsync::from_str(crl_uri.as_str()).unwrap();

    let file_content =
        adapted_functions::overwritten_functions::encode_ref_roa_builder(roa_builder, crl_rsync, issuer_rsync, uri_rsync, ks, None, conf);

    if write_to_disc {
        write_object_to_disc(&file_content, "roa", roa_string, ca_name, conf);
    }

    file_content
}

// The delta file containes two types of elements, publish (new objects) and update (updating existing elements)
pub fn create_delta_from_elements(
    pub_elements: Vec<PublishElement>,
    up_elements: Vec<UpdateElement>,
    session_id: Uuid,
    serial_number: u64,
) -> Delta {
    let mut delta_vec = vec![];
    for element in pub_elements {
        delta_vec.push(DeltaElement::from(element));
    }
    for element in up_elements {
        delta_vec.push(DeltaElement::from(element));
    }

    let delta = create_delta(session_id, serial_number, delta_vec);
    delta
}

pub fn add_elements_to_delta(
    pub_elements: Vec<PublishElement>,
    up_elements: Vec<UpdateElement>,
    session_id: Uuid,
    serial_number: u64,
    conf: &RepoConfig,
) -> io::Result<()> {
    let delta = create_delta_from_elements(pub_elements, up_elements, session_id, serial_number);

    let mut file_uri = uri_from_session_and_serial_random(session_id, serial_number, conf);
    file_uri.push_str("delta.xml");

    write_delta_file(delta, &file_uri)
}

// Search for a specific filename in the target dir, recursivly
// Can be used to find out if file was saved at a critical place
pub fn repository_contains_file(target_dir: &str, filename: &str, search_extension: bool) -> Vec<String> {
    let mut found_files = vec![];
    for entry in WalkDir::new(target_dir).follow_links(true).into_iter() {
        let e = entry.unwrap();
        let path = e.path().to_str();
        let p = path.unwrap().to_owned();
        let f_name = e.file_name().to_string_lossy().to_string();
        if search_extension && f_name.ends_with(filename) {
            found_files.push(p);
        } else if !search_extension && f_name == filename {
            found_files.push(p);
        }
    }
    found_files
}

// Read all currently published Elements of this Repo from the repo folder
// Fixed base path allows to search at an other place than the base repo dir
// Deep search also searches for objects with a fitting extension in subfolders
pub fn read_published_elements(
    exclude_file: Option<String>,
    fixed_base_path: &str,
    deep_search: bool,
    conf: &RepoConfig,
    excluded_folders: Option<Vec<String>>,
) -> Vec<PublishElement> {
    // let mut pathvector = vec![];
    let mut new_elements = vec![];
    let mut folder = "";
    let mut pos_paths = vec![];

    let excluding = match excluded_folders {
        Some(ex) => ex,
        None => vec![],
    };

    // TODO Make this prettier
    if fixed_base_path == "" {
        folder = &conf.BASE_REPO_DIR_l;
        let paths = fs::read_dir(folder).unwrap();

        for path in paths {
            let p1 = path.unwrap();
            if p1.file_type().unwrap().is_dir() {
                // This might run into problems if the max-open-file amount in the OS is not large enough
                if excluding.contains(&p1.path().to_str().unwrap().to_string()) {
                    continue;
                }
                let dirs = fs::read_dir(p1.path()).unwrap();
                for path in dirs {
                    let p1 = path.unwrap();
                    if p1.path().is_dir() {
                        continue;
                    }
                    pos_paths.push(p1.path().to_str().unwrap().to_string());
                }

                // pathvector.push(dirs);
            }
        }
    } else {
        folder = fixed_base_path.clone();
        for path in fs::read_dir(fixed_base_path).unwrap() {
            let p1 = path.unwrap();
            if p1.path().is_dir() {
                continue;
            }
            pos_paths.push(p1.path().to_str().unwrap().to_string());
        }
        // pathvector.push();
    }

    // for path_dir in pathvector {
    //     for path in path_dir {
    //         let p1 = path.unwrap();
    //         if p1.path().is_dir() {
    //             continue;
    //         }
    //         pos_paths.push(p1.path().to_str().unwrap().to_string());
    //     }
    // }

    if deep_search {
        let object_extensions = vec![".roa", ".mft", ".crl", ".gbr"];
        for extension in object_extensions {
            let paths = repository_contains_file(&folder, extension, true);
            for path in paths {
                if !pos_paths.contains(&path) {
                    pos_paths.push(path);
                }
            }
        }
    }
    for p in pos_paths {
        let file_content = fs::read(&p).unwrap();

        if exclude_file.clone().is_some() && p.contains(&exclude_file.clone().unwrap()) {
            continue;
        }

        let base_path = "rsync://".to_string() + &conf.DOMAIN_l + "/" + p.as_str();

        let content = Bytes::from(file_content);
        let uri_l = normalize_uri(base_path);

        let uri = local_to_uri(uri_l, &conf);

        new_elements.push(PublishElement::new(uri::Rsync::from_string(uri).unwrap(), content));
    }

    new_elements
}

// Create a Snapshot from all currently published elements
pub fn create_current_snapshot(
    session_id: Uuid,
    serial_number: u64,
    addtional_elements: Option<Vec<PublishElement>>,
    deep_search: bool,
    conf: &RepoConfig,
    excluded_folders: Option<Vec<String>>,
    excluded_files: Option<Vec<String>>,
) -> (Snapshot, String) {
    // Read all elements from repo folder to create snapshot
    let mut elements = read_published_elements(None, "", deep_search, conf, excluded_folders);
    // let excluding = match excluded_files {
    //     Some(ex) => ex,
    //     None => vec![],
    // };

    if addtional_elements.is_some() {
        elements.extend(addtional_elements.unwrap());
    }

    let mut upels = vec![];
    if excluded_files.is_some() {
        let excluding = excluded_files.unwrap();
        for element in elements {
            let file_name = filename_from_uri(element.uri());
            if excluding.contains(&file_name) {
                continue;
            }
            upels.push(element);
        }
    } else {
        upels = elements;
    }

    let snapshot = Snapshot::new(session_id, serial_number, upels);
    let filename = write_snapshot_file(snapshot.clone(), session_id, serial_number, conf);
    (snapshot, filename)
}

// Create all necessary directories for a file-path
pub fn create_directories(filepath: &String) {
    let path = Path::new(&filepath);
    let prefix = path.parent().unwrap();
    std::fs::create_dir_all(prefix).unwrap();
}

// Write Snapshot-File to disc
pub fn write_snapshot_file(snapshot: Snapshot, session_id: Uuid, serial: u64, conf: &RepoConfig) -> String {
    let mut vec = vec![];
    snapshot.write_xml(&mut vec).unwrap();

    let xml = unsafe { str::from_utf8_unchecked(vec.as_ref()) };
    let xml_bytes = xml.as_bytes();
    write_snapshot_file_bytes(xml_bytes, session_id, serial, conf)
}

pub fn write_snapshot_file_bytes(data: &[u8], session_id: Uuid, serial: u64, conf: &RepoConfig) -> String {
    let mut filename = uri_from_session_and_serial_random(session_id, serial, conf);
    filename.push_str("snapshot.xml");
    create_directories(&filename);

    fs::write(&filename, &data).unwrap();
    filename
}

// Create a new tal -> Only required in the setup process
pub fn create_tal(cert_uri: &str, httpsuri: &str, rsyncuri: &str, tal_uri: &str) -> io::Result<()> {
    let der = fs::read(cert_uri).unwrap();
    let by = der;
    let cert = Cert::decode(Bytes::from(by));
    let cert = cert.unwrap();

    let b64 = base64::encode(&cert.subject_public_key_info().to_info_bytes());

    let mut final_string: String = "".to_owned();
    final_string.push_str(httpsuri);
    final_string.push_str("\n");
    final_string.push_str(rsyncuri);
    final_string.push_str("\n\n");
    final_string.push_str(&b64.to_string());
    final_string.push_str("\n");

    fs::write(tal_uri, &final_string)
}

// pub fn read_ca_cert() -> ResourceCert {
// 	let content_ta = fs::read("./data/tal/root_ca.cer").unwrap();
// 	let decoded_ta = Cert::decode(Bytes::from(content_ta)).unwrap();
// 	let talinfo = TalInfo::from_name("root_ca.tal".into()).into_arc();
// 	let rescert = decoded_ta.validate_ta(talinfo, true).unwrap();

// 	let content = fs::read("./data/repo/ta/new_ca.cer").unwrap();
// 	let decoded = Cert::decode(Bytes::from(content)).unwrap();

// 	decoded.validate_ca(&rescert, true).unwrap()
// }

pub fn create_default_tal(conf: &RepoConfig) {
    let ta_cer_uri = conf.BASE_TA_DIR_l.clone() + "ta.cer";
    let tal_uri = conf.BASE_TAL_DIR_l.clone() + "ta.tal";

    let tal_https_uri = "https://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_TA_DIR + "ta.cer";
    let tal_rsync_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_TA_DIR + "ta.cer";

    create_tal(&ta_cer_uri, &tal_https_uri, &tal_rsync_uri, &tal_uri).unwrap();
}

pub fn create_default_ta(new_keys: bool, conf: &mut RepoConfig) {
    let parent_cert_key_uri_l = "";
    let notification_uri = "https://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_RRDP_DIR_l + "notification.xml";
    let ca_name = "ta";
    let resource_block = Prefix::new(
        Ipv4Addr::new(conf.DEFAULT_IPSPACE_FIRST_OCTET.into(), conf.DEFAULT_IPSPACE_SEC_OCTET.into(), 0, 0),
        conf.DEFAULT_IPSPACE_PREFIX,
    );
    let asn_min = Asn::from_u32(conf.DEFAULT_AS_RESOURCES_MIN);
    let asn_max = Asn::from_u32(conf.DEFAULT_AS_RESOURCES_MAX);
    let issuer_cer_uri = "";
    let parent_name = "root";
    let parents_parent_name = "";
    let ta = true;

    conf.CA_TREE.insert("ta".to_string(), "root".to_string());

    create_ca(
        parent_cert_key_uri_l,
        &conf.BASE_TA_DIR_l,
        &notification_uri,
        ca_name,
        resource_block,
        asn_min,
        asn_max,
        issuer_cer_uri,
        parent_name,
        parents_parent_name,
        ta,
        "RSA",
        new_keys,
        &conf,
        true,
    );
}

pub fn create_default_config_abs(domain: String, base: String, port: String) -> RepoConfig {
    let base_dir = "data/".to_string() + &domain + "/";
    let first_octet = 10;
    let second_octet = 0;
    let prefix = 16;
    let as_min = 0;
    let as_max = 1000000;
    let ssl_pem_uri_l = "certs/".to_string() + &domain + ".crt";
    let ca_name = "newca".to_string();

    let ipv4 = vec![Ipv4Net::new(Ipv4Addr::new(first_octet, second_octet, 0, 0), prefix).unwrap()];

    let ipblocks = vec![(
        4,
        IpBlock::from(resources::Prefix::new(Ipv4Addr::new(first_octet, second_octet, 0, 0), prefix)),
    )];

    let mut c = RepoConfig::new(
        base_dir,
        domain.clone() + &port,
        first_octet,
        second_octet,
        prefix,
        as_min,
        as_max,
        ssl_pem_uri_l,
        ca_name,
        "",
        ipv4,
        ipblocks,
    );
    c.BASE_KEY_DIR = "data/keys/".to_string();
    c.BASE_TAL_DIR = "data/tals/".to_string();
    c.BASE_TA_DIR = "data/".to_string() + &domain + "/tal/";
    c.CA_TREE.insert("newca".to_string(), "ta".to_string());
    let c = c.default_locals_a(base, domain);
    c
}

pub fn create_default_config(domain: String) -> RepoConfig {
    return create_default_config_abs(domain, "".to_string(), "".to_string());
}

pub fn create_alt_config(domain: String, port: String) -> RepoConfig {
    let base_dir = "data/".to_string() + &domain + "/";
    let first_octet = 10;
    let second_octet = 0;
    let prefix = 16;
    let as_min = 0;
    let as_max = 1000;
    let ssl_pem_uri_l = "certs/".to_string() + &domain + ".crt";
    let ca_name = "newca".to_string();
    let ipv4 = vec![Ipv4Net::new(Ipv4Addr::new(first_octet, second_octet, 0, 0), prefix).unwrap()];
    let ipblock = vec![(
        4,
        IpBlock::from(resources::Prefix::new(Ipv4Addr::new(first_octet, second_octet, 0, 0), prefix)),
    )];

    let mut c = RepoConfig::new(
        base_dir,
        domain.clone() + &port,
        first_octet,
        second_octet,
        prefix,
        as_min,
        as_max,
        ssl_pem_uri_l,
        ca_name,
        "",
        ipv4,
        ipblock,
    );
    c.BASE_KEY_DIR = "data/keys/".to_string();
    c.BASE_TAL_DIR = "data/tals/".to_string();
    c.BASE_TA_DIR = "data/".to_string() + &domain + "2/tal/";

    let mut c = c.default_locals();

    let base_dir_l = "data/".to_string() + &domain + "2/";
    let base_rrdp_l = base_dir_l.clone() + "rrdp/";
    let base_repo_l = base_dir_l.clone() + "repo/";
    //c.BASE_TAL_DIR_l = base_dir_l.clone() + "tal/";
    //c.BASE_KEY_DIR_l = base_dir_l.clone() + "keys/";

    c.BASE_DATA_DIR_l = base_dir_l;
    c.BASE_REPO_DIR_l = base_repo_l;
    c.BASE_RRDP_DIR_l = base_rrdp_l;
    c.DOMAIN_l = "consts::domain2".to_string();

    c
}

pub fn create_multiple_cas(new_keys: bool, conf: &mut RepoConfig) {
    let names = ["ca1", "ca2"];

    for name in names {
        let parent_cert_key_uri_l = conf.BASE_KEY_DIR_l.clone() + "ta.der";
        let parent_repo_uri_l = conf.BASE_REPO_DIR_l.to_string() + "ta/";
        let notification_uri = "https://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_RRDP_DIR_l + "notification.xml";
        let ca_name = name;
        let resource_block = Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 16);
        let asn_min = Asn::from_u32(0);
        let asn_max = Asn::from_u32(1000000);

        let issuer_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_TA_DIR + "ta.cer";
        let parent_name = "ta";
        let parents_parent_name = "root";
        let ta = false;

        conf.CA_TREE.insert(name.to_string(), "ta".to_string());

        create_ca(
            &parent_cert_key_uri_l,
            &parent_repo_uri_l,
            &notification_uri,
            ca_name,
            resource_block,
            asn_min,
            asn_max,
            &issuer_cer_uri,
            parent_name,
            parents_parent_name,
            ta,
            "RSA",
            new_keys,
            &conf,
            false,
        );
    }
}

pub fn create_default_ca(new_keys: bool, conf: &mut RepoConfig) {
    let parent_cert_key_uri_l = conf.BASE_KEY_DIR_l.clone() + "ta.der";
    let parent_repo_uri_l = conf.BASE_REPO_DIR_l.to_string() + "ta/";
    let notification_uri = "https://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_RRDP_DIR_l + "notification.xml";
    let ca_name = &conf.CA_NAME;
    let resource_block = Prefix::new(
        Ipv4Addr::new(conf.DEFAULT_IPSPACE_FIRST_OCTET, conf.DEFAULT_IPSPACE_SEC_OCTET, 0, 0),
        conf.DEFAULT_IPSPACE_PREFIX,
    );
    let asn_min = Asn::from_u32(0);
    let asn_max = Asn::from_u32(100000);

    let issuer_cer_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_TA_DIR + "ta.cer";
    let parent_name = "ta";
    let parents_parent_name = "root";
    let ta = false;

    conf.CA_TREE.insert("newca".to_string(), "ta".to_string());

    create_ca(
        &parent_cert_key_uri_l,
        &parent_repo_uri_l,
        &notification_uri,
        ca_name,
        resource_block,
        asn_min,
        asn_max,
        &issuer_cer_uri,
        parent_name,
        parents_parent_name,
        ta,
        "RSA",
        new_keys,
        &conf,
        true,
    );
}

pub fn get_prviate_key(key_file: &str) -> PKey<openssl::pkey::Private> {
    let file_content = fs::read(key_file).unwrap();
    let p_key = PKey::private_key_from_der(&file_content).unwrap();
    p_key
}

pub fn create_ca(
    parent_cert_key_uri_l: &str,
    parent_repo_uri_l: &str,
    notification_uri: &str,
    ca_name: &str,
    resource_block: Prefix,
    asn_min: Asn,
    asn_max: Asn,
    issuer_cer_uri: &str,
    parent_name: &str,
    parents_parent_name: &str,
    ta: bool,
    sig_algo: &str,
    new_keys: bool,
    conf: &RepoConfig,
    create_aux: bool,
) -> KeyAndSigner {
    // Parent cert_key_uri is needed as the cert will be signed with this key
    // Can be let empty if this is a trustanchor
    // Parent_repo_uri is the repo where the .cer will be stored
    // For a trust-anchor, use ./data/tals/
    // For TA, use "root" as parent_name

    let serial = random_serial();

    let repo_uri_l = conf.BASE_REPO_DIR_l.to_string() + ca_name + "/";

    fs::create_dir_all(&repo_uri_l).unwrap();

    let base_domain_uri = base_repo_uri(ca_name, conf);

    let rsa_key_uri_l = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";
    let cert_key;
    if new_keys {
        cert_key = make_cert_key(&rsa_key_uri_l, sig_algo);
    } else {
        cert_key = read_cert_key(&rsa_key_uri_l);
    }
    let pubkey = cert_key.get_pub_key();

    let uri = uri::Rsync::from_str(&base_domain_uri).unwrap();
    let mut cert;

    let parent_cert_key = if ta { cert_key } else { read_cert_key(parent_cert_key_uri_l) };

    let parent_signer = parent_cert_key.get_signer();
    let parent_key = parent_cert_key.get_key_id().unwrap();
    let parent_pubkey = parent_cert_key.get_pub_key();

    cert = TbsCert::new(
        serial.into(),
        parent_pubkey.to_subject_name(),
        Validity::from_secs(286400),
        None,
        pubkey,
        KeyUsage::Ca,
        Overclaim::Refuse,
    );

    let mft_crl_filename = get_filename_crl_mft(&rsa_key_uri_l);

    let mut mft_uri_l = "".to_string();
    mft_uri_l.push_str(&mft_crl_filename);
    mft_uri_l.push_str(".mft");

    let mut crl_uri_l = "".to_string();
    crl_uri_l.push_str(&mft_crl_filename);
    crl_uri_l.push_str(".crl");

    let mut mft_uri = base_domain_uri.clone();
    mft_uri.push_str(mft_uri_l.to_string().as_str());

    let mut crl_uri = base_domain_uri.clone();
    crl_uri.push_str(crl_uri_l.to_string().as_str());

    cert.set_basic_ca(Some(true));
    cert.set_ca_repository(Some(uri.clone()));

    if !ta {
        let mut base_crl_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + parent_name + "/";

        base_crl_uri.push_str(get_filename_crl_mft(parent_cert_key_uri_l).as_str());
        base_crl_uri.push_str(".crl");

        cert.set_crl_uri(Some(uri::Rsync::from_str(&base_crl_uri).unwrap()));
    }
    cert.set_rpki_manifest(Some(uri::Rsync::from_str(&mft_uri).unwrap()));
    cert.build_v4_resource_blocks(|b| {
        for a in &conf.IPBlocks {
            // Either use absolute value or family id from asn
            if a.0 != 4 && a.0 != 1 {
                continue;
            }
            b.push(a.1);
        }
    });

    cert.build_v6_resource_blocks(|b| {
        for a in &conf.IPBlocks {
            // Either use absolute value or family id from asn
            if a.0 != 6 && a.0 != 2 {
                continue;
            }
            b.push(a.1);
        }
    });

    cert.build_as_resource_blocks(|b| b.push((asn_min, asn_max)));

    let uri = local_to_uri(notification_uri.to_string(), &conf);

    cert.set_rpki_notify(Some(uri::Https::from_str(&uri).unwrap()));

    // The cert of this CA is signed by the parent
    // This is NOT allowed for TA -> Will lead to error
    if !ta {
        cert.set_authority_key_identifier(Some(parent_pubkey.key_identifier()));
        cert.set_ca_issuer(Some(uri::Rsync::from_str(issuer_cer_uri).unwrap()));
    }

    let cert = cert.into_cert(parent_signer, &parent_key).unwrap();

    let mut cer_uri_l = parent_repo_uri_l.clone().to_string();
    if !ta {
        cer_uri_l.push_str(&ca_name);
        cer_uri_l.push_str(".cer");
    } else {
        cer_uri_l.push_str("ta.cer");
    }
    // The certificate is put into the repository of the parent
    let cer_uri_l = get_cwd() + "/" + &cer_uri_l;
    // println!("Cert: {:?}", cert.to_captured().as_slice());
    fs::write(cer_uri_l, cert.to_captured().as_slice()).unwrap();

    // Now we need to recreate the parent mft and create the new ca's mft and crl

    if create_aux {
        create_default_crl(0, vec![], &rsa_key_uri_l, ca_name, conf);
        make_manifest(ca_name, parent_name, conf);

        if !ta {
            make_manifest(parent_name, parents_parent_name, conf);
        }
    }

    read_cert_key(&rsa_key_uri_l)
}

fn local_to_uri(uri: String, conf: &RepoConfig) -> String {
    uri.clone().replace(&conf.BASE_l, "")
}

// Structure used to store a key with its signer
#[derive(Clone)]
pub struct KeyAndSigner {
    pub signer: OpenSslSigner,
    pub keyid: Option<KeyId>,
    pub private_key: PKey<Private>,
    pub key_only: bool,
    pub file_uri: String,
}

impl KeyAndSigner {
    pub fn get_key_id(&self) -> Option<KeyId> {
        self.keyid
    }

    pub fn get_signer(&self) -> &OpenSslSigner {
        &self.signer
    }

    pub fn get_ssl_signer(&self) -> OSigner {
        let s = OSigner::new(MessageDigest::sha256(), &self.private_key).unwrap();
        s
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> Bytes {
        let signature;
        if self.key_only {
            let mut s = self.get_ssl_signer();
            s.update(&mut data.as_ref()).unwrap();
            let sig_tmp = s.sign_to_vec().unwrap();
            signature = Bytes::from(sig_tmp);
        } else {
            signature = self
                .signer
                .sign(&self.keyid.unwrap(), SignatureAlgorithm::default(), data)
                .unwrap()
                .value()
                .clone();
        }
        signature
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(&self, data: &D, key_algo: &str) -> (Bytes, PublicKey) {
        let key;
        if key_algo == "RSA" {
            key = new_key();
        } else {
            key = new_ECDSA_key();
        }

        let pkey = PKey::private_key_from_der(&key).unwrap();
        let mut s = OSigner::new(MessageDigest::sha256(), &pkey).unwrap();
        s.update(&mut data.as_ref()).unwrap();
        let pubkey = PublicKey::decode(pkey.public_key_to_der().unwrap().as_ref()).unwrap();
        let sig_tmp = s.sign_to_vec().unwrap();
        let signature = Bytes::from(sig_tmp);
        (signature, pubkey)
    }

    pub fn get_pub_key(&self) -> PublicKey {
        let pubkey;
        if self.key_only {
            pubkey = PublicKey::decode(self.private_key.public_key_to_der().unwrap().as_ref()).unwrap();
        } else {
            pubkey = self.signer.get_key_info(&self.keyid.unwrap()).unwrap();
        }
        return pubkey;
    }
}

pub struct RPConfig {
    pub binary_location: String,
    pub outfile: String,
    pub logfile: String,
    pub ssl_cert: String,
    pub tal_folder: String,
    pub cache_folder: String,
}

pub struct FortConfig {}

pub struct OctoRPKIConfig {}

pub struct ValidatorConfig {}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RepoConfig {
    pub BASE_DATA_DIR: String,
    pub BASE_REPO_DIR: String,
    pub BASE_RRDP_DIR: String,
    pub BASE_KEY_DIR: String,
    pub BASE_TAL_DIR: String,

    // Differenitate between the location on the file-system and the location given in the ROA
    // In normal Repos, this would be identical, but we may want to change the storage location without changing the values inside the objects
    pub BASE_l: String,

    pub BASE_DATA_DIR_l: String,
    pub BASE_REPO_DIR_l: String,
    pub BASE_RRDP_DIR_l: String,
    pub BASE_KEY_DIR_l: String,
    pub BASE_TAL_DIR_l: String,

    pub BASE_TA_DIR: String,
    pub BASE_TA_DIR_l: String,

    pub DOMAIN: String,
    pub DOMAIN_l: String,

    pub DEFAULT_IPSPACE_FIRST_OCTET: u8,
    pub DEFAULT_IPSPACE_SEC_OCTET: u8,

    pub DEFAULT_IPSPACE_PREFIX: u8,
    pub DEFAULT_IPSPACE_PREFIX6: u8,

    pub DEFAULT_AS_RESOURCES_MIN: u32,
    pub DEFAULT_AS_RESOURCES_MAX: u32,

    pub SSL_KEY_WEBSERVER: String,

    pub CA_NAME: String,

    pub CA_TREE: HashMap<String, String>,

    pub IPBlocks: Vec<(u8, IpBlock)>,
    pub IPv4: Vec<Ipv4Net>,
    pub IPv6: Vec<Ipv6Net>,

    pub DEBUG: bool,
}
impl Clone for RepoConfig {
    fn clone(&self) -> RepoConfig {
        return RepoConfig {
            BASE_DATA_DIR: self.BASE_DATA_DIR.clone(),
            BASE_REPO_DIR: self.BASE_REPO_DIR.clone(),
            BASE_RRDP_DIR: self.BASE_RRDP_DIR.clone(),
            BASE_KEY_DIR: self.BASE_KEY_DIR.clone(),
            BASE_TAL_DIR: self.BASE_TAL_DIR.clone(),
            BASE_l: self.BASE_l.clone(),
            BASE_DATA_DIR_l: self.BASE_DATA_DIR_l.clone(),
            BASE_REPO_DIR_l: self.BASE_REPO_DIR_l.clone(),
            BASE_RRDP_DIR_l: self.BASE_RRDP_DIR_l.clone(),
            BASE_KEY_DIR_l: self.BASE_KEY_DIR_l.clone(),
            BASE_TAL_DIR_l: self.BASE_TAL_DIR_l.clone(),
            BASE_TA_DIR: self.BASE_TA_DIR.clone(),
            BASE_TA_DIR_l: self.BASE_TA_DIR_l.clone(),
            DOMAIN: self.DOMAIN.clone(),
            DOMAIN_l: self.DOMAIN_l.clone(),
            DEFAULT_IPSPACE_FIRST_OCTET: self.DEFAULT_IPSPACE_FIRST_OCTET.clone(),
            DEFAULT_IPSPACE_SEC_OCTET: self.DEFAULT_IPSPACE_SEC_OCTET.clone(),
            DEFAULT_IPSPACE_PREFIX: self.DEFAULT_IPSPACE_PREFIX.clone(),
            DEFAULT_IPSPACE_PREFIX6: self.DEFAULT_IPSPACE_PREFIX6.clone(),
            DEFAULT_AS_RESOURCES_MIN: self.DEFAULT_AS_RESOURCES_MIN.clone(),
            DEFAULT_AS_RESOURCES_MAX: self.DEFAULT_AS_RESOURCES_MAX.clone(),
            SSL_KEY_WEBSERVER: self.SSL_KEY_WEBSERVER.clone(),
            CA_NAME: self.CA_NAME.clone(),
            CA_TREE: self.CA_TREE.clone(),
            IPBlocks: self.IPBlocks.clone(),
            IPv4: self.IPv4.clone(),
            IPv6: self.IPv6.clone(),
            DEBUG: self.DEBUG.clone(),
        };
    }
}

impl RepoConfig {
    pub fn new(
        base_data_dir: String,
        domain: String,
        first_octet: u8,
        second_octet: u8,
        prefix: u8,
        as_min: u32,
        as_max: u32,
        ssl_pem_uri_l: String,
        ca_name: String,
        rrdp_addition: &str,
        IPv4: Vec<Ipv4Net>,
        ipblocks: Vec<(u8, IpBlock)>,
    ) -> RepoConfig {
        RepoConfig {
            BASE_DATA_DIR: base_data_dir.clone(),
            BASE_REPO_DIR: base_data_dir.clone() + "repo/",
            BASE_RRDP_DIR: base_data_dir.clone() + "rrdp" + rrdp_addition + "/",
            BASE_KEY_DIR: base_data_dir.clone() + "keys/",
            BASE_TAL_DIR: base_data_dir + "tal/",
            DOMAIN: domain,
            DEFAULT_IPSPACE_FIRST_OCTET: first_octet,
            DEFAULT_IPSPACE_SEC_OCTET: second_octet,
            DEFAULT_IPSPACE_PREFIX: prefix,
            DEFAULT_AS_RESOURCES_MIN: as_min,
            DEFAULT_AS_RESOURCES_MAX: as_max,
            SSL_KEY_WEBSERVER: ssl_pem_uri_l,
            CA_NAME: ca_name,
            IPv4: IPv4,
            IPBlocks: ipblocks,
            ..Default::default()
        }
    }

    pub fn new_full(
        base_data_dir: String,
        base_repo_dir: String,
        base_rrdp_dir: String,
        base_key_dir: String,
        base_tal_dir: String,
        domain: String,
        first_octet: u8,
        second_octet: u8,
        prefix: u8,
        as_min: u32,
        as_max: u32,
        ssl_pem_uri_l: String,
        ca_name: String,
    ) -> RepoConfig {
        RepoConfig {
            BASE_DATA_DIR: base_data_dir.clone(),
            BASE_REPO_DIR: base_repo_dir,
            BASE_RRDP_DIR: base_rrdp_dir,
            BASE_KEY_DIR: base_key_dir,
            BASE_TAL_DIR: base_tal_dir,
            DOMAIN: domain,
            DEFAULT_IPSPACE_FIRST_OCTET: first_octet,
            DEFAULT_IPSPACE_SEC_OCTET: second_octet,
            DEFAULT_IPSPACE_PREFIX: prefix,
            DEFAULT_AS_RESOURCES_MIN: as_min,
            DEFAULT_AS_RESOURCES_MAX: as_max,
            SSL_KEY_WEBSERVER: ssl_pem_uri_l,
            CA_NAME: ca_name,
            ..Default::default()
        }
    }

    pub fn default_locals(mut self) -> RepoConfig {
        self.BASE_l = "".to_string();

        self.BASE_DATA_DIR_l = self.BASE_DATA_DIR.clone();
        self.BASE_REPO_DIR_l = self.BASE_REPO_DIR.clone();
        self.BASE_KEY_DIR_l = self.BASE_KEY_DIR.clone();
        self.BASE_RRDP_DIR_l = self.BASE_RRDP_DIR.clone();
        self.BASE_TAL_DIR_l = self.BASE_TAL_DIR.clone();
        self.BASE_TA_DIR_l = self.BASE_TA_DIR.clone();
        self.DOMAIN_l = self.DOMAIN.clone();

        self
    }

    pub fn default_locals_a(mut self, base_uri: String, domain: String) -> RepoConfig {
        self.BASE_l = base_uri.clone();
        self.BASE_DATA_DIR_l = base_uri.clone() + &self.BASE_DATA_DIR.clone();
        self.BASE_REPO_DIR_l = base_uri.clone() + &self.BASE_REPO_DIR.clone();
        self.BASE_KEY_DIR_l = base_uri.clone() + &self.BASE_KEY_DIR.clone();
        self.BASE_RRDP_DIR_l = base_uri.clone() + &self.BASE_RRDP_DIR.clone();
        self.BASE_TAL_DIR_l = base_uri.clone() + &self.BASE_TAL_DIR.clone();
        self.BASE_TA_DIR_l = base_uri.clone() + &self.BASE_TA_DIR.clone();
        self.DOMAIN_l = domain;
        self
    }
}

impl Default for RepoConfig {
    fn default() -> RepoConfig {
        RepoConfig {
            BASE_DATA_DIR: "data/".to_string(),
            BASE_REPO_DIR: "data/repo/".to_string(),
            BASE_RRDP_DIR: "data/rrdp/".to_string(),
            BASE_KEY_DIR: "data/keys/".to_string(),
            BASE_TAL_DIR: "data/tal/".to_string(),
            BASE_TA_DIR: "data/tal/".to_string(),
            BASE_l: "".to_string(),
            BASE_DATA_DIR_l: "data/".to_string(),
            BASE_REPO_DIR_l: "data/repo/".to_string(),
            BASE_RRDP_DIR_l: "data/rrdp/".to_string(),
            BASE_KEY_DIR_l: "data/keys/".to_string(),
            BASE_TAL_DIR_l: "data/tal/".to_string(),
            BASE_TA_DIR_l: "data/tal/".to_string(),
            DOMAIN: "my.server.com".to_string(),
            DOMAIN_l: "my.server.com".to_string(),
            DEFAULT_IPSPACE_FIRST_OCTET: 10,
            DEFAULT_IPSPACE_SEC_OCTET: 0,
            DEFAULT_IPSPACE_PREFIX: 16,
            DEFAULT_IPSPACE_PREFIX6: 32,
            DEFAULT_AS_RESOURCES_MIN: 0,
            DEFAULT_AS_RESOURCES_MAX: 1000,
            SSL_KEY_WEBSERVER: "ssl/certbundle.pem".to_string(),
            CA_NAME: "newca".to_string(),
            CA_TREE: HashMap::new(),
            IPBlocks: vec![],
            IPv4: vec![],
            IPv6: vec![],
            DEBUG: false,
        }
    }
}

#[derive(Clone)]
pub struct DeltaWrapper {
    pub delta: Delta,
    pub uri: String,
    pub hash: Hash,
}

// Generate a new RSA 2048 bit key
pub fn new_key() -> Vec<u8> {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let der = pkey.private_key_to_der().unwrap();
    der
}

pub fn new_DSA_key() -> Vec<u8> {
    let key = Dsa::generate(2048).unwrap();
    let pkey = PKey::from_dsa(key).unwrap();
    let der = pkey.private_key_to_der().unwrap();
    der
}

pub fn new_ECDSA_key() -> Vec<u8> {
    //SECP256R1
    // For some reason the SECP256R1 curve is refered to as prime256v1 by openssl
    // Pain in the ass to figure this out
    let pkey = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
    let der = pkey.private_key_to_der().unwrap();
    let d = pkey.public_key_to_der().unwrap();
    der
}

// pub fn key_and_signer_from_key(priv_key: PKey<Private>) -> KeyAndSigner{
//     let signer = OpenSslSigner::new();
//     let keyid = Some(signer.key_from_der(&priv_key.private_key_to_der().unwrap()).unwrap());
//     KeyAndSigner {
//         signer,
//         keyid,
//         priv_key,
//         false,
//     }

// }

// Create new cert key that can be used to sign objects in the repository
pub fn make_cert_key(file_uri: &str, sig_algo: &str) -> KeyAndSigner {
    let der;
    let key_only;
    if sig_algo == "DSA" {
        der = new_ECDSA_key();
        key_only = true;
    } else {
        der = new_key();
        key_only = false;
    }
    let private_key = PKey::private_key_from_der(&der).unwrap();
    let signer = OpenSslSigner::new();

    let path = std::path::Path::new(file_uri);
    let prefix = path.parent().unwrap();
    std::fs::create_dir_all(prefix).unwrap();
    fs::write(file_uri, &der).unwrap();

    let keyid;
    if key_only {
        keyid = None;
    } else {
        keyid = Some(signer.key_from_der(&der).unwrap());
    }
    return KeyAndSigner {
        signer,
        keyid,
        private_key,
        key_only,
        file_uri: file_uri.to_string(),
    };
}

pub fn fill_signer(file_uri: &str, signer: &OpenSslSigner) -> KeyId {
    let der = fs::read(file_uri).unwrap();
    let key_only;
    let keyid = match signer.key_from_der(&der) {
        Ok(v) => {
            key_only = false;
            Some(v)
        }
        Error => {
            key_only = true;
            None
        }
    };
    return keyid.unwrap();
}

pub fn pub_and_priv_key(file_uri: &str) -> (PKey<Private>, PublicKey) {
    // If key does not exist yet: Create it
    if fs::read(file_uri).is_err() {
        println!("Key {} does not exist yet, creating new key", file_uri);
        make_cert_key(file_uri, "RSA");
    }

    let der = fs::read(file_uri).unwrap();
    let private_key = PKey::private_key_from_der(&der).unwrap();
    let pkey_raw = private_key.rsa().unwrap().public_key_to_der().unwrap();
    //let raw_pub = private_key.raw_public_key().unwrap();
    let pub_key = PublicKey::decode(pkey_raw.as_ref()).unwrap();

    (private_key, pub_key)
}

// Read the cert key from the repo
pub fn read_cert_key(file_uri: &str) -> KeyAndSigner {
    if fs::read(file_uri).is_err() {
        println!("Key {} does not exist yet, creating new key", file_uri);
        make_cert_key(file_uri, "RSA");
    }

    let der = fs::read(file_uri).unwrap();
    let signer = OpenSslSigner::new();
    let key_only;
    let keyid = match signer.key_from_der(&der) {
        Ok(v) => {
            key_only = false;
            Some(v)
        }
        Error => {
            key_only = true;
            None
        }
    };
    let private_key = PKey::private_key_from_der(&der).unwrap();
    return KeyAndSigner {
        signer,
        keyid,
        private_key,
        key_only,
        file_uri: file_uri.to_string(),
    };
}

// TODO Make these Errors give usefull information
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCharacters,
    BadUri,
    BadScheme,
    DotSegments,
    EmptySegments,
    Generic,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Error::InvalidCharacters => "invalid characters",
            Error::BadUri => "bad URI",
            Error::BadScheme => "bad URI scheme",
            Error::DotSegments => "URI with dot path segments",
            Error::EmptySegments => "URI with empty path segments",
            Error::Generic => "Generic Error",
        })
    }
}

impl error::Error for Error {}
