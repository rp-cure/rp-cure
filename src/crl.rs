use crate::asn1p::ExtensionValue;
use crate::consts;
use crate::mft;
use crate::util;
use crate::util::read_files_from_folder;
use asn1;
use asn1::Asn1Writable;
use asn1::BitString;
use asn1::SequenceOf;
use asn1::SetOf;
use asn1::SimpleAsn1Readable;
use base64;
use bcder::encode::{PrimitiveContent, Values};

use bcder::{encode, Captured, Mode, OctetString, Oid, Tag};
use bytes::Bytes;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use rpki::repository::crypto::DigestAlgorithm;
use rpki::repository::crypto::PublicKey;
use rpki::repository::manifest::{FileAndHash, ManifestContent};
use rpki::repository::x509::Time;
use rpki::uri;
use rpki_testing::fuzzing_interface;
use rpki_testing::repository;
use rpki_testing::repository::KeyAndSigner;
use rpki_testing::repository::RepoConfig;
use serde_json::{Result, Value};
use std::clone;
use std::fs;
use std::fs::read_dir;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use hex;
use crate::asn1p;




// Serialize Byte Vector to a random file in obj_cache folder
pub fn serialize_data(val: &Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)>) -> String {
    let s = serde_json::to_string(&val).unwrap();
    let filename = util::get_cwd() + "/obj_cache/" + &util::random_file_name();

    fs::write(&filename, s).unwrap();
    filename
}

pub fn read_serialized_data(filename: &str) -> Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)> {
    let s = fs::read_to_string(filename).unwrap();
    let c = serde_json::from_str::<Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)>>(&s);
    if c.is_err() {
        return vec![];
    }
    c.unwrap()
}

pub fn move_files_data(folder: String, filepaths: &Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)>, dont_move: bool) {
    // For Debugging
    if dont_move {
        return;
    }

    for filepath in filepaths {
        let p = folder.clone() + &filepath.0;
        fs::remove_file(p).unwrap();
    }
}

pub fn create_objects(folder: String, max_file_amount: u16, dont_move: bool, oneshot: bool, amount: u32) {
    let mut conf = repository::create_default_config(consts::domain.to_string());
    let (cert_keys, new_conf) = util::create_cas(amount, vec![&conf], None);
    conf.CA_TREE = new_conf.CA_TREE.clone();
    let cws = util::get_cwd() + "/";
    let output_folder = cws + "obj_cache/";

    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf, amount, false);
    let roas = util::create_example_roas(&cert_keys, amount, &conf);    

    loop {
        let data = generate_from_files_plain(&folder, &mut conf, amount, &cert_keys, "crl", &priv_keys, &pub_keys, &roas);
        if data.len() == 0 {
            println!("No more Objects in Folder {} - Exiting Process", folder);
            return;
        }


        serialize_data(&data);

        move_files_data(folder.clone().to_string(), &data, dont_move);
        if oneshot{
            break;
        }
        // If folder is sufficiently full -> Wait
        while util::fileamount_in_folder(&output_folder) >= max_file_amount.into() {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn generate_from_files_plain(
    folder: &str,
    conf: &mut RepoConfig,
    amount: u32,
    ca_keys: &Vec<KeyAndSigner>,
    obj_type: &str,
    priv_keys: &Vec<PKey<Private>>,
    pub_keys: &Vec<PublicKey>,
    roas: &Vec<(Bytes, String)>,
) -> Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)> {
    let obj = read_files_from_folder(folder, amount);

    //println!("Found {} objects", obj.len());
    let mut objects = vec![];

    for i in 0..obj.clone().len() {
        let ca_name = "ca".to_string() + &i.to_string();

        // let parent_fingerprint = ca_keys[i].get_key_id().unwrap();

        let a = &obj.clone()[i];

        let re = parse_and_sign(a.1.clone(), &ca_keys[i]);

        let mft = util::create_manifest(
            &conf,
            &ca_name,
            &a.0.clone(),
            priv_keys[i].clone(),
            pub_keys[i].clone(),
            &ca_keys[i],
            i.try_into().unwrap(),
            re.clone().into(),
            roas[i].clone(),
        );
        // let v = (roas[i].0.to_vec(), roas[i].1.clone());
        objects.push((a.0.clone(), re.to_vec(), mft.to_vec(), roas[i].0.to_vec(), roas[i].1.clone()));
    }

    objects
}



pub fn do_both(obj_folder: &str, conf: &mut RepoConfig) {
    let cws = util::get_cwd() + "/";
    let folder;
    if obj_folder.starts_with("/"){
        folder = obj_folder.to_string();
    }
    else{
        folder = cws.clone() + obj_folder;
    }
    let obj_folder = cws + "obj_cache/";

    fs::remove_dir_all(obj_folder.clone());
    fs::create_dir_all(obj_folder.clone());
    let amount;
    if fs::metadata(folder.clone()).is_ok() && fs::metadata(folder.clone()).unwrap().is_file(){
        amount = 1;
    }
    else{
        amount = read_dir(folder.clone()).unwrap().count();
            // amount = fs::metadata(folder.clone()).unwrap().;
    }


    for i in 0..amount{
        let ca_name = "ca".to_string() + &i.to_string();
        conf.CA_TREE.insert(ca_name, "ta".to_string());

    }

    create_objects(folder.clone(), 5, true, true, amount.try_into().unwrap());
    let paths = read_dir(obj_folder.clone()).unwrap();

    let mut all_paths = vec![];
    for path in paths {
        let p = path.unwrap().path();
        let file_name = p.to_str().unwrap().to_string();
        all_paths.push(file_name);
    }

    let (cert_keys, new_conf) = util::create_cas(amount.try_into().unwrap(), vec![&conf], None);
    let roas = util::create_example_roas(&cert_keys, amount.try_into().unwrap(), &conf);

    // println!("Paths found: {:?}", paths);
    for file_name in all_paths {
        // let p = path.unwrap().path();
        // let file_name = p.to_str().unwrap();
        handle_serialized_object(&file_name, &conf, 1, Some(roas), "crl");
        fs::remove_file(&file_name);

        //repository::add_random_roa_ca(&conf, "ca0");
        break;
    }
}



pub fn generate_example_crls(){
    let conf = repository::create_default_config(consts::domain.to_string());
    let amount = 12;
    for i in 0..amount{
        let ca_name = "ca".to_string() + &i.to_string();
        let cert_key = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";
        let crl_bytes = repository::create_default_crl(1, vec![], &cert_key, &ca_name, &conf);
        fs::write(&("/home/nvogel/git/rpki-fuzzing/crl_example/".to_string() + &ca_name + ".crl"), crl_bytes).unwrap();
    }   
}


pub fn handle_serialized_object_inner(data: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)>, start_index: u32, conf: &RepoConfig){
    let mut filenames = vec![];
    let mut objects = vec![];
    let mut index = 0;

    for date in data {
        let ca_name = "ca".to_string() + &(index + start_index).to_string();
        index += 1;
        let byte = Bytes::from(date.1);
        let byte_mft = Bytes::from(date.2);
        let byte_roa = Bytes::from(date.3);
        let uri_roa = date.4;
        filenames.push(date.0.clone());
        objects.push(byte.clone());

        let key_uri = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";

        repository::write_object_to_disc(&byte, "crl", &key_uri, &ca_name, conf);
        repository::write_object_to_disc(&byte_mft, "mft", &key_uri, &ca_name, conf);
        repository::write_object_to_disc(&byte_roa, "", &(uri_roa), &ca_name, conf);
    }

    let mut alt_con = conf.clone();
    alt_con.CA_NAME = "ca0".to_string();
    alt_con.CA_TREE.insert("ca0".to_string(), "ta".to_string());
    // repository::add_roa_str("10.0.0.0/24 => 11111", true, &alt_con);
    repository::add_roa_str(&(conf.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." +  &conf.DEFAULT_IPSPACE_SEC_OCTET.to_string() + ".0.0/24 => 22222"), true, conf);

    fs::remove_dir_all(&conf.BASE_RRDP_DIR_l);
    let (session_id, serial_number) = repository::get_current_session_notification(conf);

    let (snapshot, snapshot_uri) = repository::create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);
    let notification = repository::create_notification(snapshot_bytes, vec![], &snapshot_uri, 5, session_id, serial_number, conf);
    repository::write_notification_file(notification, conf).unwrap();
}

pub fn handle_serialized_object(path: &str, conf: &RepoConfig, _: u32, _: Option<Vec<(Bytes, String)>>, _: &str) {
    let data = read_serialized_data(path);
    if data.is_empty(){
        println!("Error: Dump could not be read, maybe wrong file type?");
        return;
    }
    handle_serialized_object_inner(data, 0, conf);
   
}


pub fn parse_and_sign(data: Bytes, signer: &KeyAndSigner) -> Vec<u8> {
    // return data.into();
    let a = asn1::parse_single::<asn1p::CertificateRevocationList>(&data);
    let kid = signer.get_pub_key().key_identifier().to_string();
    let replace_everything = true;
    let change_validity = false;
    let change_name = false;
    let replace_ski = false;

    // If this is not valid ASN1 -> Just return the bytes
    if a.is_err(){
        println!("Didnt parse crl");
        return data.into();
    }
    let mut obj = a.unwrap();
    obj.tbsCertList.validity.unwrap();
    let c = asn1::UtcTime::new(chrono::offset::Local::now().into()).unwrap();
    let d = asn1::UtcTime::new((chrono::offset::Local::now() + chrono::Duration::days(5)).into()).unwrap();
    let tmp = asn1::write_single(&c).unwrap();
    let a = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();
    if change_validity{
        obj.tbsCertList.validity = Some(a);
    }

    let tmp = asn1::write_single(&d).unwrap();
    let a = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();
    if change_validity{
        obj.tbsCertList.subject = Some(a);
    }

    // Make SubjectPublicKeyInfo an empty sequence
   

    let o = asn1p::SubPubKeyInfo{keyIdentifier: None};
    let content = asn1::write_single(&o).unwrap();
    let a = asn1::parse_single::<asn1::Tlv>(&content).unwrap();
    if replace_ski{
        obj.tbsCertList.subjectPublicKeyInfo = Some(a);

    }

    // Replace Issuer with real Issuer
    let x = asn1::PrintableString::new(&kid).unwrap();
    let issuer_bytes = asn1::write_single(&x).unwrap();

    let a = asn1::parse_single::<asn1::Tlv>(&issuer_bytes).unwrap();
    let at = asn1::ObjectIdentifier::from_string("2.5.4.3").unwrap();
    let tmp = asn1::write_single(&at).unwrap();
    let tu = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();
    let tuv = asn1p::TypeAndValue{
        attrType: tu,
        attrValue: a,
    };

    let a = signer.get_pub_key().key_identifier().to_encoded_bytes(Mode::Der);

    let con = asn1p::AKIContent{
        keyIdentifier: Some(&a),
        authorityCertIssuer: None,
        authorityCertSerialNumber: None,
    };

    let b = asn1::write_single(&con).unwrap();

    let t = asn1::parse_single::<asn1::Tlv>(&b).unwrap();
    let octetstr = asn1::OctetStringEncoded::new(t);
    let issuer_bytes = asn1::write_single(&octetstr).unwrap();

    let a = asn1::parse_single::<asn1::Tlv>(&issuer_bytes).unwrap();
    let aus = obj.tbsCertList.crlExtensions.clone();
    

    let newe = asn1p::ExtensionValue{
        identifier: asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap(),
        critical: false,
        value: a,
    };



    let b = hex::decode(b"040402020303").unwrap();

    let a = asn1::parse_single::<asn1::Tlv>(&b).unwrap();
    let number_ext = asn1p::ExtensionValue{
        identifier: asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap(),
        critical: false,
        value: a,
    };

    let mut all_exts = vec![newe];
    let mut exField = None;
    let ti;
    if aus.is_none() {
        if obj.tbsCertList.subjectPublicKeyInfo.is_some(){
            let t = asn1::write_single(&obj.tbsCertList.subjectPublicKeyInfo.unwrap());
            if t.is_ok(){
                ti = t.unwrap();
                let r = asn1::parse_single::<asn1::SequenceOf<ExtensionValue>>(&ti);
                if r.is_ok(){
                    exField = Some(r.unwrap());
                }
            }

        }
    
    }
    else{
        exField = Some(aus.unwrap());
    }

    if exField.is_some(){        
        // Adding all remaining extensions
    
        let mut ignored_aki_once = false;
        let mut ignored_number_once = false;

        let e = exField.clone().unwrap().into_iter().collect::<Vec<asn1p::ExtensionValue>>();
        for i in 0..e.len() {
            let tmp = &e[i];
    
            if tmp.identifier.to_string() == "2.5.29.35" && !ignored_aki_once{
                ignored_aki_once = true;
                continue;
            }


    
            let ex = asn1p::ExtensionValue{
                identifier: tmp.identifier.clone(),
                critical: false,
                value: tmp.value,
            };
            all_exts.push(ex);
        }
    }
    else{
        all_exts.push(number_ext);
    }
    let ww = asn1::SequenceOfWriter::new(all_exts);
    
    let b = asn1::write_single(&ww).unwrap();
    let res = asn1::parse_single::<asn1::SequenceOf<asn1p::ExtensionValue>>(&b).unwrap();
    if exField.is_some(){
        obj.tbsCertList.crlExtensions = Some(res.clone());
    }
    else{
        obj.tbsCertList.subjectPublicKeyInfo = None;
        obj.tbsCertList.crlExtensions = Some(res.clone());
        println!("No Extension field");
    }
   


    let w = asn1::SetOfWriter::new(vec![tuv]);

    let binding = asn1::write_single(&w).unwrap();
    let res = asn1::parse_single::<asn1::SetOf<asn1p::TypeAndValue>>(&binding).unwrap();
    let tmp = &obj.tbsCertList.issuer.clone();
    let bin;
    if tmp.is_some() && change_name{
        let mut i = tmp.clone().unwrap();
        let sw = asn1::SequenceOfWriter::new(vec![res]);
        bin = asn1::write_single(&sw).unwrap();
        let res = asn1::parse_single::<asn1::SequenceOf<asn1::SetOf<asn1p::TypeAndValue>>>(&bin).unwrap();
        obj.tbsCertList.issuer = Some(res);      
        println!("Replaced issuer");
    }
    

    // Finally, recalculate the Signature
    let content = asn1::write_single(&obj.tbsCertList).unwrap();
    let sig = signer.sign(&content);
    obj.signatureValue = BitString::new(&sig, 0).unwrap();


    let new_bytes = asn1::write_single(&obj).unwrap();
    new_bytes
}
