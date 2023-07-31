use std::fs;
use std::fs::metadata;
use std::thread;

use crate::asn1p;
use crate::consts;
use crate::process_util;
use crate::process_util::ObjectFactory;
use crate::publication_point::fuzzing_interface;
use crate::publication_point::repository;
use crate::publication_point::repository::create_current_snapshot;
use crate::publication_point::repository::create_notification;
use crate::publication_point::repository::get_current_session_notification;
use crate::publication_point::repository::write_notification_file;
use crate::publication_point::repository::KeyAndSigner;
use crate::publication_point::repository::RepoConfig;
use crate::util;
use crate::util::read_files_from_folder;
use crate::FuzzConfig;
use bytes::Bytes;
use openssl::pkey::{PKey, Private};
use rpki::repository::crypto::PublicKey;
use std::fs::read_dir;
use std::time::Duration;

pub fn srun(conf: FuzzConfig) {
    let repo_config = &conf.repo_conf.clone();

    let typ = &conf.typ.to_string();
    let total_amount = conf.amount;

    let mut factory = ObjectFactory::new(50, "/tmp/sock");
    create_objects_new(true, conf);

    handle_serialized_object_new(&mut factory, repo_config, typ);
}

pub fn create_objects_new(oneshot: bool, mut conf: FuzzConfig) {
    let (cert_keys, _) = util::create_cas(conf.amount.into(), vec![&mut conf.repo_conf], None);

    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf.repo_conf, conf.amount.into(), false);

    loop {
        let data = generate_from_files_plain(priv_keys.clone(), pub_keys.clone(), &cert_keys, &conf);

        if data.is_empty() {
            return;
        }

        let serialized = util::serialize_data_new(&data);
        process_util::send_new_data(serialized);

        if oneshot {
            return;
        }

        util::move_files_data(conf.uri.clone(), &data, conf.dont_move);

        while process_util::is_stopped() {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn create_objects(folder: String, max_file_amount: u16, dont_move: bool, oneshot: bool, amount: u32, no_ee: bool) {
    // let mut conf = repository::create_default_config(consts::domain.to_string());

    // // let amount = 4000;

    // let (cert_keys, _) = util::create_cas(amount, vec![&mut conf], None);

    // let cws = util::get_cwd() + "/";
    // let output_folder = cws + "obj_cache/";

    // let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf, amount, false);

    // loop {
    //     let data = generate_from_files_plain(
    //         &folder,
    //         conf.clone(),
    //         amount,
    //         priv_keys.clone(),
    //         pub_keys.clone(),
    //         &cert_keys,
    //         no_ee,
    //         "mft",
    //     );

    //     if data.len() == 0 {
    //         println!("No more Objects in Folder {} - Exiting Process", folder);
    //         return;
    //     }
    //     util::serialize_data(&data);

    //     util::move_files_data(folder.clone().to_string(), &data, dont_move);

    //     if oneshot {
    //         break;
    //     }
    //     // TODO REMOVE
    //     // If folder is sufficiently full -> Wait
    //     while util::fileamount_in_folder(&output_folder) >= max_file_amount.into() {
    //         thread::sleep(Duration::from_millis(100));
    //         println!("Waiting for folder to be empty again");
    //     }
    // }
}

pub fn generate_from_files_plain(
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    ca_keys: &Vec<KeyAndSigner>,
    conf: &FuzzConfig,
) -> Vec<(String, Vec<u8>)> {
    let folder = &conf.uri;

    let md = metadata(&folder).unwrap();
    let obj;
    if md.is_file() {
        let con = util::decb64(&folder);
        if con.is_some() {
            obj = vec![(folder.to_string(), con.unwrap())];
        } else {
            obj = vec![(folder.to_string(), Bytes::from(fs::read(folder).unwrap()))];
        }
    } else {
        obj = read_files_from_folder(&folder, conf.amount.into());
    }
    let mut objects = vec![];

    for i in 0..obj.clone().len() {
        let ca_name = "ca".to_string() + &i.to_string();
        let a = &obj.clone()[i];
        let e_content;

        if conf.no_ee {
            e_content = Bytes::from(asn1p::extract_e_content(Bytes::from(a.1.clone()), Some("mft")).unwrap());
        } else {
            e_content = a.1.clone();
        }

        let re = fuzzing_interface::generate_signed_data_from_bytes(
            e_content.clone(),
            &conf.repo_conf,
            &conf.typ.to_string(),
            &a.0,
            true,
            i.try_into().unwrap(),
            &ca_keys[i],
            priv_keys[i].clone(),
            pub_keys[i].clone(),
            &ca_name,
            None,
        );

        objects.push((a.0.clone(), re.to_vec()));
    }

    objects
}

pub fn handle_serialized_object_inner(data: Vec<(String, Vec<u8>)>, start_index: u32, conf: &RepoConfig) {
    let mut filenames = vec![];
    let mut objects = vec![];
    let mut index = 0;

    for date in data {
        let ca_name = "ca".to_string() + &(index + start_index).to_string();
        index += 1;
        let byte = Bytes::from(date.1);
        filenames.push(date.0.clone());
        objects.push(byte.clone());

        let key_uri = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";

        repository::write_object_to_disc(&byte, "mft", &key_uri, &ca_name, conf);
    }
    let mut alt_con = conf.clone();
    alt_con.CA_NAME = "ca0".to_string();
    alt_con.CA_TREE.insert("ca0".to_string(), "ta".to_string());

    repository::add_roa_str(
        &(conf.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." + &conf.DEFAULT_IPSPACE_SEC_OCTET.to_string() + ".0.0/24 => 22222"),
        true,
        conf,
    );

    fs::remove_dir_all(&conf.BASE_RRDP_DIR_l);
    let (session_id, serial_number) = get_current_session_notification(conf);

    let (snapshot, snapshot_uri) = create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);
    let notification = create_notification(snapshot_bytes, vec![], &snapshot_uri, 5, session_id, serial_number, conf);
    write_notification_file(notification, conf).unwrap();
}

pub fn handle_serialized_object(path: &str, conf: &RepoConfig, index: u32, additional_data: Option<Vec<(Bytes, String)>>, _: &str) {
    let data = util::read_serialized_data(path);
    handle_serialized_object_inner(data, 0, conf);
}

pub fn handle_serialized_object_new(factory: &mut ObjectFactory, conf: &RepoConfig, obj_type: &str) {
    let data = util::read_serialized_data_new(factory);

    if data.is_empty() {
        return;
    }

    handle_serialized_object_inner(data, 0, conf);
}

pub fn clear_repo(conf: &RepoConfig, ca_amount: u32) {
    // Remove all ca repos
    for i in 0..ca_amount {
        let folder = conf.BASE_REPO_DIR_l.to_string() + "ca" + &ca_amount.to_string() + "/";
        fs::remove_dir_all(&folder);
        fs::create_dir_all(&folder);
    }
}
