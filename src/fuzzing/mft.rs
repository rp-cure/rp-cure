use std::fs;
use std::fs::metadata;
use std::net::Ipv4Addr;
use std::process::Child;
use std::thread;
use std::time::Instant;

use crate::asn1p;
use crate::consts;
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
use bytes::Bytes;
use openssl::pkey::{PKey, Private};
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use rpki::repository::crypto::PublicKey;
use rpki::repository::resources::Asn;
use rpki::repository::resources::Prefix;
use std::fs::read_dir;
use std::time::Duration;
use uuid::Uuid;

use std::mem::ManuallyDrop;
pub fn do_both(obj_folder: &str, no_ee: bool, conf: &RepoConfig) {
    let cws = util::get_cwd() + "/";
    let folder;
    if obj_folder.starts_with("/") {
        folder = obj_folder.to_string();
    } else {
        folder = cws.clone() + obj_folder;
    }
    let obj_folder = cws + "obj_cache/";
    fs::remove_dir_all(obj_folder.clone());
    fs::create_dir_all(obj_folder.clone());
    let amount;
    if fs::metadata(folder.clone()).is_ok() && fs::metadata(folder.clone()).unwrap().is_file() {
        amount = 1;
    } else {
        amount = read_dir(folder.clone()).unwrap().count();
    }

    create_objects(folder.clone(), 2, true, true, amount.try_into().unwrap(), no_ee);
    let paths = read_dir(obj_folder.clone()).unwrap();
    for path in paths {
        let p = path.unwrap().path();
        let file_name = p.to_str().unwrap();
        //util::clear_repo(&conf);

        handle_serialized_object(file_name, &conf, 1, None, "");
        break;
    }
}

pub fn create_crls(amount: u32, conf: &mut RepoConfig) -> Vec<Bytes> {
    let mut contents = vec![];
    for i in 0..amount {
        let ca_name = "ca".to_string() + &i.to_string();
        let rsa_key_uri_l = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";
        let crl_content = repository::create_default_crl(0, vec![], &rsa_key_uri_l, &ca_name, conf);
        contents.push(crl_content);
    }
    contents
}

pub fn create_objects(folder: String, max_file_amount: u16, dont_move: bool, oneshot: bool, amount: u32, no_ee: bool) {
    let mut conf = repository::create_default_config(consts::domain.to_string());

    // let amount = 4000;

    let (cert_keys, _) = util::create_cas(amount, vec![&mut conf], None);

    let cws = util::get_cwd() + "/";
    let output_folder = cws + "obj_cache/";

    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf, amount, false);

    loop {
        let data = generate_from_files_plain(
            &folder,
            conf.clone(),
            amount,
            priv_keys.clone(),
            pub_keys.clone(),
            &cert_keys,
            no_ee,
            "mft",
        );

        if data.len() == 0 {
            println!("No more Objects in Folder {} - Exiting Process", folder);
            return;
        }
        util::serialize_data(&data);

        util::move_files_data(folder.clone().to_string(), &data, dont_move);

        if oneshot {
            break;
        }
        // TODO REMOVE
        // If folder is sufficiently full -> Wait
        while util::fileamount_in_folder(&output_folder) >= max_file_amount.into() {
            thread::sleep(Duration::from_millis(100));
            println!("Waiting for folder to be empty again");
        }
    }
}

pub fn create_mft_roa() {}

pub fn generate_from_files_plain(
    folder: &str,
    conf: RepoConfig,
    amount: u32,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    ca_keys: &Vec<KeyAndSigner>,
    no_ee: bool,
    obj_type: &str,
) -> Vec<(String, Vec<u8>)> {
    // TODO REMOVE, THIS IS FOR DEBUGGING ONLY
    let duplicate_amount = 1;

    let md = metadata(folder).unwrap();
    let obj;
    if md.is_file() {
        let con = util::decb64(folder);
        if con.is_some() {
            obj = vec![(folder.to_string(), con.unwrap())];
        } else {
            obj = vec![(folder.to_string(), Bytes::from(fs::read(folder).unwrap()))];
        }

        // obj = vec![(folder.to_string(), Bytes::from(fs::read(folder).unwrap()))];
    } else {
        obj = read_files_from_folder(folder, amount);
    }
    //let obj = read_files_from_folder(folder, amount);

    // let mut objnew_obj = vec![];

    // for i in 0..duplicate_amount {
    //     new_obj.push(obj[0].clone());
    // }

    //println!("Found {} objects", obj.len());
    let mut objects = vec![];

    for i in 0..obj.clone().len() {
        let ca_name = "ca".to_string() + &i.to_string();
        let a = &obj.clone()[i];
        let e_content;

        if no_ee {
            e_content = Bytes::from(asn1p::extract_e_content(Bytes::from(a.1.clone()), Some("mft")).unwrap());
        } else {
            e_content = a.1.clone();
        }

        let re = fuzzing_interface::generate_signed_data_from_bytes(
            e_content.clone(),
            &conf,
            obj_type,
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

pub fn handle_serialized_object_inner(data: Vec<(String, Vec<u8>)>, path: &str, start_index: u32, conf: &RepoConfig) {
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

        //println!("key {}", key_uri);

        repository::write_object_to_disc(&byte, "mft", &key_uri, &ca_name, conf);
    }
    let mut alt_con = conf.clone();
    alt_con.CA_NAME = "ca0".to_string();
    alt_con.CA_TREE.insert("ca0".to_string(), "ta".to_string());
    // repository::add_roa_str("10.0.0.0/24 => 11111", true, &alt_con);
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
    handle_serialized_object_inner(data, path, 0, conf);
}

pub fn clear_repo(conf: &RepoConfig, ca_amount: u32) {
    // Remove all ca repos
    for i in 0..ca_amount {
        let folder = conf.BASE_REPO_DIR_l.to_string() + "ca" + &ca_amount.to_string() + "/";
        fs::remove_dir_all(&folder);
        fs::create_dir_all(&folder);
    }
}

// pub fn start_fuzzing(obj_cache: &str, min_interval: u128, rp_names: Vec<String>, rp_process: &mut Vec<Child>, obj_type: &str) {
//     let ca_amount = 100;

//     let conf = repository::create_default_config(consts::domain.to_string());
//     let mut g_start = Instant::now();

//     let client_conf = util::create_client_config();

//     let mut proc_amount = 0;

//     let mut current_client_file = "".to_string();

//     // Run rpki-client once to initialize it
//     //fuzzing_interface::run_rp_server("rpki-client", &client_conf);
//     println!("Info: Starting Fuzzer");
//     println!("\nRunning...");

//     let mut cur_ind = 0;
//     let mut prev_file = "".to_string();

//     loop {
//         if util::check_process("object_generato").is_empty() {
//             println!("All Generation Processes Exited -> Exiting");
//             return;
//         }

//         let paths = read_dir(obj_cache.clone()).unwrap();
//         let mut found_path = false;
//         let mut something_crashed = false;

//         for path in paths {
//             clear_repo(&conf, ca_amount);

//             if rp_process.len() == 0 {
//                 println!("All RPs crashed -> Exiting");
//                 //return;
//             }
//             let start = Instant::now();
//             found_path = true;

//             let p = path.unwrap().path();
//             let file_name = p.to_str().unwrap();
//             println!("Found path {}", file_name);
//             // This function does the creation of RPKI objects and generation of the repo
//             handle_serialized_object(file_name, &conf, cur_ind);

//             // // Only run rpki-client when previous execution finished
//             // if check_process("rpki-client").is_empty() {
//             //     let cra = check_client_crash(&current_client_file.clone());
//             //     if cra {
//             //         something_crashed = true;
//             //     }
//             //     fuzzing_interface::run_rp_server("rpki-client", &client_conf);
//             //     current_client_file = file_name.clone().to_string();
//             // }

//             proc_amount += 10000;
//             let duration = start.elapsed();

//             // Check for crash
//             let mut to_rem = vec![];
//             for i in 0..rp_process.len() {
//                 let ret = util::check_crash(&mut rp_process[i], &rp_names[i], file_name, obj_type);
//                 if ret == 1 {
//                     to_rem.push(i);
//                     something_crashed = true;
//                 }
//             }

//             if !to_rem.len() > 0 {
//                 to_rem.reverse();
//                 for i in to_rem {
//                     rp_process.remove(i);
//                     println!("Removed RP: {}", &rp_names[i]);
//                 }
//             }

//             // Handling of the serilized File after it was used
//             // Always also cache the previous file in case this one really caused the crash

//             if something_crashed {
//                 println!("Moving {} while current file is {}", prev_file, file_name);

//                 let cws = util::get_cwd() + "/";
//                 let reports = cws.clone() + "serilized_output/";
//                 fs::create_dir_all(&reports);

//                 let fname = file_name.split("/").last().unwrap();
//                 let new_file = reports.clone() + &cur_ind.to_string() + "-" + fname;
//                 fs::rename(file_name, new_file).unwrap();

//                 let fname = prev_file.split("/").last().unwrap();
//                 let new_file = reports + &(cur_ind - 1).to_string() + "-" + fname;
//                 println!("{}", prev_file);
//                 fs::rename(prev_file, new_file).unwrap();
//                 prev_file = "".to_string();
//             } else {
//                 //println!("Removing {} while current file is {}", prev_file, file_name);
//                 let cws = util::get_cwd() + "/";
//                 let reports = cws.clone() + "tmp_cache/";
//                 fs::create_dir_all(&reports);

//                 let fname = file_name.split("/").last().unwrap();
//                 let new_file = reports.clone() + &cur_ind.to_string() + "-" + fname;
//                 fs::rename(file_name, &new_file).unwrap();

//                 fs::remove_file(prev_file);
//                 prev_file = new_file.to_string().clone();
//             }
//             something_crashed = false;

//             cur_ind += 1;
//             // We can only update once every second -> Ensure this by waiting in case we were too fast
//             // Waiting not a problem, ideally we would have to wait for object generation anyway...
//             if duration.as_millis() < min_interval {
//                 let dif = min_interval.checked_sub(duration.as_millis()).unwrap();
//                 let dif_i = dif.to_string().parse::<u64>().unwrap();
//                 if dif_i > 0 {
//                     thread::sleep(Duration::from_millis(dif_i));
//                 }
//                 println!("Had to sleep for {} milliseconds", dif_i);
//             }

//             let g_duration = g_start.elapsed();

//             if proc_amount > 50000 {
//                 println!(
//                     "Processed {} objects in {} ",
//                     proc_amount.to_string(),
//                     g_duration.as_secs_f32().to_string()
//                 );
//                 println!("Running RPs: {}", rp_process.len());
//                 proc_amount = 0;
//                 g_start = Instant::now();
//             }

//             //break;
//         }
//         if !found_path {
//             // If no path was found, sleep for a while until something is done
//             thread::sleep(Duration::from_millis(300));
//         }
//     }
// }
