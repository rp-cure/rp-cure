use crate::fuzzing::{cert, crl, mft, roa};
use crate::publication_point::repository::RepoConfig;
use crate::publication_point::rp_interaction::RoaContents;
use crate::publication_point::{fuzzing_interface, repository};
use crate::{consts, util, FuzzConfig};
use base64;
use bytes::Bytes;
use core::panic;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::str;
use std::time::Instant;
use std::{self};
use strsim::jaro;

pub fn test_serialized_file(file_name: &str, typ: &str) {
    if typ == "mft" {
        let conf = repository::create_default_config(consts::domain.to_string());
        util::clear_repo_full(&conf, 0);

        mft::handle_serialized_object(file_name, &conf, 1, None, "mft");
        run_rps();
    }
}

fn hashset(data: &Vec<RoaContents>) -> HashSet<u32> {
    data.iter().map(|x| x.as_id.into_u32()).collect::<HashSet<u32>>()
}

pub fn run_rp(name: &str) -> (HashSet<u32>, String) {
    if name == "routinator" {
        let routinator_conf = util::create_routinator_config();
        let rr = fuzzing_interface::run_rp("routinator", &routinator_conf);
        (hashset(&rr.0), rr.1)
    } else if name == "fort" {
        let fort_conf = util::create_fort_config();
        let rf = fuzzing_interface::run_rp("fort", &fort_conf);
        (hashset(&rf.0), rf.1)
    } else if name == "octorpki" {
        let octo_conf = util::create_octorpki_config();
        let ro = fuzzing_interface::run_rp("octorpki", &octo_conf);
        (hashset(&ro.0), ro.1)
    } else if name == "rpki-client" {
        let client_conf = util::create_client_config();
        let rc = fuzzing_interface::run_rp("rpki-client", &client_conf);
        (hashset(&rc.0), rc.1)
    } else {
        panic!("Unknown rp name");
    }
}

pub fn run_rps() -> bool {
    let start = Instant::now();
    let client_conf = util::create_client_config();
    let rc = fuzzing_interface::run_rp("rpki-client", &client_conf);
    let duration = start.elapsed();
    let start = Instant::now();

    // println!("Time elapsed in client is: {:?}", duration);

    let routinator_conf = util::create_routinator_config();
    let rr = fuzzing_interface::run_rp("routinator", &routinator_conf);
    let duration = start.elapsed();
    let start = Instant::now();

    // println!("Time elapsed in routinator is: {:?}", duration);

    let octo_conf = util::create_octorpki_config();
    let ro = fuzzing_interface::run_rp("octorpki", &octo_conf);
    let duration = start.elapsed();
    let start = Instant::now();

    // println!("Time elapsed in octo is: {:?}", duration);

    let fort_conf = util::create_fort_config();
    let rf = fuzzing_interface::run_rp("fort", &fort_conf);
    let duration = start.elapsed();
    let start = Instant::now();

    // println!("Time elapsed in fort is: {:?}", duration);

    let a = hashset(&rc.0) == hashset(&rr.0) && hashset(&rc.0) == hashset(&ro.0) && hashset(&rc.0) == hashset(&rf.0);
    let b = hashset(&rr.0) == hashset(&ro.0) && hashset(&rr.0) == hashset(&rf.0);
    let c = hashset(&ro.0) == hashset(&rf.0);
    let identical = a && b && c;
    // println!("Identical all {}", identical);
    // println!("Identical a {}", a);

    // println!("Identical b {}", b);
    println!("Info: VRPs");
    println!("  -> RPKI-Client {:?}", hashset(&rc.0));
    println!("  -> Routinator {:?}", hashset(&rr.0));
    println!("  -> OctoRPKI {:?}", hashset(&ro.0));
    println!("  -> Fort {:?}", hashset(&rf.0));
    let duration = start.elapsed();

    // println!("{}", rr.0[0].as_id.to_string());
    // println!("{}", ro.0[0].as_id.to_string());

    identical
}

fn read_data_uniform(serilized_uri: &str, obj_type: &str) -> Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, u32)> {
    if obj_type == "roa" || obj_type == "mft" {
        let data = util::read_serialized_data(serilized_uri);
        let mut v: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, u32)> = vec![];
        let mut i = 0;
        for date in data {
            //Vec<u8>, Vec<u8>, String
            let k: Vec<u8> = vec![];
            v.push((date.0, date.1, k.clone(), k.clone(), k.clone(), "".to_string(), i));
            i += 1;
        }
        return v;
    } else if obj_type == "crl" {
        let data = crl::read_serialized_data(serilized_uri);
        let mut v: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, u32)> = vec![];
        let mut i = 0;
        for date in data {
            //Vec<u8>, Vec<u8>, String
            let k: Vec<u8> = vec![];
            v.push((date.0, date.1, date.2, date.3, k.clone(), date.4, i));
            i += 1;
        }
        return v;
    } else if obj_type == "cert" {
        let data = cert::read_serialized_data(serilized_uri);
        let mut v: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, u32)> = vec![];
        let mut i = 0;
        for date in data {
            //Vec<u8>, Vec<u8>, String
            let k: Vec<u8> = vec![];
            v.push((date.0, date.1, date.2, date.3, date.4, date.5, i));
            i += 1;
        }
        return v;
    } else {
        panic!("Unknown obj type");
    }
}

fn handle_data_uniform(
    data: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, u32)>,
    path: &str,
    conf: &mut RepoConfig,
    obj_type: &str,
) {
    if data.is_empty() {
        return;
    }
    if obj_type == "roa" {
        let mut v: Vec<(String, Vec<u8>)> = vec![];
        let start_index = data[0].6;

        for date in data {
            v.push((date.0, date.1));
        }
        roa::handle_serialized_object_inner(conf, v, "roa");
    } else if obj_type == "mft" {
        let mut v: Vec<(String, Vec<u8>)> = vec![];
        let start_index = data[0].6;
        for date in data {
            v.push((date.0, date.1));
        }

        mft::handle_serialized_object_inner(v, start_index, conf);
    } else if obj_type == "crl" {
        let mut v: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, String)> = vec![];
        let start_index = data[0].6;
        for date in data {
            v.push((date.0, date.1, date.2, date.3, date.5));
        }
        crl::handle_serialized_object_inner(v, start_index, conf);
    } else if obj_type == "cert" {
        let mut v: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> = vec![];
        let start_index = data[0].6;
        for date in data {
            v.push((date.0, date.1, date.2, date.3, date.4, date.5));
        }
        cert::handle_serialized_object_inner(v, conf, start_index);
    } else {
        panic!("Unknown obj type");
    }
}

// pub fn test_process_result(){
//     let filename = roa::create_test_roas();
//     process_result(&filename, "roa", None, None, true);
// }

pub fn process_results(conf: FuzzConfig) {
    let folder = &conf.uri;
    let obj_type = &conf.typ.to_string();

    let p = Path::new(folder);
    let mut total_crashes = 0;
    let mut total_inconsistencies = 0;
    let mut processed_files = 0;

    let mut inconsistent_files = vec![];
    if p.is_dir() {
        let mut seen_vec = vec![];
        let mut pr_report = None;
        for entry in fs::read_dir(p).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            processed_files += 1;
            let filename = path.to_str().unwrap();
            // last_file = filename.clone();
            let (crash_count, inc_count, prev_report, a) =
                process_result(filename, obj_type, Some(&mut seen_vec), pr_report, false, &mut inconsistent_files);
            inconsistent_files = a;
            pr_report = Some(prev_report);

            total_crashes += crash_count;
            total_inconsistencies += inc_count;
            println!("Finished file {}", &filename);
        }
        let fina = "com-".to_string() + &util::random_file_name();
        write_report_to_disc(&fina, &pr_report.unwrap());
        println!(
            "Finished processing {} files with {} unique crashes and {} unique inconsistencies",
            processed_files, total_crashes, total_inconsistencies
        );
    } else if p.is_file() {
        let filename = p.to_str().unwrap();
        let (crash_count, inc_count, _, _) = process_result(filename, obj_type, None, None, true, &mut vec![]);
        println!(
            "Finished processing 1 file with {} unique crashes and {} unique inconsistencies",
            crash_count, inc_count
        );
    } else {
        println!("{} is not a valid file or directory", folder);
    }
}

pub fn clear_unused_obj(amount: u32, start_index: u32) {
    let default_conf = repository::create_default_config("my.server.com".to_string());

    let mut excluded_files = vec![];
    let mut excluded_folders = vec![];

    for i in (0..start_index).rev() {
        let ca_name = "ca".to_string() + &i.to_string();
        let uri = ca_name.clone() + ".cer";
        excluded_files.push(uri);
        let folder_name = default_conf.BASE_REPO_DIR_l.clone() + &ca_name;
        excluded_folders.push(folder_name);
    }

    for i in (start_index + amount..10000).rev() {
        let uri = "ca".to_string() + &i.to_string() + ".cer";
        excluded_files.push(uri);
    }

    let start = Instant::now();
    for fold in excluded_folders.clone() {
        util::remove_folder_content(&fold);
        fs::remove_dir_all(&fold);
    }

    for f in excluded_files {
        let path = default_conf.BASE_REPO_DIR_l.clone() + "ta/" + &f;
        fs::remove_file(path);
    }
    let end = start.elapsed();
}

pub fn create_aux(amount: u32, start_index: u32) {
    let default_conf = repository::create_default_config("my.server.com".to_string());

    // println!("Excluded {} files", excluded.len());
    let mut excluded_files = vec![];

    for i in (0..start_index) {
        let ca_name = "ca".to_string() + &i.to_string();
        let uri = ca_name.clone() + ".cer";
        excluded_files.push(uri);
    }

    for i in (start_index + amount..10000) {
        let ca_name = "ca".to_string() + &i.to_string();
        let uri = ca_name.clone() + ".cer";
        excluded_files.push(uri);
    }

    repository::make_manifest_i("ta", "root", &default_conf, Some(excluded_files));
    let (ses, ser) = repository::get_current_session_notification(&default_conf);

    let (snapshot, n) = repository::create_current_snapshot(ses, ser, None, true, &default_conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = repository::create_notification(snapshot_bytes, vec![], n.as_str(), 5, ses, ser, &default_conf);
    repository::write_notification_file(notification, &default_conf).unwrap();
}

pub fn clear_repo() {
    let conf = repository::create_default_config("my.server.com".to_string());
    fs::remove_dir_all(conf.BASE_REPO_DIR_l.clone() + "newca").unwrap();
    for i in 0..4000 {
        let path = conf.BASE_REPO_DIR_l.clone() + "ca" + &i.to_string();
        let r = fs::remove_dir_all(path);
        if r.is_err() {
            return;
        }
    }
}

pub fn read_other_rp_logs(crashes: &Vec<(String, bool)>, rp_name: String) -> String {
    let mut ret = "\n[Non-Crashing RP Logs]\n".to_string();
    for c in crashes {
        if c.0 != rp_name {
            let l = util::read_rp_log(&c.0);
            ret += "<";
            ret += &c.0;
            ret += " log>\n ";
            ret += &l;
            ret += "\n\n";
        }
    }
    ret
}

// This is an experimental implementation
pub fn extract_error_from_log(log: &str, rp_name: &str, obj_type: &str) -> String {
    let ret;
    if rp_name == "routinator" {
        ret = log.split(&(".".to_string() + obj_type)).collect::<Vec<&str>>()[1].to_string()[2..].to_string();
    } else if rp_name == "octorpki" {
        ret = "".to_string();
    } else if rp_name == "fort" {
        ret = log.split("\n").collect::<Vec<&str>>()[1]
            .split(&(".".to_string() + obj_type))
            .collect::<Vec<&str>>()[1]
            .to_string()[2..]
            .to_string();
    } else if rp_name == "client" {
        let tmp = log.split("\n").collect::<Vec<&str>>();
        ret = tmp.last().unwrap().split(&(".".to_string() + obj_type)).collect::<Vec<&str>>()[1].to_string()[2..].to_string();
    } else {
        panic!("Unknown rp name");
    }
    ret
}

pub fn normalize_error_confident(log: &str, rp_name: &str, obj_type: &str) -> String {
    let log_s;
    if rp_name == "routinator" {
        log_s = log.to_string();
    } else if rp_name == "octorpki" {
        log_s = log.to_string();
    } else if rp_name == "fort" {
        // This removes the dates from the log which is necessary because they will differ between each log
        // Its ugly, maybe we can find a better way to do this
        let mut r = "".to_string();
        for l in log.split("\n") {
            let mut m = "".to_string();
            if l.is_empty() {
                continue;
            }
            for x in &l.split(":").collect::<Vec<&str>>()[3..] {
                m += x;
                m += ":";
            }
            let m = m[..m.len() - 1].to_string();
            if m.contains("The validation has") {
                continue;
            }
            r += &m;
            r += "\n";
        }

        log_s = r[..r.len() - 1].to_string();
    } else if rp_name == "client" {
        log_s = log.to_string();
    } else {
        panic!("Unknown rp name");
    }
    normalize_error(&log_s, obj_type)
}

pub fn normalize_error(log: &str, obj_type: &str) -> String {
    let obj_t;
    if obj_type == "cert" {
        obj_t = "cer";
    } else if obj_type == "aspa" {
        obj_t = "asa";
    } else {
        obj_t = obj_type;
    }
    let mut ret = "".to_string();
    let s = log.split(" ");
    for i in s {
        if i.ends_with(&(".".to_string() + obj_t + ":")) {
            ret += "[object]";
        } else {
            ret += i;
        }
        ret += " ";
    }
    // Remove last space
    let ret = ret[..ret.len() - 1].to_string();
    ret
}

pub fn string_similarity(s1: &str, s2: &str) -> f64 {
    jaro(s1, s2)
}

pub fn check_inc_unique(inc: &Vec<(String, bool, String)>, all_inc: &Vec<Vec<(String, bool, String)>>) -> bool {
    for i in all_inc {
        let mut unique = false;
        for j in 0..i.len() {
            let v = &i[j];
            let u = &inc[j];
            if v.0 != u.0 || v.1 != u.1 {
                unique = true;
                break;
            }
            let s = string_similarity(&v.2, &u.2);
            println!("Similarity: {}, {}, {}", v.2, u.2, s);

            if s < 0.9 {
                unique = true;
                break;
            }
        }
        if !unique {
            return false;
        }
    }
    true
}

pub fn roa_content_to_string(con: &Vec<RoaContents>) -> String {
    let mut ret = "".to_string();
    for c in con {
        if c.as_id.into_u32() == 22222 {
            // Skip sanity check
            continue;
        }
        ret += &c.ip_addr.to_string();
        ret += ",";
        ret += &c.prefix.to_string();
        ret += ",";
        ret += &c.as_id.to_string();
        ret += "\n";
    }
    ret
}

pub fn create_vrps(cons: Vec<Vec<RoaContents>>) -> String {
    let mut ret = "".to_string();
    let rp_names = ["Routiantor", "Octorpki", "Fort", "Client"];
    for i in 0..cons.len() {
        let con = &cons[i];
        let s = roa_content_to_string(con);
        ret += &(rp_names[i].to_string() + ":\n " + &s + "");
    }
    ret.to_string()
}

pub fn process_result(
    filename: &str,
    obj_type: &str,
    seen: Option<&mut Vec<String>>,
    report: Option<String>,
    write_to_disc: bool,
    all_inconsistencies: &mut Vec<Vec<(String, bool, String)>>,
) -> (u16, u16, String, Vec<Vec<(String, bool, String)>>) {
    let timelimit = 6000;
    let fast_mode = true;
    let only_crash = false;
    let log_level = "error";

    let mut conf = repository::create_default_config(consts::domain.to_string());
    repository::initialize_repo(&mut conf, false, None);
    if obj_type == "mft" || obj_type == "crl" {
        let (_, _) = util::create_cas(4000, vec![&conf], None);
    }

    // Inconsistent data
    let mut fresult = vec![];
    // Crash data
    let mut crash_result = vec![];
    let data = read_data_uniform(filename, obj_type);
    let mut queue = vec![];

    let fd = &data[0..data.len() / 2];
    let sd = &data[data.len() / 2..data.len()];
    queue.push(fd);
    queue.push(sd);
    let start = Instant::now();

    let mut crash_count = 0;
    let mut inc_count = 0;

    let mut seen_crash_logs;
    let mut tmp = vec![];
    // let mut all_inconsistencies = vec![];
    if seen.is_none() {
        seen_crash_logs = &mut tmp;
    } else {
        seen_crash_logs = seen.unwrap();
    }

    while !queue.is_empty() {
        let start = Instant::now();
        util::clear_caches();
        if obj_type == "roa" {
            util::remove_folder_content(&(conf.BASE_REPO_DIR_l.clone() + "/newca/"));
        }
        let end = start.elapsed();
        // println!("Time elapsed in clear repo is: {:?}", end);
        if start.elapsed().as_secs() > timelimit {
            println!("Timelimit reached, not processing further file: {}", filename);
            break;
        }

        let q = queue.pop().unwrap();
        if q.is_empty() {
            println!("\n --> Error: Parsing did not work! Maybe you used the wrong file type?\n");
            return (0, 0, "".to_string(), all_inconsistencies.to_vec());
        }
        handle_data_uniform(q.clone().to_vec(), filename, &mut conf, obj_type);
        create_aux(q.len().try_into().unwrap(), q[0].6);
        // println!("Checking between {} and {}", q[0].6, q[0].6 + q.len() as u32);
        let crashes = util::run_rp_processes(log_level);
        let mut something_crashed = false;

        let mut crash_log = "".to_string();

        let mut rp_crash_log = "".to_string();
        let mut rp_log;
        for c in crashes.clone() {
            if c.1 {
                println!("Crashes between {} and {}", q[0].6, q[0].6 + q.len() as u32);
                clear_unused_obj(q.len().try_into().unwrap(), q[0].6);

                something_crashed = true;

                crash_log += &("\n[Crash]\n".to_string());
                crash_log += "<RP Name>\n ";
                crash_log += &c.0;
                crash_log += "\n";
                let d = &q[0].1;
                let b64 = base64::encode(d);

                rp_log = util::read_rp_log(&c.0);
                rp_crash_log = rp_log.clone();

                crash_log += "<";
                crash_log += &c.0;
                crash_log += " error log>\n ";
                crash_log += &rp_log;

                crash_log += "\n\n";
                crash_log += &read_other_rp_logs(&crashes, c.0.clone());
                crash_log += &("<Object>\n ".to_string() + &b64 + "\n\n");
            }
        }

        let (res, iden, smaller_rps, conte) = util::get_rp_vrps();
        if !iden {
            println!("Inconsistency between {} and {}", q[0].6, q[0].6 + q.len() as u32);
            clear_unused_obj(q.len().try_into().unwrap(), q[0].6);
        }

        if !iden || something_crashed {
            if q.clone().len() == 1 {
                if something_crashed {
                    if !seen_crash_logs.contains(&rp_crash_log.to_string()) {
                        println!("Logging a crash!");
                        seen_crash_logs.push(rp_crash_log.to_string().clone());
                        crash_count += 1;
                        crash_result.push(crash_log);
                        if fast_mode {
                            break;
                        }
                    } else {
                        println!("Already logged this crash! {}", rp_crash_log);
                    }
                } else {
                    println!("Logging an Inconsistency!");
                    let v = create_vrps(conte);

                    inc_count += 1;
                    let mut r = "[Result]\n".to_string();
                    r += "<VRPS>\n ";
                    r += &v;

                    // r += &res;
                    r += "<Object>\n ";
                    let d = &q[0].1;
                    let b64 = base64::encode(d);
                    r += &b64;
                    r += "\n\n";

                    for rp in smaller_rps.clone() {
                        let rp_log = util::read_rp_log(&rp);
                        r += "<";
                        r += &rp;
                        r += " inconsistency log>\n ";
                        r += &rp_log;
                        r += "\n\n";
                    }

                    fresult.push(r.clone());

                    let mut inc = vec![];
                    for c in crashes {
                        let rp_name = c.0;
                        if smaller_rps.contains(&rp_name) {
                            let rp_log = util::read_rp_log(&rp_name);
                            let rp_log = normalize_error_confident(&rp_log, &rp_name, obj_type);
                            inc.push((rp_name, true, rp_log));
                        } else {
                            inc.push((rp_name, false, "".to_string()));
                        }
                    }

                    let un = check_inc_unique(&inc, &all_inconsistencies);
                    println!("Was unique {}", un);

                    if un {
                        all_inconsistencies.push(inc);
                    }

                    if fast_mode {
                        if inc_count > 10 {
                            break;
                        }
                        // break;
                    }
                }
                continue;
            }
            if !something_crashed && only_crash {
                // println!("Nothing crashed");
                continue;
            }
            let fd = &q.clone()[0..q.len() / 2];
            let sd = &q.clone()[q.len() / 2..q.len()];
            queue.push(fd);
            queue.push(sd);
        }
    }

    let mut final_output;
    if report.is_none() {
        final_output = "------  Fuzzer Finding Report  ------\n".to_string();
    } else {
        final_output = "\n".to_string() + &report.unwrap();
    }
    final_output += &("Serialized Filename: ".to_string() + filename + "\n");
    final_output += &("Object Type: ".to_string() + obj_type + "\n\n");

    final_output += "--- Crashes ---\n";
    if crash_result.len() == 0 {
        final_output += "No crashes found\n\n\n";
    } else {
        final_output += "\n";
        for c in crash_result.clone() {
            final_output += &c;
            // final_output += "\n\n";
        }
    }

    final_output += "--- Inconsistencies ---\n";
    if fresult.len() == 0 {
        final_output += "No inconsistencies found\n\n";
    } else {
        final_output += "\n";

        for c in fresult {
            final_output += &c;
        }
    }

    final_output += "\n";

    println!("All Inconsistencies\n\n {:?}", all_inconsistencies);

    // && crash_result.len() != 0
    if write_to_disc {
        write_report_to_disc(filename, &final_output)
    } else {
        println!("Report not written to disc because no crashes were found");
    }

    (crash_count, inc_count, final_output, all_inconsistencies.to_vec())
}

pub fn write_report_to_disc(filename: &str, final_output: &str) {
    let cws = util::get_cwd() + "/";
    let fol = cws + "detailed_reports/";
    fs::create_dir_all(&fol);
    let uri = fol + Path::new(&filename).file_stem().unwrap().to_str().unwrap() + ".txt";
    fs::write(&uri, &final_output);

    println!("Report written to {}", uri);
}

pub fn generate_test_serialized() -> String {
    let mut conf = repository::create_default_config(consts::domain.to_string());
    util::clear_repo(&conf, 1);
    let amount = 10;
    conf.CA_TREE.insert("ta".to_string(), "root".to_string());

    conf.CA_TREE.insert("newca".to_string(), "ta".to_string());

    let mut objects = vec![];
    for _ in 0..amount {
        let roa = repository::create_random_roa_ca(&conf, "newca");
        let file_name = util::random_file_name();
        objects.push((file_name, roa.0.to_vec()));
    }

    util::serialize_data(&objects)
}
