use bcder::encode::{PrimitiveContent, Values};
use bcder::Mode;
use bytes::Bytes;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rpki::repository::resources::{self, Addr, IpBlock, Prefix};

use publication_point::repository::RepoConfig;
use publication_point::{fuzzing_interface, repository};
mod result_processing;
mod util;
use core::panic;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Child;
use std::{env, thread, vec};
use std::{fmt, fs};

use crate::vrps_analysis::find_affected_entries;

mod asn1p;
mod consts;
mod fuzzing;
mod publication_point;
mod vrps_analysis;
use clap::{Arg, ArgGroup, Command, Subcommand};
pub fn get_cwd() -> String {
    env::current_dir().unwrap().into_os_string().into_string().unwrap()
}

fn create_folders() {
    let cws = get_cwd() + "/";
    let folders = vec![cws.clone() + "obj_cache", cws.clone() + "fuzz_output", cws.clone() + "output"];

    for folder in folders {
        fs::create_dir_all(folder);
    }
}

fn create_normal_repo() {
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

fn test_run() -> bool {
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
    util::clear_caches();

    fault
}

#[derive(PartialEq)]
enum OpMode {
    Generation,
    Fuzzer,
    Processor,
    Runner,
    Vrps,
}

#[derive(PartialEq)]
enum OpType {
    MFT,
    ROA,
    CRL,
    CERT,
    SNAP,
    NOTI,
    ASPA,
    GBR,
}

impl fmt::Display for OpType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self == &OpType::MFT {
            return write!(f, "mft");
        }
        if self == &OpType::ROA {
            return write!(f, "roa");
        }
        if self == &OpType::CRL {
            return write!(f, "crl");
        }
        if self == &OpType::CERT {
            return write!(f, "cert");
        }
        if self == &OpType::SNAP {
            return write!(f, "snapshot");
        }
        if self == &OpType::NOTI {
            return write!(f, "notification");
        }
        if self == &OpType::ASPA {
            return write!(f, "aspa");
        }
        if self == &OpType::GBR {
            return write!(f, "gbr");
        }
        panic!("Error: Unknown OpType");

        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

pub fn typ_to_name(typ: &str) -> String {
    let mut names = HashMap::new();
    names.insert("roa", "Route Origin Authorization");
    names.insert("mft", "Manifest");
    names.insert("crl", "Certificate Revocation List");
    names.insert("cert", "Certificate");
    names.insert("gbr", "Ghostbuster Record");
    names.insert("aspa", "AS Provider Attestation");
    names.insert("snapshot", "Snapshot");
    names.insert("notification", "Notification");
    return names.get(typ).unwrap().to_string();
}

pub fn store_example_roa() {
    let conf = repository::create_default_config("my.server.com".to_string());
    let cws = util::get_cwd() + "/";

    let roas = util::create_example_roas(&vec![], 10000, &conf);

    fs::create_dir_all(cws.clone() + "roas_4/").unwrap();

    for i in roas {
        let con = asn1p::extract_e_content(i.0, Some("roa")).unwrap();
        let name: String = thread_rng().sample_iter(&Alphanumeric).take(14).map(char::from).collect();
        fs::write(cws.clone() + "roas_4/" + &name, con).unwrap();
    }
}

fn parse_mode(mode: &str) -> OpMode {
    if mode == "processor" {
        return OpMode::Processor;
    } else if mode == "gen" {
        return OpMode::Generation;
    } else if mode == "fuzz" {
        return OpMode::Fuzzer;
    } else if mode == "run" {
        return OpMode::Runner;
    } else if mode == "vrps" {
        return OpMode::Vrps;
    } else {
        panic!("Invalid arguments! Use 'fuzz' to run the fuzzer, 'gen' to generate objects, 'processor' to process results or 'run' for a single run");
    }
}

fn parse_type(typ: &str) -> OpType {
    if typ == "roa" {
        return OpType::ROA;
    } else if typ == "mft" {
        return OpType::MFT;
    } else if typ == "crl" {
        return OpType::CRL;
    } else if typ == "cert" {
        return OpType::CERT;
    } else if typ == "gbr" {
        return OpType::GBR;
    } else if typ == "aspa" {
        return OpType::ASPA;
    } else if typ == "snapshot" {
        return OpType::SNAP;
    } else if typ == "notification" {
        return OpType::NOTI;
    } else {
        panic!("Invalid Object Type! Use 'roa', 'mft', 'crl', 'cert', 'gbr', 'aspa', 'snapshot' or 'notification'");
    }
}

fn main() {
    util::clear_caches();
    // let matches = Command::new("CURE")
    //     .version("1.0")
    //     .author("RP-CURE-DEV")
    //     .about("A tool for testing RPKI Relying Party Software")
    //     .arg(
    //         Arg::new("uri")
    //             .required(true)
    //             .short('u')
    //             .help("URI of Object/Folder")
    //             .value_name("URI"),
    //     )
    //     .arg(
    //         Arg::new("type")
    //             .required(true)
    //             .short('t')
    //             .help("Object Type [roa, mft, crl, cert, gbr, aspa, snapshot, or notification]")
    //             .value_name("TYPE"),
    //     )
    //     .subcommand(
    //         Subcommand::new("run")
    //             .about("Execute a single run")
    //             .arg(Arg::new("contains-ee").required(true).short('e').help("Object contains EE-Cert")),
    //     )
    //     .subcommand(Subcommand::new("processor").about("Process Results"))
    //     .subcommand(
    //         Subcommand::with_name("vrps_analysis").about("Process Results").arg(
    //             Arg::new("analysis_type")
    //                 .required(true)
    //                 .short('a')
    //                 .help("Analysis Type [folder, raw_folder, cache]"),
    //         ),
    //     )
    //     .subcommand(
    //         Subcommand::with_name("gen")
    //             .about("Generate processed Objects")
    //             .arg(Arg::new("amount").required(false).short('a').help("Max amount of generated Files"))
    //             .value_name("AMOUNT")
    //             .arg(
    //                 Arg::new("dont_move")
    //                     .required(false)
    //                     .short('d')
    //                     .help("Do not delete processed Files [Debugging]"),
    //             ),
    //     )
    //     .subcommand(Subcommand::with_name("fuzz").about("Start the Fuzzer"))
    //     .get_matches();

    // println!("{}", matches.get_flag("contains-ee").unwrap());
    // return;

    let typ;
    let mode;
    let uri;
    let mut additional_info = vec![];
    let a: Vec<String> = env::args().collect();
    // let a = vec!["a".to_string(), "vrps".to_string(), "roa".to_string(), "inv".to_string(), "no_ee".to_string()];

    let valid_types = vec!["roa", "mft", "crl", "cert", "gbr", "aspa", "snapshot", "notification"];

    if a.len() > 1 {
        mode = parse_mode(&a[1]);
    } else {
        panic!("Invalid arguments! Use 'fuzz' to run the fuzzer, 'gen' to generate objects, 'processor' to process results or 'run' for a single run");
    }

    if a.len() > 2 && valid_types.contains(&a[2].as_str()) {
        typ = parse_type(&a[2]);
    } else {
        panic!("Invalid arguments! Please provide a Type (roa, mft, crl, cert, gbr, aspa, snapshot, notification)");
    }

    if mode != OpMode::Fuzzer {
        if a.len() > 3 {
            uri = a[3].clone();
        } else {
            panic!("Invalid arguments! Please provide a URI to a File or Folder");
        }
    } else {
        uri = "".to_string();
    }

    // Some modes need additional info
    for i in 4..a.len() {
        if a.len() > i {
            additional_info.push(a[i].clone());
        }
    }

    create_folders();

    if mode == OpMode::Processor {
        println!("\n\n--- RPKI Result Processor ---\n");

        println!("Info: Processing Results");
        println!("This might take a few minutes...");

        result_processing::process_results(&uri, &typ.to_string());
        return;
    } else if mode == OpMode::Vrps {
        let ty;
        if additional_info.len() == 0 {
            panic!("Invalid arguments! Please provide information on what to look at (folder, file, cache)");
        } else {
            ty = additional_info[0].clone();
        }
        vrps_analysis::start_analysis(&uri, &typ.to_string(), &ty);
    } else if mode == OpMode::Runner {
        println!("\n--- RPKI Relying Party Standalone Fuzzer ---\n");

        let re = test_run();
        if re {
            return;
        }

        let mut no_ee = false;
        if additional_info.len() > 0 && additional_info[0] == "no_ee" {
            no_ee = true;
        }

        let mut conf = repository::create_default_config(consts::domain.to_string());

        let cont = fs::read(&uri).unwrap();
        let con_ips = vrps_analysis::get_content_ips(Bytes::from(cont));
        conf.IPBlocks.extend(con_ips);

        repository::initialize_repo(&mut conf, false, None);

        if typ == OpType::MFT {
            fuzzing::mft::do_both(&uri, no_ee, &conf);
        } else if typ == OpType::CRL {
            fuzzing::crl::do_both(&uri, &mut conf);
        } else if typ == OpType::ROA || typ == OpType::GBR || typ == OpType::ASPA {
            fuzzing::roa::do_both(&uri, no_ee, &typ.to_string(), &conf);
        } else if typ == OpType::CERT {
            fuzzing::cert::do_both(&uri, &conf);
        } else {
            panic!("Unknown object type!");
        }

        println!("Info: Finished creating all objects in data/repo/ folder");
        println!("Info: Running RPs");
        let re = util::run_rp_processes("info");

        for r in re {
            if r.1 {
                println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
            }
        }

        let rp_names = vec!["Routinator", "OctoRPKI", "Fort", "RPKI-Client"];
        let (vrps, _, _, roas) = util::get_rp_vrps();
        let mut fault_occured = false;
        for i in 0..roas.len() {
            let r = &roas[i];
            let mut two_in = false;

            for v in r {
                if v.as_id.into_u32() == 22222 {
                    two_in = true;
                }
            }
            if !(two_in) {
                println!("Warning: {} did not accept test ROA ASN22222", rp_names[i]);
                fault_occured = true;
            }
        }
        println!("");
        if !fault_occured {
            println!("Info: All RPs accepted test ROA 22222");
        }
        println!("Info: RPs finished, Logs written to output/\n");
        println!("<VRPS>\n{}", vrps);
        return;
    } else if mode == OpMode::Generation {
        let amount;
        if additional_info.len() > 0 {
            amount = additional_info[0].parse::<u16>().unwrap();
        } else {
            amount = 20;
        }
        let dont_move;
        if additional_info.len() > 1 {
            dont_move = additional_info[1].parse::<bool>().unwrap();
        } else {
            dont_move = true;
        }

        if dont_move {
            println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
        }

        let conf = repository::create_default_config(consts::domain.to_string());
        if typ == OpType::MFT {
            fuzzing::mft::create_objects(uri, amount, dont_move, false, 4000, false);
        } else if typ == OpType::CRL {
            fuzzing::crl::create_objects(uri, amount, dont_move, false, 4000);
        } else if typ == OpType::ROA || typ == OpType::ASPA || typ == OpType::GBR {
            // TODO change this back
            fuzzing::roa::create_objects(uri, amount, dont_move, false, 10000, false, &typ.to_string(), &conf);
        } else if typ == OpType::CERT {
            fuzzing::cert::create_objects(uri, amount, dont_move, false, 10000);
        } else {
            panic!("Unknown object type generator!");
        }
        std::process::exit(0);
    } else if mode == OpMode::Fuzzer {
        println!("\n--- RPKI Relying Party Fuzzer ---\n");
        println!("Info: Object Type: {}", typ_to_name(&typ.to_string()));

        let re = test_run();
        if re {
            return;
        }

        let folders = match additional_info.len() > 0 {
            true => {
                let mut ret = vec![];
                for i in additional_info {
                    ret.push(i);
                }
                Some(ret)
            }
            false => None,
        };

        println!("Info: Creating Folders");

        let mut con = repository::create_default_config(consts::domain.to_string());
        repository::initialize_repo(&mut con, false, None);
        let cws = get_cwd() + "/";
        let rrdp_types = vec!["notification", "snapshot"];

        if !rrdp_types.contains(&typ.to_string().as_str()) {
            let (mut children, folders) = util::start_processes("./bin/object_generator", &typ.to_string(), folders);
            let obj_cache = cws + "obj_cache/";

            let obj_per_iteration;
            let repo_fn: &dyn Fn(&RepoConfig, u32);
            let serialized_obj_fn: &dyn Fn(&str, &RepoConfig, u32, Option<Vec<(Bytes, String)>>, &str);

            if typ == OpType::MFT {
                obj_per_iteration = 5000;

                repo_fn = &fuzzing::mft::clear_repo;
                serialized_obj_fn = &fuzzing::mft::handle_serialized_object;
            } else if typ == OpType::CERT {
                obj_per_iteration = 10000;

                repo_fn = &util::clear_repo;
                serialized_obj_fn = &fuzzing::cert::handle_serialized_object;
            } else if typ == OpType::ROA || typ == OpType::GBR || typ == OpType::ASPA {
                obj_per_iteration = 10000;

                repo_fn = &util::clear_repo;
                serialized_obj_fn = &fuzzing::roa::handle_serialized_object;
            } else {
                panic!("Unknown object type!");
            }

            util::start_fuzzing(
                &obj_cache,
                &typ.to_string(),
                folders,
                obj_per_iteration,
                repo_fn,
                serialized_obj_fn,
                &mut children,
            );
        } else {
            if typ == OpType::NOTI {
                let dont_move = false;
                if dont_move {
                    println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
                }

                let create_fun = fuzzing::notification::create_notifications;
                let repo_fn = &util::clear_repo;
                util::start_fuzzing_xml(&typ.to_string(), vec![uri.clone()], 4000, repo_fn, &create_fun, dont_move);
                return;
            } else if typ == OpType::SNAP {
                let dont_move = false;
                if dont_move {
                    println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
                }
                let create_fun = fuzzing::snapshot::create_snapshots;
                let repo_fn = &util::clear_repo;
                util::start_fuzzing_xml(&typ.to_string(), vec![uri.clone()], 4000, repo_fn, &create_fun, dont_move);
                return;
            }
        }
    }
}
