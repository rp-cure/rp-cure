use bcder::encode::{PrimitiveContent, Values};
use bcder::Mode;
use bytes::Bytes;

use openssl::conf;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rpki::repository::resources::{self, Addr, IpBlock, Prefix};

use crate::fuzzing::processing;
use publication_point::repository::RepoConfig;
use publication_point::{fuzzing_interface, repository};
mod result_processing;
mod util;
use crate::vrps_analysis::find_affected_entries;
use clap::{command, Arg, CommandFactory, Parser};
use core::panic;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::{Child, Command};
use std::time::Instant;
use std::{env, thread, vec};
use std::{fmt, fs};

mod asn1p;
mod consts;
mod coverage_interface;
mod fuzzing;
mod generation_interface;
mod process_util;
mod publication_point;
mod vrps_analysis;

use crate::generation_interface::OpType;

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

#[derive(PartialEq)]
enum OpMode {
    Generation,
    GenerationMP,
    Fuzzer,
    Processor,
    Runner,
    Vrps,
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
        if self == &OpType::CERTCA {
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
        return OpType::CERTCA;
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

fn run(mut conf: FuzzConfig) {
    println!("\n--- RPKI Relying Party Runner ---\n");

    if generation_interface::test_run() {
        return;
    }

    repository::initialize_repo(&mut conf.repo_conf, false, None);

    processing::srun(conf);

    println!("Info: Running RPs");
    let re = util::run_rp_processes("info");

    for r in re {
        if r.1 {
            println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
        }
    }

    let (vrps, _, _, _) = util::get_rp_vrps();

    println!("Info: RPs finished, Logs written to output/\n");
    println!("<VRPS>\n{}", vrps);
}

fn generate(conf: FuzzConfig) {
    if conf.dont_move {
        println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
    }

    // let uri = uri.to_string();

    // TODO
    // if typ == OpType::MFT {
    //     fuzzing::mft::create_objects(uri, amount, dont_move, false, 4000, false);
    // } else if typ == OpType::CRL {
    //     fuzzing::crl::create_objects(uri, amount, dont_move, false, 4000);
    // } else if typ == OpType::ROA || typ == OpType::ASPA || typ == OpType::GBR {
    //     fuzzing::roa::create_objects_new(uri, amount, dont_move, false, 10000, false, &typ.to_string(), &conf);
    // } else if typ == OpType::CERTCA {
    //     fuzzing::cert::create_objects(uri, amount, dont_move, false, 10000);
    // } else {
    //     panic!("Unknown object type generator!");
    // }
    std::process::exit(0);
}

fn fuzz(mut conf: FuzzConfig, folders: Option<Vec<String>>) {
    println!("\n--- RPKI Relying Party Fuzzer ---\n");
    println!("Info: Object Type: {}", typ_to_name(&conf.typ.to_string()));

    if generation_interface::test_run() {
        return;
    }

    println!("Info: Creating Folders");

    repository::initialize_repo(&mut conf.repo_conf, false, None);
    let cws = get_cwd() + "/";
    let rrdp_types = vec!["notification", "snapshot"];

    if !rrdp_types.contains(&conf.typ.to_string().as_str()) {
        let (mut children, folders) = util::start_processes("./bin/object_generator", &conf.typ.to_string(), folders);
        let obj_cache = cws + "obj_cache/";

        let obj_per_iteration;
        let repo_fn: &dyn Fn(&RepoConfig, u32);
        let serialized_obj_fn: &dyn Fn(&str, &RepoConfig, u32, Option<Vec<(Bytes, String)>>, &str);

        if conf.typ == OpType::MFT {
            obj_per_iteration = 5000;

            repo_fn = &fuzzing::mft::clear_repo;
            serialized_obj_fn = &fuzzing::mft::handle_serialized_object;
        } else if conf.typ == OpType::CERTCA {
            obj_per_iteration = 10000;

            repo_fn = &util::clear_repo;
            serialized_obj_fn = &fuzzing::cert::handle_serialized_object;
        } else if conf.typ == OpType::ROA || conf.typ == OpType::GBR || conf.typ == OpType::ASPA {
            obj_per_iteration = 10000;

            repo_fn = &util::clear_repo;
            serialized_obj_fn = &fuzzing::roa::handle_serialized_object;
        } else {
            panic!("Unknown object type!");
        }

        util::start_fuzzing(
            &obj_cache,
            &conf.typ.to_string(),
            folders,
            obj_per_iteration,
            repo_fn,
            serialized_obj_fn,
            &mut children,
        );
    } else {
        if conf.typ == OpType::NOTI {
            if conf.dont_move {
                println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
            }

            let create_fun = fuzzing::notification::create_notifications;
            let repo_fn = &util::clear_repo;
            util::start_fuzzing_xml(
                &conf.typ.to_string(),
                vec![conf.uri.to_string().clone()],
                4000,
                repo_fn,
                &create_fun,
                conf.dont_move,
            );
            return;
        } else if conf.typ == OpType::SNAP {
            if conf.dont_move {
                println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
            }
            let create_fun = fuzzing::snapshot::create_snapshots;
            let repo_fn = &util::clear_repo;
            util::start_fuzzing_xml(
                &conf.typ.to_string(),
                vec![conf.uri.to_string().clone()],
                4000,
                repo_fn,
                &create_fun,
                conf.dont_move,
            );
        }
    }
}

pub struct FuzzConfig {
    pub typ: OpType,
    pub uri: String,
    pub subtype: String,
    pub amount: u16,
    pub dont_move: bool,
    pub no_ee: bool,
    pub repo_conf: RepoConfig,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long, index = 1)]
    command: String,

    #[arg(short, long)]
    typ: String,

    #[arg(short, long)]
    uri: String,

    #[arg(short, long)]
    only_content: Option<bool>,

    #[arg(short, long)]
    dont_move: Option<bool>,

    #[arg(short, long)]
    subcommand: Option<String>,

    /// Number of times to greet
    #[arg(short, long)]
    amount: Option<u16>,
}

fn main() {
    util::clear_caches();
    let res = Args::parse();

    // println!("{:?}", res);
    // return;

    // let matches = App::new("RP CURE")
    //     .version("0.1.0")
    //     .author("RP-CURE")
    //     .about("A RPKI Relying Party Fuzzing Tool")
    //     .subcommand(
    //         App::new("run")
    //             .about("Runs a command")
    //             .arg(
    //                 Arg::with_name("type")
    //                     .long("type")
    //                     .required(true)
    //                     .takes_value(true)
    //                     .help("Execution Type. Choose from run (Execute in a one-shot) or fuzz (Execute in a fuzzing mode)"),
    //             )
    //             .arg(
    //                 Arg::with_name("uri")
    //                     .long("uri")
    //                     .required(true)
    //                     .takes_value(true)
    //                     .help("The URI to a file"),
    //             )
    //             .arg(
    //                 Arg::with_name("oc")
    //                     .long("only-content")
    //                     .help("File is only the encapsulated content info of the object"),
    //             )
    //             .arg(
    //                 Arg::with_name("dm")
    //                     .long("dont-move")
    //                     .help("Do not delete Objects after processing"),
    //             )
    //             .arg(Arg::with_name("st").long("sub-type").help("Subtype of VRPS analysis"))
    //             .arg(Arg::with_name("am").long("amount").help("Amount of Objects to generate")),
    //     )
    //     .get_matches();

    let type_name = res.typ;
    let uri_r = &res.uri;
    let no_ee = res.only_content.unwrap_or(false);
    let typ = parse_type(&type_name);
    let subtype = res.subcommand.unwrap_or("none".to_string());
    let amount = res.amount.unwrap_or(1);
    let dont_move = res.dont_move.is_some();

    let tmp;
    let uri: &str;
    if uri_r.starts_with("/") {
        uri = uri_r;
    } else {
        tmp = get_cwd() + "/" + uri_r;
        uri = &tmp;
    }

    let fuzz_config = FuzzConfig {
        typ,
        uri: uri.to_string(),
        subtype: subtype.to_string(),
        amount,
        dont_move,
        no_ee,
        repo_conf: repository::create_default_config(consts::domain.to_string()),
    };

    let c = res.command.as_str();
    match c {
        "run" => {
            run(fuzz_config);
            return;
        }
        "process" => {
            println!("\n\n--- RPKI Result Processor ---\n");

            println!("Info: Processing Results");
            println!("This might take a few minutes...");

            result_processing::process_results(fuzz_config);
        }
        "vrps" => {
            println!("\n\n--- RPKI VRPS Analysis ---\n");
            vrps_analysis::start_analysis(fuzz_config);
        }
        "generate" => {
            generate(fuzz_config);
            return;
        }
        "fuzz" => {
            fuzz(fuzz_config, None);
            return;
        }
        _ => unreachable!(),
    }
}
