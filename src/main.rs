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
use std::os::unix::net::UnixListener;
use std::process::{Child, Command};
use std::time::Instant;
use std::{env, thread, vec};
use std::{fmt, fs};

mod asn1p;
mod consts;
mod coverage_interface;
mod fuzzing;
mod fuzzing_loop;
mod fuzzing_repo;
mod generation_interface;
mod mutator;
mod process_util;
mod profraw;
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

    let roas = util::create_example_roas(10000);
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

fn sign(conf: FuzzConfig) {
    if conf.dont_move {
        println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
    }

    let (roas, crls, mfts) = processing::create_aux_objects(&conf);

    let socket = "/tmp/gensock".to_string() + &conf.id.to_string();
    fs::remove_file(&socket).unwrap_or_default();

    let stream = UnixListener::bind(&socket).unwrap();
    stream.set_nonblocking(true).unwrap();

    processing::create_objects(false, conf, roas, crls, mfts, &stream);
}

fn generate(conf: FuzzConfig) {
    fuzzing_loop::start_generation();
}

fn fuzz(mut conf: FuzzConfig, folders: Option<Vec<String>>) {
    println!("\n--- RPKI Relying Party Fuzzer ---\n");
    println!("Info: Object Type: {}", typ_to_name(&conf.typ.to_string()));

    // TODO Re-Enable Test run

    // if generation_interface::test_run() {
    //     return;
    // }

    println!("Info: Creating Folders");
    repository::initialize_repo(&mut conf.repo_conf, false, None);

    let rrdp_types = vec!["notification", "snapshot", "delta"];

    util::start_generation("./bin/generator", "roa", &conf.amount.to_string());
    util::start_signing("./bin/generator");

    let mut factory = process_util::ObjectFactory::new(50, "/tmp/fuzzing");

    if !rrdp_types.contains(&conf.typ.to_string().as_str()) {
        // conf.amount = 100;

        // let (_, folders) = util::start_processes("./bin/signer", &conf.typ.to_string(), folders, conf.amount, conf.raw);

        util::start_fuzzing(conf, &mut factory);
    } else {
        if conf.typ == OpType::NOTI {
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
    pub amount: u32,
    pub dont_move: bool,
    pub no_ee: bool,
    pub repo_conf: RepoConfig,
    pub id: u8,
    pub raw: bool,
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
    uri: Option<String>,

    #[arg(short, long)]
    only_content: Option<bool>,

    #[arg(short, long)]
    dont_move: Option<bool>,

    #[arg(short, long)]
    subcommand: Option<String>,

    #[arg(short, long)]
    amount: Option<u32>,

    #[arg(short, long)]
    id: Option<u8>,

    #[arg(short, long)]
    raw: Option<bool>,
}

fn key_id(data: Vec<u8>) -> usize {
    let mut total: usize = 0;
    let mut i = 0;
    while i < data.len() - 1 {
        total += ((data[i] as usize) << 8) + data[i + 1] as usize;
        i += 2;
    }
    total += (total >> 16) & 0xFFFF;
    return total & 0xFFFF;
}

pub fn test_keys() {
    let mut key_id_distr = HashMap::new();
    for i in 0..10000 {
        let file_uri = "data/keys/".to_string() + &i.to_string() + ".der";
        let bits = repository::read_cert_key(&file_uri).get_pub_key();
        let byt = bits.bits();
        let mut base_data = vec![1, 0, 3, 8];
        base_data.extend(byt.to_vec());

        let kid = key_id(base_data);
        if key_id_distr.contains_key(&kid) {
            key_id_distr.insert(kid, key_id_distr.get(&kid).unwrap() + 1);
        } else {
            key_id_distr.insert(kid, 1);
        }
    }
    println!("{:?}", key_id_distr);
}

fn main() {
    // let ve = vec![1, 2, 3, 4, 5, 6, 7, 8];
    // let mut v = Bytes::from(ve);
    // bcder::length::Length::take_from(&mut v, Mode::Der).unwrap();
    // return;
    util::clear_caches();

    let mut conf = repository::create_default_config("my.server.com".to_string());
    generation_interface::pp_test();
    return;
    // let args: Vec<String> = env::args().collect();

    // // Check if the arguments include `--add-roa`
    // if args.len() > 2 && args[1] == "--add-roa" {
    //     repository::add_roa_str(&args[2], false, &conf);

    //     // // Check if the roa-content is provided
    //     // if args.len() > 2 {
    //     //     let roa_content = &args[2];
    //     // }
    // }
    // else{
    //     repository::initialize_repo(&mut conf, false, None);
    // }
    // return;

    // let re = &util::create_example_roas(1)[0];
    // return;
    // // println!("Roa {:?}", base64::encode(re.0.clone()));
    // repository::add_roa_str("10.0.0.0/24 => AS1776", false, &conf);

    // generation_interface::test_generation();
    // generation_interface::full_test();
    // generation_interface::pp_test();
    // return;

    util::clear_caches();

    // let res = Args::parse();

    // Parse in the command line arguments
    // let type_name = res.typ;
    // let uri_r = &res.uri.unwrap_or("None".to_string());
    // let no_ee = res.only_content.unwrap_or(false);
    // let typ = parse_type(&type_name);
    // let subtype = res.subcommand.unwrap_or("none".to_string());
    // let amount = res.amount.unwrap_or(1);
    // let dont_move = false;
    // let id = res.id.unwrap_or(0);
    // let raw = res.raw.unwrap_or(false);

    let type_name = "roa";
    let uri_r = "None".to_string();
    let no_ee = false;
    let typ = parse_type(&type_name);
    let subtype = "none".to_string();
    let amount = match &env::args().collect::<Vec<String>>().len() > &2 {
        true => env::args().collect::<Vec<String>>()[2].parse::<u32>().unwrap_or(1),
        false => 1,
    };
    // let amount = 1;
    let dont_move = false;
    let id = 0;
    let raw = false;

    // Ensure uri is absolute
    let tmp;
    let uri: &str;
    if uri_r.starts_with("/") {
        uri = &uri_r;
    } else {
        tmp = get_cwd() + "/" + &uri_r;
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
        id,
        raw,
    };

    let command = &env::args().collect::<Vec<String>>()[1];
    // let c = res.command.as_str();
    match command.as_str() {
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
        "sign" => {
            sign(fuzz_config);
            return;
        }
        "fuzz" => {
            fuzz(fuzz_config, None);
            return;
        }
        "generate" => {
            generate(fuzz_config);
            return;
        }
        "signing" => {
            fuzzing_repo::signing_loop(fuzz_config, amount);
        }
        _ => unreachable!(),
    }
}
