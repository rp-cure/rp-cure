use rpki::repository::resources::Asn;
use std::collections::HashMap;
use std::net::{Ipv4Addr, IpAddr, Ipv6Addr};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::{fs, str};

use crate::publication_point::constants;
use crate::repository;
use crate::publication_point::manual_tests::test_util;

use crate::repository::RPConfig;

use csv;
use std::str::FromStr;

use serde_json::Value;




pub fn run_rp_command(
    command_tuples: Vec<(&str, &str)>,
    conf: &RPConfig,
    pre: &str,
    server: bool,
    rp_name: &str,
) -> (String, String, Option<Child>) {
    // let rp_log = "./output/rp_".to_string() + rp_name + ".log";
    let path = std::path::Path::new(&conf.logfile);
    let prefix = path.parent().unwrap();

    fs::create_dir_all(&prefix);
    fs::create_dir_all(&conf.cache_folder);

    fs::remove_file(&conf.outfile);
    fs::write(&(conf.logfile.clone() + ".log"), "").unwrap();
    fs::write(&(conf.logfile.clone() + ".error"), "").unwrap();
    // fs::write(&rp_log, "");

    let mut command = conf.binary_location.clone() + " ";
    command += &command_from_tuples(command_tuples, pre);
    command += " > ";
    if rp_name == "xyz"{
        //command += &conf.logfile.clone().split(".").collect::<Vec<&str>>()[0].to_string();
        command += &conf.outfile;
        //command += ".log";
    }
    else{
        command += &conf.logfile;
        command += ".log ";
    }

    command += " 2> ";
    command += &conf.logfile;
    command += ".error";
    //command += ".console ";

    if server {
        let child = Command::new("sh").arg("-c").arg(&command).spawn().expect("Failed to launch child");
        if rp_name == "rpki-client"{
            // d = fs::read_to_string(&(conf.outfile.clone() + "csv"));
        }

        return ("".to_string(), "".to_string(), Some(child));
    } else {
        let o = Command::new("sh").arg("-c").arg(&command).output().unwrap();
        let output = str::from_utf8(&o.stdout).unwrap();
        let d;
        if rp_name == "rpki-client"{
            fs::copy(&(conf.outfile.clone() + "csv"), &(conf.outfile.clone() + "vrps_client.txt"));
            // d = fs::read_to_string(&(conf.outfile.clone() + "csv"));
        }
        
        d = fs::read_to_string(&conf.outfile);
        
        let roa_data = match d {
            Ok(val) => val,
            Err(e) => e.to_string(),
        };
        return (roa_data, output.to_string(), None);
    }
}


pub fn run_update_routinator_both() -> (Vec<RoaContents>, String) {
    let cwd = test_util::get_cwd();

    // Routinator needs a path to the ssl key as the ssl certificate of our webserver is self-signed
    //let ssl_pem = repository::get_user_dir() + constants::SSL_KEY_WEBSERVER;
    let ssl_pem2 = cwd.clone() + "../repo2/certs/certbundle.pem";
    let ssl_pem = cwd.clone() + "/" + constants::SSL_KEY_WEBSERVER;

    let mut command = cwd.clone();
    let mut outfile = cwd.clone();
    let mut base = cwd.clone();
    let mut tals = cwd.clone();

    // Set necessary parameters to run routinator

    command += "/rp/bin/routinator ";

    outfile += "/rp/routinator/outputs/routinator.csv";

    base += "/rp/routinator/rpki-cache/";

    //tals += "/rp/routinator/rpki-cache/tals/";

    tals += "/";
    tals += constants::TAL_DIR;
    println!("{}", tals);

    let log_file = cwd.clone() + "/rp/routinator/outputs/log.log";
    let answer_dir = cwd.clone() + "/rp/routinator/rpki-cache/responses/";

    // Clear the log file
    fs::remove_file(&log_file);

    command += "-vv ";
    command += "--logfile=";
    command += log_file.clone().as_str();
    command += " ";
    command += "--rrdp-keep-responses=";
    command += &answer_dir;
    command += " ";
    command += "--disable-rsync ";
    command += "--rrdp-root-cert=";
    command += &ssl_pem;
    command += " ";

    command += "--rrdp-root-cert=";
    command += &ssl_pem2;
    command += " ";

    command += "-t ";
    command += tals.as_str();
    command += " ";
    command += "-b ";
    command += base.as_str();
    command += " ";
    command += "vrps";

    println!("{}", command);

    // This only works on Linux
    let o = Command::new("sh").arg("-c").arg(command).output().unwrap();

    let output = str::from_utf8(&o.stdout).unwrap();

    let csv_data = match fs::read_to_string(log_file) {
        Ok(val) => val,
        Err(e) => e.to_string(),
    };

    (parse_output_csv(&output), csv_data)
}

pub fn command_from_tuples(tuples: Vec<(&str, &str)>, pre: &str) -> String {
    // pre is the prefix of command flags for the CLI command, i.e. generally either " -" or " --"
    let mut command = "".to_string();
    for t in tuples {
        // Prefix escape
        if !t.0.starts_with("$") {
            command += pre;
            command += t.0;
        } else {
            command += " ";
            command += &t.0[1..]
        }

        if !t.1.is_empty() {
            if !t.1.starts_with("$") {
                command += "=";
                command += t.1;
            } else {
                command += " ";
                command += &t.1[1..];
            }
        }
    }
    command
}

pub fn run_update_routinator_p_server(conf: &RPConfig) -> Child {
    let command_tuples = vec![
        ("no-rir-tals", ""),
        ("allow-dubious-hosts", ""),
        ("disable-rsync", ""),
        ("verbose", ""),
        ("rrdp-root-cert", conf.ssl_cert.as_str()),
        ("extra-tals-dir", conf.tal_folder.as_str()),
        ("repository-dir", conf.cache_folder.as_str()),
        ("logfile", conf.logfile.as_str()),
        //("verbose", ""),
        //("$-vv", ""),
        ("$server", ""),
        ("refresh", "1"),
        ("http", "127.0.0.1:8888"),
    ];

    let (_, _, child) = run_rp_command(command_tuples, conf, " --", true, "routinator");

    child.unwrap()
}

pub fn run_update_routinator_p(conf: &RPConfig) -> (Vec<RoaContents>, String) {
    let command_tuples = vec![
        ("no-rir-tals", ""),
        ("allow-dubious-hosts", ""),
        ("disable-rsync", ""),
        ("rrdp-root-cert", conf.ssl_cert.as_str()),
        ("extra-tals-dir", conf.tal_folder.as_str()),
        ("repository-dir", conf.cache_folder.as_str()),
        //("logfile", &(conf.logfile.clone() + ".log")),
        ("$vrps", ""),
        ("output", conf.outfile.as_str()),
    ];

    let (data, output, _) = run_rp_command(command_tuples, conf, " --", false, "routinator");

    (parse_output_csv(&data), output)
}

pub fn run_update_routinator_p_non_blocking(conf: &RPConfig, log_level: &str) -> Child {
    let log_levels: HashMap<&str, &str> = HashMap::from([("none", "quiet"), ("error", "$"), ("info", "$-v"), ("debug", "$-vv")]);

    
    let command_tuples = vec![
        ("no-rir-tals", ""),
        ("allow-dubious-hosts", ""),
        ("disable-rsync", ""),
        ("rrdp-root-cert", conf.ssl_cert.as_str()),
        ("extra-tals-dir", conf.tal_folder.as_str()),
        ("repository-dir", conf.cache_folder.as_str()),
        //("$-vv",""),
        (log_levels[log_level], ""),
        //("logfile", &(conf.logfile.clone() + ".log")),
        ("$vrps", ""),
        ("output", conf.outfile.as_str()),
    ];

    let (_, _, child) = run_rp_command(command_tuples, conf, " --", true, "routinator");
    child.unwrap()
}

pub fn run_update_routinator() -> (Vec<RoaContents>, String) {
    let cwd = test_util::get_cwd();

    // Routinator needs a path to the ssl key as the ssl certificate of our webserver is self-signed
    let ssl_pem = repository::get_user_dir() + constants::SSL_KEY_WEBSERVER;

    let mut command = cwd.clone();
    let mut outfile = cwd.clone();
    let mut base = cwd.clone();
    let mut tals = cwd.clone();

    command += "/rp/bin/routinator ";

    outfile += "/rp/routinator/outputs/routinator.csv";

    base += "/rp/routinator/rpki-cache/";

    tals += "/";
    tals += "data/tals/";

    let logfile = cwd.clone() + "/rp/routinator/outputs/log.log";

    let conf = RPConfig {
        binary_location: command,
        outfile,
        logfile,
        ssl_cert: ssl_pem,
        tal_folder: tals,
        cache_folder: base,
    };
    run_update_routinator_p(&conf)
}

pub fn run_update_fort_p_server(conf: &RPConfig) -> Child {
    let command_tuples = vec![
        ("tal", conf.tal_folder.as_str()),
        ("validation-log.level", "error"),
        ("validation-log.enabled", "false"),
        ("mode", "server"),
        ("output.roa", conf.outfile.as_str()),
        ("local-repository", conf.cache_folder.as_str()),
        ("rsync.enabled", "false"),
        ("log.level", "info"),
        ("log.output", "console"),
        ("server.interval.validation", "1"),
    ];

    run_rp_command(command_tuples, conf, " --", true, "fort").2.unwrap()
}

pub fn run_update_fort_p(conf: &RPConfig) -> (Vec<RoaContents>, String) {
    let command_tuples = vec![
        ("tal", conf.tal_folder.as_str()),
        ("validation-log.level", "info"),
        ("validation-log.enabled", "true"),
        ("mode", "standalone"),
        ("output.roa", conf.outfile.as_str()),
        ("local-repository", conf.cache_folder.as_str()),
        ("rsync.enabled", "false"),
        ("log.output", "console"),
    ];

    let (data, output, _) = run_rp_command(command_tuples, conf, " --", false, "fort");

    (parse_output_csv(&data), output)
}

pub fn run_update_fort_p_non_blocking(conf: &RPConfig, log_level: &str) -> Child {
    let log_levels: HashMap<&str, &str> = HashMap::from([("none", "info"), ("error", "error"), ("info", "info"), ("debug", "debug")]);
    let mut log_enabled = "true";
    if log_level == "none"{
        log_enabled = "false";
    }

    let command_tuples = vec![
        ("tal", conf.tal_folder.as_str()),
        ("validation-log.level", log_levels[log_level]),
        ("validation-log.enabled", log_enabled),
        ("mode", "standalone"),
        ("output.roa", conf.outfile.as_str()),
        ("local-repository", conf.cache_folder.as_str()),
        ("rsync.enabled", "false"),
        ("log.output", "console"),
    ];

    let (_, _, child) = run_rp_command(command_tuples, conf, " --", true, "fort");

    child.unwrap()
}

pub fn run_update_fort() -> (Vec<RoaContents>, String) {
    let cwd = test_util::get_cwd();

    let ssl_pem = repository::get_user_dir() + constants::SSL_KEY_WEBSERVER;

    let mut command = cwd.clone();
    let mut outfile = cwd.clone();
    let mut base = cwd.clone();
    let mut tals = cwd.clone();

    command += "/rp/bin/fort ";

    outfile += "/rp/fort/outputs/fort.csv";

    base += "/rp/fort/rpki-cache/";

    tals += "/";
    tals += "data/tals/ta.tal";

    let logfile = cwd.clone() + "/rp/fort/outputs/log.log";

    let conf = RPConfig {
        binary_location: command,
        outfile,
        logfile,
        ssl_cert: ssl_pem,
        tal_folder: tals,
        cache_folder: base,
    };

    run_update_fort_p(&conf)
}

pub fn run_update_rpki_client_p_server(conf: &RPConfig) -> Child {
    // Need bindings to correct for lifetime problems
    let binding = "$".to_string() + conf.tal_folder.as_str();
    let binding2 = "$".to_string() + conf.cache_folder.as_str();
    let binding3 = "$".to_string() + conf.outfile.as_str();

    let command_tuples = vec![
        ("t ", binding.as_str()),
        ("r", ""),
        ("c", ""),
        ("d", binding2.as_str()),
        ("j", binding3.as_str()),
    ];
    let rp_log = "./output/rp_rpki-client.log.console";

    fs::remove_file(rp_log);
    let (_, _, child) = run_rp_command(command_tuples, conf, " -", true, "rpki-client");

    child.unwrap()
}

pub fn run_update_rpki_client_p(conf: &RPConfig) -> (Vec<RoaContents>, String) {
    let binding = "$".to_string() + conf.tal_folder.as_str();
    let binding2 = "$".to_string() + conf.cache_folder.as_str();
    let binding3 = "$".to_string() + conf.outfile.as_str();

    let command_tuples = vec![
        ("t ", binding.as_str()),
        ("r", ""),
        ("c", ""),
        ("d", binding2.as_str()),
        ("j", binding3.as_str()),
    ];

    let (data, output, _) = run_rp_command(command_tuples, conf, " -", false, "rpki-client");

    (parse_output_csv(&data), output)
}

pub fn run_update_rpki_client_p_non_blocking(conf: &RPConfig, log_level: &str) -> Child {
    let binding = "$".to_string() + conf.tal_folder.as_str();
    let binding2 = "$".to_string() + conf.cache_folder.as_str();
    let binding3 = "$".to_string() + conf.outfile.as_str();

   
    let mut command_tuples = vec![
        ("t ", binding.as_str()),
        ("r", ""),
        ("c", ""),
        ("d", binding2.as_str()),
        ("j", binding3.as_str()),
    ];

    if log_level == "warning" || log_level == "debug"{
        command_tuples.push(("v", ""));
    }



    let (_, _, child) = run_rp_command(command_tuples, conf, " -", true, "rpki-client");

    child.unwrap()
}

pub fn run_update_rpki_client() -> (Vec<RoaContents>, String) {
    let cwd = test_util::get_cwd();
    let mut command = cwd.clone();
    let mut outfile = cwd.clone();
    let mut base = cwd.clone();
    let mut tals = cwd.clone();

    let log_file = cwd.clone() + "/rp/rpki/outputs/log.log";

    outfile += "/rp/rpki/outputs/";

    base += "/rp/rpki/cache/";

    tals += "/";
    tals += constants::TAL_DIR;
    tals += "ta.tal";

    command += "/rp/bin/rpki-client";

    let conf = RPConfig {
        binary_location: command,
        outfile,
        logfile: "".to_string(),
        ssl_cert: "".to_string(),
        tal_folder: tals,
        cache_folder: base,
    };

    run_update_rpki_client_p(&conf)
}



pub fn run_update_octorpki_p_server(conf: &RPConfig) -> Child {
    let command_tuples = vec![
        ("tal.root", conf.tal_folder.as_str()),
        ("-tal.name", "ta"),
        ("mode", "server"),
        ("loglevel", "fatal"),
        ("output.roa", conf.outfile.as_str()),
        ("output.sign", "false"),
        ("refresh", "0m1s"),
        ("cache", conf.cache_folder.as_str()),
        ("-http.addr", "127.0.0.1:8887"),
    ];

    let (_, _, child) = run_rp_command(command_tuples, conf, " -", true, "octorpki");

    child.unwrap()
}

pub fn run_update_octorpki_p(conf: &RPConfig) -> (Vec<RoaContents>, String) {
    let command_tuples = vec![
        ("tal.root", conf.tal_folder.as_str()),
        ("-tal.name", "ta"),
        ("mode", "oneoff"),
        ("loglevel", "info"),
        ("output.roa", conf.outfile.as_str()),
        ("output.sign", "false"),
        ("cache", conf.cache_folder.as_str()),
    ];

    let (data, output, _) = run_rp_command(command_tuples, conf, " -", false, "octorpki");
    (parse_output_json(&data), output)
}

pub fn run_update_octorpki_p_non_blocking(conf: &RPConfig, log_level: &str) -> Child {
    let log_levels: HashMap<&str, &str> = HashMap::from([("none", "off"), ("error", "error"), ("info", "info"), ("debug", "debug")]);

    let command_tuples = vec![
        ("tal.root", conf.tal_folder.as_str()),
        ("-tal.name", "ta"),
        ("mode", "oneoff"),
        ("loglevel", log_levels[log_level]),
        ("output.roa", conf.outfile.as_str()),
        ("output.sign", "false"),
        ("cache", conf.cache_folder.as_str()),
    ];

    let (_, _, child) = run_rp_command(command_tuples, conf, " -", true, "octorpki");
    child.unwrap()
}

pub fn run_update_octorpki() -> (Vec<RoaContents>, String) {
    let cwd = test_util::get_cwd();
    let mut command = cwd.clone();
    let mut outfile = cwd.clone();
    let mut base = cwd.clone();
    let mut tals = cwd.clone();

    outfile += "/rp/octorpki/outputs/";

    outfile += "octo.csv";

    base += "/rp/octorpki/base/";
    tals += "/";
    tals += constants::TAL_DIR;
    tals += "ta.tal";

    command += "/rp/bin/octorpki";

    let conf = RPConfig {
        binary_location: command,
        outfile,
        logfile: "".to_string(),
        ssl_cert: "".to_string(),
        tal_folder: tals,
        cache_folder: base,
    };

    run_update_octorpki_p(&conf)
}

pub fn parse_output_csv(csv_data: &str) -> Vec<RoaContents> {
    //let file_content = fs::read(file_uri).unwrap();
    let mut result = csv::ReaderBuilder::new().from_reader(csv_data.as_bytes());

    let mut roa_contents = vec![];
    for record_w in result.records() {
        let record = record_w.unwrap();
        let as_id = record[0].to_string();
        let ip = record[1].to_string();
        //Slet ca = record[3].to_string();

        let (i, p) = ip.split_once("/").unwrap();
        let prefix = p.trim().parse::<u8>().unwrap();

        let ip_addr;
        if i.contains("."){
            ip_addr = IpAddr::from(Ipv4Addr::from_str(&i).unwrap());
            
        }
        else{
            ip_addr = IpAddr::from(Ipv6Addr::from_str(&i).unwrap());
        }
        let aid_tmp = Asn::from_str(&as_id);
        if aid_tmp.is_err() {
            continue;
        }
        let as_id = Asn::from_str(&as_id).unwrap();
        let roa_content = RoaContents { ip_addr, prefix, as_id };
        roa_contents.push(roa_content);
    }
    roa_contents
}

pub fn parse_output_json(json_data: &str) -> Vec<RoaContents> {
    if json_data == "" {
        return vec![];
    }
    let js: Value = serde_json::from_str(json_data).unwrap();
    let a = &js["roas"];
    let b = a.as_array().unwrap();
    let mut roa_contents = vec![];

    for roa in b {
        // Remove quote signes
        let ip_r = roa["prefix"].to_string();
        let ip = ip_r[1..ip_r.len() - 1].to_string();
        let asn_r = roa["asn"].to_string();
        let asn = asn_r[1..asn_r.len() - 1].to_string();

        let (i, p) = ip.split_once("/").unwrap();
        let prefix = p.trim().parse::<u8>().unwrap();

        // let mut ip_vec = vec![];
        let ip_addr;
        if i.contains("."){
            ip_addr = IpAddr::from(Ipv4Addr::from_str(&i).unwrap());
            
        }
        else{
            ip_addr = IpAddr::from(Ipv6Addr::from_str(&i).unwrap());
        }
        let aid_tmp = Asn::from_str(&asn);
        if aid_tmp.is_err() {
            continue;
        }
        let as_id = Asn::from_str(&asn).unwrap();
        let roa_content = RoaContents { ip_addr, prefix, as_id };
        roa_contents.push(roa_content);
        
    }
    roa_contents
}

pub fn roas_contain_announcment(roas: Vec<RoaContents>, ip: Ipv4Addr, prefix: u8, asn: u32) -> bool {
    for roa in roas {
        if roa.as_id.into_u32() == asn && ip == roa.ip_addr && roa.prefix == prefix {
            return true;
        }
    }
    return false;
}
#[derive(PartialEq)]
pub struct RoaContents {
    pub ip_addr: IpAddr,
    pub prefix: u8,
    pub as_id: Asn,
}
