use bytes::Bytes;

use crate::{consts, publication_point::repository, util};

pub fn create_normal_repo() {
    let mut con = repository::create_default_config(consts::domain.to_string());
    repository::initialize_repo(&mut con, false, None);
    println!("Got here");

    for i in 0..10 {
        let roa_string = con.DEFAULT_IPSPACE_FIRST_OCTET.to_string()
            + "."
            + &con.DEFAULT_IPSPACE_SEC_OCTET.to_string()
            + &".0.0/24 => ".to_string()
            + &i.to_string();
        repository::add_roa_str(&roa_string, true, &con);
    }
}

pub fn test_run() -> bool {
    println!("Info: Running Testrun to check if RPs work correctly...");

    println!("Got here");

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

    println!("Info: Testrun sucesful");
    util::clear_caches();

    fault
}

pub fn initialize_fuzzer() -> bool {
    util::clear_caches();
    let err = test_run();

    return err;
}

#[derive(PartialEq)]
pub enum OpType {
    MFT,
    ROA,
    CRL,
    CERTCA,
    CERTEE,
    SNAP,
    NOTI,
    ASPA,
    GBR,
}
