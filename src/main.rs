use bcder::Mode;
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use hex::ToHex;
use openssl::pkey::PKey;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use result_processing::run_rp;
use rpki::repository::crypto::softsigner::OpenSslSigner;
use rpki::repository::resources::{Addr, IpBlock, Prefix, self};
use rpki::repository::sigobj::SignedObjectBuilder;
use rpki::repository::x509::Validity;
use rpki::rrdp::Hash;
use rpki::uri;
use rpki_testing::repository::RepoConfig;
use rpki_testing::{self, fuzzing_interface, repository};
mod result_processing;
mod util;
use core::panic;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::{env, vec, thread};
use std::fs;
use std::process::Child;

use crate::vrps_analysis::find_affected_entries;

mod crl;
mod mft;
mod cert;
mod notification;
mod roa;
mod snapshot;
mod asn1p;
mod consts;
mod vrps_analysis;

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

fn start_rps() -> (Vec<Child>, Vec<String>) {
    let mut children = vec![];
    let mut rp_names = vec![];

    let conf = util::create_routinator_config();
    let mut child = fuzzing_interface::run_rp_server("routinator", &conf);
    println!("Info: Started Routinator");

    children.push(child);
    rp_names.push("routinator".to_string());

    let conf = util::create_fort_config();
    let mut child = fuzzing_interface::run_rp_server("fort", &conf);
    println!("Info: Started Fort");

    children.push(child);
    rp_names.push("fort".to_string());

    let conf = util::create_octorpki_config();
    let child = fuzzing_interface::run_rp_server("octorpki", &conf);
    println!("Info: Started Octorpki");

    children.push(child);
    rp_names.push("octorpki".to_string());

    // let conf = util::create_client_config();
    // let mut child = fuzzing_interface::run_rp_server("rpki-client", &conf);
    // children.push(child);
    // rp_names.push("rpki-client".to_string());
    println!("Info: RPKI Client is executed every Iteration");

    return (children, rp_names);
}


fn create_normal_repo(){
    let mut con = repository::create_default_config(consts::domain.to_string());
    repository::initialize_repo(&mut con, false, None);
    for i in 0..10{
        let roa_string = con.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." + &con.DEFAULT_IPSPACE_SEC_OCTET.to_string() + &".0.0/24 => ".to_string() + &i.to_string();
        repository::add_roa_str(&roa_string, true, &con);

    }

    // let roa_string = con.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." + &con.DEFAULT_IPSPACE_SEC_OCTET.to_string() + &".0.0/24 => ".to_string() + &11.to_string();
    // repository::add_roa_str(&roa_string, true, &con);


    // let roa_string = con.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." + &con.DEFAULT_IPSPACE_SEC_OCTET.to_string() + &".0.0/24 => ".to_string() + &11.to_string();
    // repository::add_roa_str(&roa_string, true, &con);

}


fn test_run() -> bool{
    println!("Info: Running Testrun to check if RPs work correctly...");

    create_normal_repo();
    util::run_rp_processes("info");
    let mut con = repository::create_default_config(consts::domain.to_string());

    let v = vec!["Routinator", "OctoRPKI", "Fort", "RPKI-Client"];

    let (vrps, _, _, cont) = util::get_rp_vrps();
    let mut fault = false;
    for i in 0..cont.len(){
        if cont[i].len() != 10{
            println!("!--> Error in Testrun. {} doesnt seem to work correctly!!", v[i]);
            fault = true;
        }
    }
    if fault{
        println!("Debug Info VRPS:\n {:}", vrps);
    }
    else{
        //util::clear_repo(&con, 0);
    }
    if fault{
        println!("!--> Error in Testrun. Fix RPs before running fuzzer!!");
        println!("Maybe webserver points to wrong location or permission problems on a cache folder?");    
    }

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


pub fn typ_to_name(typ: &str) -> String{
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

pub fn store_example_roa(){
    let mut conf = repository::create_default_config("my.server.com".to_string());
    // let (cert_keys, new_conf) = util::create_cas(10000, vec![&conf], None);
    // conf.CA_TREE = new_conf.CA_TREE.clone();
    let cws = util::get_cwd() + "/";

    let roas = util::create_example_roas(&vec![], 10000, &conf);    

    fs::create_dir_all(cws.clone() + "roas_4/").unwrap();

    for i in roas{
        let con = asn1p::extract_e_content(i.0, Some("roa")).unwrap();
        let name: String = thread_rng().sample_iter(&Alphanumeric).take(14).map(char::from).collect();    
        fs::write(cws.clone() + "roas_4/" + &name, con).unwrap();
    }
}



fn min_to_prefix(addr: Addr) -> Prefix {
    Prefix::new(addr, 128 - addr.to_bits().trailing_zeros() as u8)
}

/// Calculates the prefix for the maximum address.
///
/// This is a prefix with all trailing ones dropped.
fn max_to_prefix(addr: Addr) -> Prefix {
    Prefix::new(addr, 128 - addr.to_bits().trailing_zeros() as u8)
}

fn min_ex(){
    let ip1 = "10.1.1.0";
    let ip2 = "11.1.1.0";

    let a = Addr::from_v4_str(ip1).unwrap();
    let b = Addr::from_v4_str(ip2).unwrap();

    let t = min_to_prefix(a);
    let t2 = max_to_prefix(b);

    let e = t.encode();
    let e2 = t2.encode();
    
    println!("t1 {:?} t2 {:?}", t, t2);

    println!("t1 {:?} t2 {:?}", e.to_captured(Mode::Der).into_bytes(), e2.to_captured(Mode::Der).into_bytes());

    // let block = IpBlock::from((a, b));

    // let uri = uri::Rsync::from_string("rsync://my.server.com/la/li/lu.file".to_string()).unwrap();
    // let mut builder = SignedObjectBuilder::new(
    //     repository::random_serial(),
    //     Validity::from_secs(286400),
    //     uri.clone(),
    //     uri.clone(),
    //     uri.clone(),
    // );

    // builder.build_v4_resource_blocks(|b| {
    //     b.push(block);
    // });
    // builder.finalize(content_type, content, signer, issuer_key)
}







fn main() {
    vrps_analysis::as_anal3();
    return;
    // vrps_analysis::find_dif_roas(None);
    // return;
    // let a = "/home/nvogel/Schreibtisch/vanilla_rps/FORT-validator/cache/AA139903/rpkica.twnic.tw/rpki/TWNICCA/HINET/U0x2J0ozCwce_SDbBfbQQpKTdD4.mft";
    // println!("a: {}", a.contains("/U0x2J0ozCwce_SDbBfbQQpKTdD4"));
    // return;
    // vrps_analysis::find_object_differences("roa");

    // return;
    // vrps_analyi.
    // test_run();
    // return;
    // let b = fs::read("./data/my.server.com/repo/newca/31302e302e302e302f3234203d3e2030.roa").unwrap();
    // asn1::parse_single::<asn1p::ContentInfo>(&b).unwrap();
    // println!("Parsing worked");
    // // t
    // return;
    // vrps_analysis::log_folders();
    // return;
    // vrps_analysis::indepth_analysis();
    // return;
    // min_ex();
    // return;
    // vrps_analysis::log_folders();
    // return;


    // let folder_uri = "/home/nvogel/Schreibtisch/testi/data/my.server.com/repo/newca/";
    // let folder_uri = "/home/nvogel/Schreibtisch/vanilla_rps/routinator/dump/store/rrdp.ripe.net/rpki.ripe.net/repository/DEFAULT/23/d1fd48-916b-4d83-96cc-c910af93e426/1/";

    // vrps_analysis::handle_folder(folder_uri);

    // let re = util::run_rp_processes("error");

    // let (vrps, _, _, roas) = util::get_rp_vrps();
    // println!("{}", vrps);

    // return;


    // let mut conf = repository::create_default_config(consts::domain.to_string());
    // repository::initialize_repo(&mut conf, false, None);
    // let (roa, roa_string) = repository::create_random_roa(&conf);

    // let mut file_uri = "rsync://".to_string() + &conf.DOMAIN +  "/" + &conf.BASE_REPO_DIR + "newca/";
    // file_uri += &repository::file_name_for_object(&roa_string, ".roa");

    // let ret = vrps_analysis::handle_signed_object(&roa, &file_uri, &conf);
    // repository::write_object_to_disc(&Bytes::from(ret.clone()), "roa", &roa_string, "newca", &conf);
    // let roa_base_uri = repository::base_repo_uri(&conf.CA_NAME, &conf);
    // repository::after_roa_creation(&roa_string, roa_base_uri, "newca", Bytes::from(ret.clone()), false, &conf);
    // repository::add_random_roa(&conf);


    // println!("ret: {:?}", base64::encode(ret));


    // vrps_analysis::handle_folder("/home/nvogel/git/rpki-fuzzing/data/my.server.com/repo/newca/");
    // println!("{}", get_issuer_cert_uri());
    // load_mft();
    // return;
    // vrps_analysis::find_dif_roas();
    // return;
    // test_run();
    // return;

    let ss = vrps_analysis::analyse_vrps(false).0;
 
    // for i in ss[0].iter(){
    //     println!("{}", i);
    //     break;
    // }

    util::clear_caches();
    let a: Vec<String> = env::args().collect();
    if a.len() == 1{
        println!("Thiw");
        // let mut conf = repository::create_default_config(consts::domain.to_string());
    
        let mut conf = vrps_analysis::example_bs();
        repository::initialize_repo(&mut conf, false, None);
        repository::add_roa_str("1.1.1.0/24 => 1",true, &conf);
        repository::add_roa_str("1.1.3.0/24 => 2",true, &conf);
    
        let re = util::run_rp_processes("error");

        let (vrps, _, _, roas) = util::get_rp_vrps();
        println!("{}", vrps);
        return;

        let start = std::time::Instant::now();
        roa::do_both("/home/nvogel/git/rpki-fuzzing/roas_4/", false, "roa", &conf);
    
        let end = start.elapsed();
        println!("Elapsed time is {}", end.as_millis());
        return;
    }
  
    // Processing results
    let typ;
    let mode;
    let uri;
    let mut additional_info = vec![];
    let a: Vec<String> = env::args().collect();
    // let a = vec!["a".to_string(), "vrps".to_string(), "roa".to_string(), "inv".to_string(), "no_ee".to_string()];

    let valid_types = vec!["roa", "mft", "crl", "cert", "gbr", "aspa", "snapshot", "notification"];


    if a.len() > 1{
        if a[1] == "processor"{
            mode = OpMode::Processor;
        }
        else if a[1] == "gen"{
            mode = OpMode::Generation;
        }
        else if a[1] == "fuzz"{
            mode = OpMode::Fuzzer;
        }
        else if a[1] == "run"{
            mode = OpMode::Runner;
        }
        else if a[1] == "vrps"{
            mode = OpMode::Vrps;
        }
        else{
            panic!("Invalid arguments! Use 'fuzz' to run the fuzzer, 'gen' to generate objects, 'processor' to process results or 'run' for a single run");
        }
    }
    else{
        panic!("Invalid arguments! Use 'fuzz' to run the fuzzer, 'gen' to generate objects, 'processor' to process results or 'run' for a single run");
    }


    if a.len() > 2 && valid_types.contains(&a[2].as_str()){
        typ = a[2].clone();
    }
    else{
        panic!("Invalid arguments! Please provide a Type (roa, mft, crl, cert, gbr, aspa, snapshot, notification)");
    }


    if mode != OpMode::Fuzzer{
        if a.len() > 3{
            uri = a[3].clone();
        }
        else{
            panic!("Invalid arguments! Please provide a URI to a File or Folder");
        }
    }
    else{
        uri = "".to_string();
    }


    // Some modes need additional info
    for i in 4..a.len(){
        if a.len() > i{
            additional_info.push(a[i].clone());
        }
    }

    create_folders();

    if mode == OpMode::Processor{
        println!("\n\n--- RPKI Result Processor ---\n");

        println!("Info: Processing Results");
        println!("This might take a few minutes...");

        result_processing::process_results(&uri, &typ);
        return;
    }
    else if mode == OpMode::Vrps{
        let ty;
        if additional_info.len() == 0{
            panic!("Invalid arguments! Please provide information on what to look at (folder, file, cache)");
        }
        else{
            ty = additional_info[0].clone();
        }

        let base_routinator = "/home/nvogel/Schreibtisch/vanilla_rps/routinator/dump/stored/";
        let base_fort = "/home/nvogel/Schreibtisch/vanilla_rps/FORT-validator/cache/";
        let base_client = "/home/nvogel/Schreibtisch/vanilla_rps/rpki-client-portable/cache/";
        let base_octo = "/home/nvogel/Schreibtisch/vanilla_rps/cfrpki/cmd/octorpki/cache/";
        let bases = vec![base_routinator, base_octo, base_fort, base_client];

        let mut report = "--- Inconsistency Report ---\n\n".to_string();

        if ty == "raw_folder"{
            let paths = fs::read_dir(&uri).unwrap();

            let tmp_folder = get_cwd() + "/tmp/";
    
            for path_t in paths{
                let p = path_t.unwrap();
                report += "<Inconsistency>\n";
                report += "Filename: " ;
                report += p.file_name().to_str().unwrap();
                report += "\n";
                let tmp = p.path();
                let path_pre = tmp.as_os_str().to_string_lossy();
                let newpath = tmp_folder.clone() + p.file_name().to_str().unwrap();
                let con = fs::read(&*path_pre).unwrap();
    
                let o = vrps_analysis::get_content_ips(Bytes::from(con.clone()));
                let mut conf = repository::create_default_config("my.server.com".to_string());
    
                conf.IPBlocks.extend(o);
                // conf.IPv4.extend(o1);
                // conf.IPv6.extend(o2);
    
                repository::initialize_repo(&mut conf, false, None);
    
                if typ == "mft" || typ == "roa" || typ == "gbr" || typ == "aspa"{
    
                    let newcon = vrps_analysis::fix_econtent(Bytes::from(con), &conf);
                    fs::write(&newpath, newcon).unwrap();
                }
                else{
                    fs::write(&newpath, con).unwrap();
                }
    
    
                let path = newpath;
    
                if typ == "mft"{
                    mft::do_both(&path, true, &conf);
                }
                else if typ == "crl"{
                    crl::do_both(&path, &mut conf);
                }
                else if typ == "roa" {
                    roa::do_both(&path, true, "roa", &conf);
                }
                else if typ == "gbr"{
                    roa::do_both(&path, true, "gbr", &conf);
                }
                else if typ == "aspa"{
                    roa::do_both(&path, true, "aspa", &conf);
                }
                else if typ == "cert"{
                    cert::do_both(&path, &conf);
                }
                else{
                    panic!("Unknown object type!");
                }
                let re = util::run_rp_processes("error");
                for r in re{
                    if r.1{
                        println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
                    }
                }
                let (vrps, _, _, roas) = util::get_rp_vrps();
                report += "<VRPS>\n";
                report += &vrps;
                report += "<Object>\n";
                report += &base64::encode(fs::read(&*path).unwrap()).to_string();           
                report += "\n\n";
    
                let rp_names = vec!["routinator", "octorpki", "fort", "client"];
                for n in rp_names{
                    let l = util::read_rp_log(n);
                    report += &("<".to_string() + n + " log>\n");
                    report += &l;
                    report += "\n\n";
    
                }
                println!("{}", report);
                return;
            }
        }
        else if ty == "folder"{
            let mut report = "".to_string();
            util::clear_caches();
            report += "<Inconsistency>\n";
            report += "Folder: " ;
            report += &uri;
            report += "\n";

            let err = vrps_analysis::handle_folder(&uri); 
            if err{
                println!("Error in parsing MFT, following RPs miss the ROAs");
                
                report += "Error while processing folder!";
            }
            else{
                report += "No inconsistencies found!";
            }
            
            let re = util::run_rp_processes("error");
            for r in re{
                if r.1{
                    println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
                }
            }
            let (vrps, diffr, _, roas) = util::get_rp_vrps();
            if diffr{
                let (dif, ssets) = vrps_analysis::analyse_vrps(true);
                let mut sw = 0;
                for i in 0..ssets.len(){
                    let rpv = &ssets[i];
                    for v in rpv{
                        if ss[i].contains(v){
                            println!("{} Switched validity {}", i, v);
                            sw += 1;
                        }
                    }
                }
                if sw == roas[0].len(){
                    report += "All ROAs switched Validity -> Likely something wrong with parent!";
                }
                report += &format!("No inconsistencies found! {}\n\n", roas[0].len().to_string());

            }
            else{
                let rp_names = vec!["routinator", "octorpki", "fort", "client"];


                report += "<Differences>\n";
                for i in 0..rp_names.len(){
                    continue;
                    // let d = dif[i].clone().into_iter().map(|x| x.to_string()).collect::<Vec<String>>().join("\n");
                    // report += &("<Missing from ".to_string() + rp_names[i] + ">\n");
                    // report += &d;
                    // report += "\n\n";
                }

                let d = vrps_analysis::find_dif_roas(Some(vec![&(util::get_cwd().clone() + "/data/my.server.com/repo/newca/")]));
                report += "<Detailed Info>\n";
                if d.len() > 5 {
                    report += "Too many differences to show!\n\n";
                }
                else{
                    for di in d{
                        continue;
                        report += "Entry: ";
                        report += &di.0;
                        report += "\n";
                        report += "Object: ";
                        let obj_enc = base64::encode(fs::read(&di.1).unwrap());
                        report += &obj_enc;
                        report += "\n\n";
                    }
                } 

                let mut ind = 0;
                for n in rp_names{
                    let l = util::read_rp_log(n);
                    report += &("<".to_string() + n + " log> (Length: " +  &roas[ind].len().to_string() + ")\n");
                    report += &l;
                    report += "\n\n";
                    ind += 1;
                }
            }

            

            println!("Report: {}", report);

        }
        else if ty == "cache"{
            let folders = fs::read_to_string(&uri).unwrap();
            let mut skipped_once = true;
            let mut cu = 0;

            let mut miss_from_rps = vec![0, 0, 0, 0];

            let mut total_subnet = 0;
            let mut total_prefix = 0;

            println!("total amount {}", folders.split("\n").collect::<Vec<&str>>().len());
            for f in folders.split("\n"){
                util::clear_caches();
                if  f.contains("amazon"){
                    continue;
                }
                cu += 1;
                println!("CU {}", cu);
                if cu < 0{
                    continue;
                }
                if cu == 0{
                    break;
                }
                if f.is_empty(){
                    continue;
                }
                if !skipped_once{
                    skipped_once = true;
                    continue;
                }

              
                let err = vrps_analysis::handle_folder(&f); 

                if err{
                    report += &format!("Error while processing folder {}!\n\n", &f);
                    continue;
                }
                
                              
                let re = util::run_rp_processes("error");
                for r in re{
                    if r.1{
                        println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
                    }
                }
                let (vrps, diffr, _, roas) = util::get_rp_vrps();


                if diffr{
                    let (dif, ssets) = vrps_analysis::analyse_vrps(true);
                    let mut sw = 0;
                    for i in 0..ssets.len(){
                        let rpv = &ssets[i];
                        for v in rpv{
                            if ss[i].contains(v){
                                // println!("{} Switched validity {}", i, v);
                                sw += 1;
                            }
                        }
                    }
                    // if sw == roas[0].len(){
                    report += format!("{} / {} ROAs switched Validity -> Likely something wrong with parent!", sw, roas[0].len()).as_str();
                    let (tu, nu) = vrps_analysis::check_mft_validity(&f);
                    report += &format!("Manifest validity {:?} - {:?}", tu, nu);

                    // let ct = chrono::Utc::now();

                        // if ct > nu.as_chrono().to_owned() || ct < tu.as_chrono().to_owned(){
                        //     report += &format!("Manifest validity {:?} - {:?}", tu, nu);
                        //     println!("Manifest not valid");
                        // }
                        
                    // }

                    report += &format!("No inconsistencies found! Roa length: {}, Folder: {}\n\n", roas[0].len().to_string(), &f);
                    continue;
                }

                let oo = vrps_analysis::check_only_octo(&roas);
                total_subnet += oo.0;
                total_prefix += oo.1;
                if (oo.0 != 0 || oo.1 != 0) && roas[0].len() == roas[1].len() + (oo.0 + oo.1) as usize{
                    report += &format!("All inconsistencies are Octo Optimizations! {}\n\n", oo.0 + oo.1);
                    continue;
                }
                else{
                    println!("no octo opti {:?}", oo);
                }

                let maxi_rp = roas.iter().map(|x| x.len()).max().unwrap();
                let highest_rp = roas.iter().position(|x| x.len() == maxi_rp).unwrap();
                let base = bases[highest_rp];

                for i in 0..roas.len(){
                    if roas[i].len() == 0{
                        let miss = find_affected_entries(&f, base);
                        miss_from_rps[i] += miss;
                    }
                }



                report += "<Inconsistency>\n";
                report += "Folder: " ;
                report += &f;
                report += "\n";
 
                // report += "<VRPS>\n";
                // report += &vrps;
                let rp_names = vec!["routinator", "octorpki", "fort", "client"];

                report += "<Differences>\n";
                for i in 0..rp_names.len(){
                    continue;
                    // let d = dif[i].clone().into_iter().map(|x| x.to_string()).collect::<Vec<String>>().join("\n");
                    // report += &("<Missing from ".to_string() + rp_names[i] + ">\n");
                    // report += &d;
                    // report += "\n\n";
                }

                let d = vrps_analysis::find_dif_roas(Some(vec![&(util::get_cwd().clone() + "/data/my.server.com/repo/newca/")]));
                report += "<Detailed Info>\n";
                if d.len() > 5 {
                    report += "Too many differences to show!\n\n";
                }
                else{
                    for di in d{
                        continue;
                        report += "Entry: ";
                        report += &di.0;
                        report += "\n";
                        report += "Object: ";
                        let obj_enc = base64::encode(fs::read(&di.1).unwrap());
                        report += &obj_enc;
                        report += "\n\n";
                    }
                } 

                let mut ind = 0;
                for n in rp_names{
                    let l = util::read_rp_log(n);
                    report += &("<".to_string() + n + " log> (Length: " +  &roas[ind].len().to_string() + ")\n");
                    report += &l;
                    report += "\n\n";
                    ind += 1;
                }
                println!("Finished Folder {}", cu);

                
            }

            report += "<Missing from RPs>\n";
            report += &miss_from_rps.iter().map(|x| x.to_string()).collect::<Vec<String>>().join("\n");
            println!("Report: {}", report);
            println!("Total subnet: {}, prefix: {}", total_subnet, total_prefix);

        }
    
    }   
    else if mode == OpMode::Runner{
        println!("\n--- RPKI Relying Party Standalone Fuzzer ---\n");

        let re = test_run();
        if re {
            return;
        }

        let mut no_ee = false;
        if additional_info.len() > 0 && additional_info[0] == "no_ee"{
            no_ee = true;
        }

        let mut conf = repository::create_default_config(consts::domain.to_string());
        let ad = Ipv4Addr::new(219, 235, 128, 0);
        let pre = resources::Prefix::new(ad, 21);
        let bl = IpBlock::from(pre);

        let cont = fs::read(&uri).unwrap();
        let con_ips = vrps_analysis::get_content_ips(Bytes::from(cont));
        conf.IPBlocks.extend(con_ips);

        repository::initialize_repo(&mut conf, false, None);
    
    
        if typ == "mft"{
            mft::do_both(&uri, no_ee, &conf);
        }
        else if typ == "crl"{
            crl::do_both(&uri, &mut conf);
        }
        else if typ == "roa" {
            roa::do_both(&uri, no_ee, "roa", &conf);
        }
        else if typ == "gbr"{
            roa::do_both(&uri, no_ee, "gbr", &conf);
        }
        else if typ == "aspa"{
            roa::do_both(&uri, no_ee, "aspa", &conf);
        }
        else if typ == "cert"{
            cert::do_both(&uri, &conf);
        }
        else{
            panic!("Unknown object type!");
            }
    
        println!("Info: Finished creating all objects in data/repo/ folder");
        println!("Info: Running RPs");
        let re = util::run_rp_processes("info");
        for r in re{
            if r.1{
                println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
            }
        }
        let rp_names = vec!["Routinator", "OctoRPKI", "Fort", "RPKI-Client"];
        let (vrps, _, _, roas) = util::get_rp_vrps();
        let mut fault_occured = false;
        for i in 0..roas.len(){
            let r = &roas[i];
            let mut two_in = false;
    
            for v in r{
                if v.as_id.into_u32() == 22222{
                    two_in = true;
                }
            }
            if !(two_in){
                println!("Warning: {} did not accept test ROA ASN22222", rp_names[i]);
                fault_occured = true;
            }
        }
        println!("");
        if !fault_occured{
            println!("Info: All RPs accepted both test ROAs");
        }
        println!("Info: RPs finished, Logs written to output/\n");
        println!("<VRPS>\n{}", vrps);
        return;
    }

    else if mode == OpMode::Generation{
        let amount;
        if additional_info.len() > 0{
            amount = additional_info[0].parse::<u16>().unwrap();
        }
        else{
            amount = 20;
        }
        let dont_move;
        if additional_info.len() > 1{
            dont_move = additional_info[1].parse::<bool>().unwrap();
        }
        else{
            dont_move = true;
        }

        if dont_move{
            println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
        }

        let conf = repository::create_default_config(consts::domain.to_string());
        if typ == "mft" {
            mft::create_objects(uri, amount, dont_move, false, 4000, false);
        } else if typ == "crl"{
            crl::create_objects(uri, amount, dont_move, false, 4000);
        }else if typ == "roa" || typ == "aspa" || typ == "gbr"{
            // TODO change this back
            roa::create_objects(uri, amount, dont_move, false, 10000, false, &typ, &conf);
        }
        else if typ == "cert"{
            cert::create_objects(uri, amount, dont_move, false, 10000);
        }
        else{
            panic!("Unknown object type generator!");
        }
        std::process::exit(0);
    }

    else if mode == OpMode::Fuzzer{
        println!("\n--- RPKI Relying Party Fuzzer ---\n");
        println!("Info: Object Type: {}", typ_to_name(&typ));

        let re = test_run();
        if re {
            return;
        }

        let folders = match additional_info.len() > 0{
            true => {
                let mut ret = vec![];
                for i in additional_info{
                    ret.push(i);
                }
                Some(ret)
            },
            false => None
        };

        println!("Info: Creating Folders");

        let mut con = repository::create_default_config(consts::domain.to_string());
        repository::initialize_repo(&mut con, false, None);
        let cws = get_cwd() + "/";
        let rrdp_types = vec!["notification", "snapshot"];

        if !rrdp_types.contains(&typ.as_str()){
            let (mut children, folders) = util::start_processes("./bin/object_generator", &typ, folders);
            let obj_cache = cws + "obj_cache/";
            
            let obj_per_iteration;
            let repo_fn: &dyn Fn(&RepoConfig, u32);
            let serialized_obj_fn: &dyn Fn(&str, &RepoConfig, u32, Option<Vec<(Bytes, String)>>, &str);

            if typ == "mft"{
                obj_per_iteration = 5000;

                repo_fn = &mft::clear_repo;
                serialized_obj_fn = &mft::handle_serialized_object;    
            }
            else if typ == "cert"{
                obj_per_iteration = 10000;

                repo_fn = &util::clear_repo;
                serialized_obj_fn = &cert::handle_serialized_object;    
            }
            else if typ == "roa" || typ == "gbr" || typ == "aspa"{
                obj_per_iteration = 10000;

                repo_fn = &util::clear_repo;
                serialized_obj_fn = &roa::handle_serialized_object;    
            }
            else{
                panic!("Unknown object type!");
            }

            util::start_fuzzing(
                &obj_cache,
                &typ,
                folders,
                obj_per_iteration,
                repo_fn,
                serialized_obj_fn,
                &mut children
            );
        }
        else{
            if typ == "notification"{
                let dont_move = false;
                if dont_move{
                    println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
                }
                let folders = vec!["/home/mirdita/data/xmls/notification/".to_string()];

                let create_fun = notification::create_notifications;
                let repo_fn = &util::clear_repo;
                util::start_fuzzing_xml(&typ, folders.clone(), 4000, repo_fn, &create_fun, dont_move);
                return;
            }
            else if typ == "snapshot"{
                let dont_move = false;
                if dont_move{
                    println!("Warning: Don't move is set to TRUE. The same files will be used continuously.")
                }
                let folders = vec!["/home/mirdita/data/xmls/snapshot/".to_string()];

                let create_fun = snapshot::create_snapshots;
                let repo_fn = &util::clear_repo;
                util::start_fuzzing_xml(&typ, folders.clone(), 4000, repo_fn, &create_fun, dont_move);
                return;
            }
    
        }
    }
}