use std::str::FromStr;

use bytes::Bytes;
use rpki_testing::repository::{self, RepoConfig};

use crate::{notification, util, consts};
use uuid::Uuid;
use std::str;
pub fn run_snapshot(obj_folder: &str){
    let amount = 2;
    
    let mut conf = repository::create_default_config(consts::domain.to_string());

    repository::initialize_repo(&mut conf, false, None);
    
    let mut confs: Vec<RepoConfig> = vec![];
    for i in 0..amount{
        let ca_name = "ca".to_string() + &i.to_string();

        let mut repo_conf = util::generate_ca_conf(ca_name.clone());
        repo_conf.CA_TREE.insert(ca_name.clone(), "ta".to_string());
        confs.push(repo_conf);
    }

    let mut nconfs = vec![];
    for i in 0..confs.len(){
        nconfs.push(&confs[i]);
    }

    util::create_cas(0, nconfs.clone(), None);

    let files = notification::read_files_from_folder(obj_folder, amount);

    let session_id = Uuid::from_str("702474f1-40b8-4d05-a0cc-36d210dc40eb").unwrap();

    // println!("Files: {:}", files.len());
    create_snapshots(nconfs, files);
    let (uid, _) = repository::get_current_session_notification(&conf);
    let (snapshot, snapshot_file) = repository::create_current_snapshot(session_id, 1, None, true, &conf, None, None);
    repository::write_snapshot_file(snapshot.clone(), session_id, 1, &conf);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);

    let notification = repository::create_notification(snapshot_bytes, vec![], snapshot_file.as_str(), 5, session_id, 1, &conf);
    repository::write_notification_file(notification, &conf).unwrap();

}


pub fn create_snapshots(confs: Vec<&RepoConfig>, contents: Vec<(String, Bytes)>){
    for i in 0..contents.len(){
        let mut conf = &confs[i];
        let c = &contents[i];
        let content = c.1.clone();

        let session_id = Uuid::from_str("702474f1-40b8-4d05-a0cc-36d210dc40eb").unwrap();        
        // let session_id = Uuid::from_str("66a35282-968d-450e-8a5d-e3de37530e80").unwrap();        

        // repository::create_random_roa_ca(conf, &("ca".to_string() + &i.to_string()));
        // repository::make_manifest(&("ca".to_string() + &i.to_string()), "ta", conf);
        // let (snapshot, _) = repository::create_current_snapshot(session_id, 1, None, false, conf);
        // let mut xml_vec = Vec::new();
        // snapshot.write_xml(&mut xml_vec).unwrap();

        // let res = str::from_utf8(&xml_vec).unwrap().to_string();
        // let filename = repository::write_snapshot_file_bytes(res.as_bytes(), session_id, 1, &mut conf);

        let filename = repository::write_snapshot_file_bytes(&content, session_id, 1, &mut conf);

        let notfile = repository::create_notification(content, vec![], &filename, 5, session_id, 1, conf);
        repository::write_notification_file(notfile, conf);
        
    }
    let mut dconf = repository::create_default_config(consts::domain.to_string());
    dconf.CA_TREE.insert("newca".to_string(), "ta".to_string());
    repository::make_manifest("newca", "ta", &dconf);
    repository::create_default_crl(1, vec![], &(dconf.BASE_KEY_DIR_l.to_string() + "newca.der"), "newca", &dconf);
    repository::add_roa_str(&(dconf.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." +  &dconf.DEFAULT_IPSPACE_SEC_OCTET.to_string() + ".0.0/24 => 22222"), true, &dconf);



}

