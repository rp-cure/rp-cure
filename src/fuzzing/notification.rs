use std::{fs::{self, metadata}, collections::HashSet};

use bytes::Bytes;
use rand::{thread_rng, distributions::Alphanumeric, Rng};
use crate::publication_point::repository::{self, RepoConfig};
use crate::{util, consts};

pub fn run_notification(obj_folders: Vec<&str>, amount: u32){
    // let amount = 10;
    
    let mut conf = repository::create_default_config(consts::domain.to_string());

    repository::initialize_repo(&mut conf, false, None);
    
    let mut confs: Vec<RepoConfig> = vec![];
    for i in 0..amount{
        let ca_name = "ca".to_string() + &i.to_string();

        let mut repo_conf = util::generate_ca_conf(ca_name.clone());
        confs.push(repo_conf);
    }

    let mut nconfs = vec![];
    for i in 0..confs.len(){
        nconfs.push(&confs[i]);
    }



    util::create_cas(0, nconfs.clone(), None);
    for folder in obj_folders{
        loop{
            let files = read_files_from_folder(&folder, amount);
            if files.len() == 0{
                break;
            }
            create_notifications(nconfs.clone(), files.clone());
            util::move_files_data(folder.clone().to_string(), &files, true);
        }
    }
}


pub fn create_notifications(confs: Vec<&RepoConfig>, contents: Vec<(String, Bytes)>){
    for i in 0..contents.len(){
        let mut conf = &confs[i];
        let c = &contents[i];
        let content = c.1.clone();
        // let content = b"\x00\x01";
        repository::write_notification_file_bytes(&content, &mut conf);
    }
}


pub fn read_files_from_folder(folder: &str, amount: u32) -> Vec<(String, Bytes)> {
    let md = metadata(folder).unwrap();
    
    let mut objects = HashSet::new();

    if md.is_file(){
        objects.insert((folder.to_string(), Bytes::from(fs::read(folder).unwrap())));
    }
    else{
       
    let paths = fs::read_dir(folder).unwrap();


    let mut read_amount = 0;
    for path in paths {
        if read_amount >= amount {
            break;
        }

        read_amount += 1;

        let p = path.unwrap().path();
        // let mut f = File::open(&p).expect("no file found");
        // let metadata = fs::metadata(&p).expect("unable to read metadata");
        // let mut buffer = vec![0; metadata.len() as usize];
        // f.read(&mut buffer).expect("buffer overflow");
        // let b = Bytes::from(buffer);

        let b = fs::read(&p).unwrap();


        objects.insert((p.file_name().unwrap().to_str().unwrap().to_string(), Bytes::from(b)));
    }}
    let obj_vec: Vec<(String, Bytes)> = objects.into_iter().collect();
    obj_vec
}




// pub fn generate_from_files_plain(
//     folder: &str,
//     amount: u32,
//     obj_type: &str,
// ) -> Vec<(String, String)> {
//     let obj = read_files_from_folder(folder, amount);

//     println!("Found {} objects", obj.len());
//     let mut objects = vec![];

//     for i in 0..obj.clone().len() {
//         let a = &obj.clone()[i];

//         let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(12).map(char::from).collect();

//         objects.push((rand_string + "." + obj_typea));
//     }

//     objects
// }