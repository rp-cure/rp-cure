use std::{
    fmt, fs, os::unix::net::UnixListener, path::Path, thread, time::{Duration, Instant}, vec
};

use crate::{
    consts,
    generation_interface::OpType,
    process_util,
    publication_point::repository::{self, KeyAndSigner, RepoConfig},
    FuzzConfig,
};
use asn1::Tlv;
use asn1_generator::asn1_elements::{self, ReadASN1, WriteASN1};
use asn1_generator::{
    asn1_elements::{Sequence, TLV},
    parser::Tree,
};
use chrono::Utc;
use hex::FromHex;
use rand::Rng;
use serde::Deserializer;
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize, Serializer,
};
use sha1::Digest;
use sha1::Sha1;

// An entire PP
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FuzzingPP {
    pub sets: Vec<RepoSet>,
    pub conf: RepoConfig,
}

impl FuzzingPP {
    // Split all contained repositories by factor
    pub fn split(&self, factor: usize) -> Vec<FuzzingPP> {
        let mut new_pps = vec![];
        for s in &self.sets {
            let new_con = s.split(factor);
            for n in new_con {
                new_pps.push(FuzzingPP {
                    sets: vec![n],
                    conf: self.conf.clone(),
                });
            }
        }
        new_pps
    }

    // Inflate all contained repositories by factor
    pub fn inflate(&mut self, factor: usize) {
        for s in &mut self.sets {
            s.inflate(factor);
        }
    }

    pub fn serialize(&self) -> Vec<(String, Vec<u8>)> {
        let mut output = vec![];
        for s in &self.sets {
            output.extend(s.serialize());
        }
        output
    }

    pub fn repositorify(&self) -> Vec<(String, Vec<u8>)> {
        return self.create_snapshot_notification(&self.conf);
    }

    // This creates the root repository that contains all children
    pub fn create_root_repo(&self, conf: &RepoConfig) -> Vec<(String, Vec<u8>)> {
        let mut values = vec![];
        let rsa_key_uri_l = conf.BASE_KEY_DIR_l.clone() + "ta.der";
        let crl_content = repository::create_default_crl_i(1, vec![], &rsa_key_uri_l, "ta", false, &conf).to_vec();

        let mut file_uri = conf.BASE_REPO_DIR_l.clone() + "ta/";

        let name = repository::get_filename_crl_mft(&rsa_key_uri_l);
        file_uri.push_str(&name);
        file_uri.push_str(".");
        let crl_uri = file_uri.clone() + "crl";
        let mft_uri = file_uri.clone() + "mft";

        for s in &self.sets {
            for repo in &s.repos {
                // let uri = parent_name.clone() + &repo.certificate.name;
                // let raw = repo.certificate.tree.encode();
                values.push((repo.certificate.name.clone(), repo.certificate.tree.encode()));
                // for_mft.push((&repo.certificate.name, raw));
            }
        }

        values.push((name + ".crl", crl_content.clone()));

        let mft_content = repository::make_manifest_objects("ta", "root", &conf, values).to_vec();

        return vec![(mft_uri, mft_content), (crl_uri, crl_content)];
    }

    pub fn create_snapshot_notification(&self, conf: &RepoConfig) -> Vec<(String, Vec<u8>)> {
        let mut objects = self.serialize();
        objects.extend(self.create_root_repo(conf));
        let debug = conf.DEBUG;
        let debug = true;
        if debug {
            for o in &objects{
                // Create parent directory
                fs::create_dir_all(Path::new(&o.0).parent().unwrap());
                fs::write(&o.0, &o.1).unwrap();
            }
        }
        let (s, su, n, nu) = repository::create_snapshot_notification_objects(objects, conf);
        vec![(s, su), (n, nu)]
    }

    pub fn write_to_disc(&self, conf: &RepoConfig) {
        let v = self.create_snapshot_notification(conf);
        for (uri, content) in v {
            fs::create_dir_all(Path::new(&uri).parent().unwrap());
            println!("Writing to {}", uri);
            fs::write(uri, content).unwrap();
        }
    }
}

pub fn signing_loop(conf: FuzzConfig, id: u32) {
    let socket = "/tmp/gensock".to_string() + &id.to_string();
    fs::remove_file(&socket).unwrap_or_default();

    println!("Binding to socket {}", &socket);
    let stream = UnixListener::bind(&socket).unwrap();
    stream.set_nonblocking(true).unwrap();

    loop {
        let mut f_option = process_util::get_batch(&stream);
        while f_option.is_none() {
            thread::sleep(Duration::from_millis(100));
            f_option = process_util::get_batch(&stream);
        }
        let mut pp = f_option.unwrap();
        pp.inflate(10);
        let data = serde_json::to_string(&pp).unwrap();
        println!("Sending reply now");
        process_util::send_new_data_s(data, "/tmp/responses");
    }
}

pub fn load_example_roa(conf: &RepoConfig, asid: u16) -> FuzzingObject {
    let roa = fs::read("./example.roa").unwrap();
    let mut roa_tree = asn1_generator::connector::new_tree(roa, "roa");

    let d = if asid < 256{
        vec![asid as u8]
    }  
    else{
        vec![(asid >> 8) as u8, asid as u8]
    };
    roa_tree.set_data_by_label("AS-ID", d, false );
    roa_tree.fix_sizes(false);
    let parent_key_roa = load_key(conf).0;
    let subject_key_roa = load_key(conf).1;

    let froa = FuzzingObject::new(
        OpType::ROA,
        parent_key_roa,
        subject_key_roa,
        roa_tree,
        "example.roa".to_string(),
        conf.clone(),
    );
    froa
}

pub fn construct_PP(conf: RepoConfig) -> FuzzingPP {
    let repo_set = construct_repositories(OpType::ROA, 1);
    FuzzingPP {
        sets: vec![repo_set],
        conf,
    }
}

pub fn construct_child_repository(parent: &mut FuzzingRepository, obj_amount: u16, ca_name: String) -> FuzzingRepository {
    let mut conf = repository::create_default_config(consts::domain.to_string());

    conf.CA_NAME = ca_name.clone();
    conf.CA_TREE.insert(ca_name.clone(), parent.conf.CA_NAME.clone());
    parent.conf.CA_TREE.insert(ca_name, parent.conf.CA_NAME.clone());
    let mut base_repository = construct_base_repository(&conf);

    let typ = parent.repo_info.target_object.clone();
    if is_payload(&typ) {
        if typ == OpType::ROA {
            let mut new_payloads = vec![];
            let ex_roa = load_example_roa(&conf, 2);
            for _ in 0..obj_amount {
                new_payloads.push(ex_roa.clone());
            }
            base_repository.payloads = new_payloads;
            base_repository.fix_all_objects(true);
            return base_repository;
        }
    }

    // TODO
    base_repository.fix_all_objects(true);

    return base_repository;
}

pub fn construct_repositories(typ: OpType, obj_amount: u16) -> RepoSet {
    let conf = repository::create_default_config(consts::domain.to_string());

    let mut base_repository = construct_base_repository(&conf);

    if is_payload(&typ) {
        if typ == OpType::ROA {
            let mut new_payloads = vec![];
            let ex_roa = load_example_roa(&conf, 1);
            for _ in 0..obj_amount {
                new_payloads.push(ex_roa.clone());
            }
            base_repository.payloads = new_payloads;

            let mut child = construct_child_repository(&mut base_repository, obj_amount, "child".to_string());
            child.fix_all_objects(true);

            base_repository.child_repos.push(child);
            base_repository.fix_all_objects(true);


            let repo_set = RepoSet {
                repos: vec![base_repository],
                target_type: typ,
            };
            return repo_set;
        }
    }

    // TODO
    base_repository.fix_all_objects(true);

    return RepoSet {
        repos: vec![base_repository],
        target_type: typ,
    };
}

pub fn construct_base_repository(conf: &RepoConfig) -> FuzzingRepository {
    let parent_key_roa = load_key(conf).0;
    let subject_key_roa = load_key(conf).1;

    let mft_key_dir = conf.BASE_KEY_DIR_l.clone() + &conf.CA_NAME + "_mft.der";
    let crl_key_dir = conf.BASE_KEY_DIR_l.clone() + &conf.CA_NAME + "_crl.der";
    let subject_key_mft = repository::read_cert_key(&mft_key_dir);
    let subject_key_crl = repository::read_cert_key(&crl_key_dir);

    let key_uri = "data/keys/".to_string() + &conf.CA_NAME + ".der";

    let subject_key_cert = repository::read_cert_key(&key_uri);

    let parent_name = conf.CA_TREE.get(&conf.CA_NAME).unwrap().to_string();
    let parent_key = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.clone() + &parent_name + ".der"));
    // let root_key = repository::read_cert_key("data/keys/ta.der");

    let key_uri = "data/keys/".to_string() + &conf.CA_NAME + ".der";

    let parent_key_mft = repository::read_cert_key(&key_uri);
    let parent_key_crl = repository::read_cert_key(&key_uri);

    let roa = fs::read("./example.roa").unwrap();
    let mft = fs::read("./example.mft").unwrap();
    let crl = fs::read("./example.crl").unwrap();
    let cert = fs::read("./example.cer").unwrap();

    let roa_tree = asn1_generator::connector::new_tree(roa, "roa");
    let mft_tree = asn1_generator::connector::new_tree(mft, "mft");
    let crl_tree = asn1_generator::connector::new_tree(crl, "crl");
    let cert_tree = asn1_generator::connector::new_tree(cert, "cert");

    let froa = FuzzingObject::new(
        OpType::ROA,
        parent_key_roa,
        subject_key_roa,
        roa_tree,
        "example.roa".to_string(),
        conf.clone(),
    );

    let filename_mft = repository::get_filename_crl_mft(&key_uri);

    let crl_uri = filename_mft.clone() + ".crl";
    let mft_uri = filename_mft.clone() + ".mft";

    let fmft = FuzzingObject::new(OpType::MFT, parent_key_mft, subject_key_mft, mft_tree, mft_uri, conf.clone());

    let fcrl = FuzzingObject::new(OpType::CRL, parent_key_crl, subject_key_crl, crl_tree, crl_uri, conf.clone());

    let fcer = FuzzingObject::new(
        OpType::CERTCA,
        parent_key,
        subject_key_cert,
        cert_tree,
        conf.CA_NAME.clone() + &".cer".to_string(),
        conf.clone(),
    );

    let mut repo = FuzzingRepository {
        payloads: vec![froa],
        manifest: fmft,
        crl: fcrl,
        conf: conf.clone(),
        certificate: fcer,
        child_repos: vec![], // TODO
        repo_info: RepoInfo::default(),
    };

    repo.fix_all_objects(true);
    repo
    // repo.mutate_objects_rnd(1);

    // repo.fix_all_objects(false);

    // repo.write_to_disc();
    // repo.update_parent();
}

pub fn load_key(conf: &RepoConfig) -> (KeyAndSigner, KeyAndSigner) {
    let key_uri = "data/keys/newca.der";
    let key_uri = conf.BASE_KEY_DIR_l.clone() + &conf.CA_NAME + ".der";
    let ks = repository::read_cert_key(&key_uri);
    // Random number between 1 and 1000000
    let number = rand::thread_rng().gen_range(1..1000);

    let key_uri2 = "fuzzing_keys/".to_string() + &number.to_string() + "_roa";
    let ks2 = repository::read_cert_key(&key_uri2);

    (ks, ks2)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoInfo {
    pub amount_objects: u16,
    pub ca_index: u16,
    pub target_object: OpType,
}

impl RepoInfo {
    pub fn new(amount_objects: u16, ca_index: u16, target_object: OpType) -> Self {
        Self {
            amount_objects,
            ca_index,
            target_object,
        }
    }

    pub fn default() -> Self {
        Self {
            amount_objects: 102,
            ca_index: 0,
            target_object: OpType::ROA,
        }
    }
}

pub fn is_payload(t: &OpType) -> bool {
    return t == &OpType::ROA || t == &OpType::ASPA || t == &OpType::GBR;
}

// All FuzzingRepositories that fuzz the same object type
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoSet {
    pub repos: Vec<FuzzingRepository>,
    pub target_type: OpType,
}

impl RepoSet {
    pub fn split(&self, factor: usize) -> Vec<RepoSet> {
        if is_payload(&self.target_type) {
            let mut new_repos = vec![];
            let repo = &self.repos[0];
            let payloads = repo.split_payloads(factor);
            for p in payloads {
                let new_repo = FuzzingRepository::new(
                    p,
                    repo.manifest.clone(),
                    repo.crl.clone(),
                    repo.conf.clone(),
                    repo.certificate.clone(),
                    vec![], // TODO
                    repo.repo_info.clone(),
                );
                let new_repo_set = RepoSet {
                    repos: vec![new_repo],
                    target_type: self.target_type.clone(),
                };
                new_repos.push(new_repo_set);
            }
            return new_repos;
        } else {
            let p = split_vector_into_parts(&self.repos, factor);
            let mut new_repos = vec![];

            for v in p {
                let new_repo_set = RepoSet {
                    repos: v,
                    target_type: self.target_type.clone(),
                };
                new_repos.push(new_repo_set);
            }
            return new_repos;
        }
    }

    // Inflate by mutating contained objects
    pub fn inflate(&mut self, factor: usize) {
        if is_payload(&self.target_type) {
            self.repos[0].inflate_payloads(factor);
        } else {
            let mut new_repos = vec![];
            for r in &mut self.repos {
                for _ in 0..factor {
                    let mut new_repo = r.clone();
                    new_repo.mutate_object();
                    new_repos.push(new_repo);
                }
            }
        }
    }

    pub fn serialize(&self) -> Vec<(String, Vec<u8>)> {
        let mut output = vec![];
        for r in &self.repos {
            output.extend(r.serialize());
        }
        output
    }
}

fn split_vector_into_parts<T>(vec: &Vec<T>, num_parts: usize) -> Vec<Vec<T>>
where
    T: Clone,
{
    let part_size = vec.len() / num_parts;
    let remainder = vec.len() % num_parts;

    let (main_chunk, remainder_chunk) = vec.split_at(part_size * num_parts);

    let mut chunks: Vec<Vec<T>> = main_chunk.chunks_exact(part_size).map(|chunk| chunk.to_vec()).collect();

    if remainder > 0 {
        chunks.push(remainder_chunk.to_vec());
    }

    chunks
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FuzzingRepository {
    pub payloads: Vec<FuzzingObject>,
    pub manifest: FuzzingObject,
    pub crl: FuzzingObject,
    pub conf: RepoConfig,
    pub certificate: FuzzingObject,
    pub child_repos: Vec<FuzzingRepository>,
    pub repo_info: RepoInfo,
}

impl FuzzingRepository {
    pub fn new(
        payloads: Vec<FuzzingObject>,
        manifest: FuzzingObject,
        crl: FuzzingObject,
        conf: RepoConfig,
        certificate: FuzzingObject,
        child_repos: Vec<FuzzingRepository>,
        repo_info: RepoInfo,
    ) -> Self {
        Self {
            payloads,
            manifest,
            crl,
            conf,
            certificate,
            child_repos,
            repo_info,
        }
    }

    pub fn serialize(&self) -> Vec<(String, Vec<u8>)> {
        let mut output = vec![];
        let data_dir = self.conf.BASE_REPO_DIR_l.clone() + &self.conf.CA_NAME + "/";
        let parent_name = self.conf.CA_TREE.get(&self.conf.CA_NAME).unwrap();
        let parent_data_dir = self.conf.BASE_REPO_DIR_l.clone() + &parent_name + "/";

        // fs::create_dir_all(data_dir.clone());

        for v in &self.payloads {
            let b = v.tree.encode();
            output.push((data_dir.clone() + &v.name, b));
        }

        let mft_b = self.manifest.tree.encode();
        output.push((data_dir.clone() + &self.manifest.name, mft_b));

        let crl_b = self.crl.tree.encode();
        output.push((data_dir.clone() + &self.crl.name, crl_b));

        let cert_b = self.certificate.tree.encode();
        output.push((parent_data_dir.clone() + &self.certificate.name, cert_b));

        for r in &self.child_repos {
            output.extend(r.serialize());
        }
        output
    }

    pub fn split_payloads(&self, factor: usize) -> Vec<Vec<FuzzingObject>> {
        return split_vector_into_parts(&self.payloads, factor);
    }

    pub fn inflate_payloads(&mut self, factor: usize) {
        let mut new_payloads = vec![];
        for p in &self.payloads {
            for _ in 0..factor {
                let mut v = p.clone();
                v.mutate();
                new_payloads.push(v);
            }
        }
        self.payloads = new_payloads;
    }

    pub fn fix_all_objects(&mut self, all_fields: bool) {
        let mut payloads = &mut self.payloads;

        let mut values = vec![];
        for obj in payloads {
            obj.fix_fields(all_fields, None);
            values.push(obj.asn1_name_and_hash());
        }

        self.crl.fix_fields(all_fields, None);
        values.push(self.crl.asn1_name_and_hash());

        for obj in &self.child_repos {
            values.push(obj.certificate.asn1_name_and_hash());
        }

        let hashlist = Sequence::new(values);
        self.manifest.fix_fields(all_fields, Some(hashlist.encode_content()));

        self.certificate.fix_fields(all_fields, None);
        // self.crl.fix_fields(all_fields, None);
    }

    pub fn create_hash_list(&self) -> Vec<u8> {
        let payloads = &self.payloads;

        let mut values = vec![];
        for obj in payloads {
            values.push(obj.asn1_name_and_hash());
        }
        values.push(self.crl.asn1_name_and_hash());
        for c in &self.child_repos{
            values.push(c.certificate.asn1_name_and_hash());
        }

        let hashlist = Sequence::new(values).encode();
        hashlist
    }

    pub fn write_to_disc(&self) {
        let data_dir = self.conf.BASE_REPO_DIR_l.clone() + &self.conf.CA_NAME + "/";
        let parent_name = self.conf.CA_TREE.get(&self.conf.CA_NAME).unwrap();
        let parent_data_dir = self.conf.BASE_REPO_DIR_l.clone() + &parent_name + "/";

        fs::create_dir_all(data_dir.clone());

        for v in &self.payloads {
            let b = v.tree.encode();
            fs::write(data_dir.clone() + &v.name, b).unwrap();
        }

        let mft_b = self.manifest.tree.encode();
        fs::write(data_dir.clone() + &self.manifest.name, mft_b).unwrap();

        let crl_b = self.crl.tree.encode();
        fs::write(data_dir.clone() + &self.crl.name, crl_b).unwrap();

        let cert_b = self.certificate.tree.encode();
        fs::write(parent_data_dir.clone() + &self.certificate.name, cert_b).unwrap();
    }

    pub fn update_parent(&self) {
        let parent_name = self.conf.CA_TREE.get(&self.conf.CA_NAME).unwrap();
        let grandparent_name = match self.conf.CA_TREE.get(parent_name) {
            Some(v) => v,
            None => "root",
        };

        let (session_id, serial_number) = repository::get_current_session_notification(&self.conf);
        let serial_number = serial_number + 1;

        repository::make_manifest(&parent_name, grandparent_name, &self.conf);

        repository::finalize_snap_notification(session_id, serial_number, vec![], vec![], &self.conf);
    }

    pub fn mutate_objects_rnd(&mut self, amount: u16) {
        let mut rand = rand::thread_rng();
        for _ in 0..amount {
            let ind = rand.gen_range(0..4);
            if ind == 0 {
                let ind_pl = rand.gen_range(0..self.payloads.len());
                println!("Mutating Payload");
                self.payloads[ind_pl].mutate();
            } else if ind == 1 {
                println!("Mutating MFT");

                self.manifest.mutate();
                self.manifest.fix_fields(false, Some(self.create_hash_list()))
            } else if ind == 2 {
                println!("Mutating CRL");

                self.crl.mutate();
            } else {
                println!("Mutating Certificate");
                self.certificate.mutate();
            }
        }
    }

    pub fn mutate_object(&mut self) {
        match self.repo_info.target_object {
            OpType::MFT => {
                // For Manifest, additionally fix hashlist
                self.manifest.mutate();
                self.manifest.fix_fields(false, Some(self.create_hash_list()))
            }
            OpType::CRL => {
                self.crl.mutate();
            }
            OpType::CERTCA | OpType::CERTEE => {
                self.certificate.mutate();
            }
            OpType::ROA | OpType::ASPA | OpType::GBR => {
                let mut rand = rand::thread_rng();

                let ind_pl = rand.gen_range(0..self.payloads.len());
                self.payloads[ind_pl].mutate();
            }
            // TODO
            OpType::SNAP => {}
            OpType::NOTI => {}
        }
    }
}

#[derive(Clone)]
pub struct FuzzingObject {
    pub op_type: OpType,
    pub parent_key: KeyAndSigner,
    pub child_key: KeyAndSigner,
    pub tree: Tree,
    pub conf: repository::RepoConfig,
    pub name: String,
}

impl Serialize for FuzzingObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Implement serialization logic here.
        // For example, serialize as a tuple:
        let tuple = (
            &self.op_type,
            &self.parent_key.file_uri,
            &self.child_key.file_uri,
            &self.tree,
            &self.conf,
            &self.name,
        );
        tuple.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FuzzingObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Implement deserialization logic here.
        // For example, deserialize from a tuple:
        struct FuzzingObjectVisitor;

        impl<'de> Visitor<'de> for FuzzingObjectVisitor {
            type Value = FuzzingObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple representing a FuzzingObject")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<FuzzingObject, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let op_type = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let parent_key_t = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let parent_key = repository::read_cert_key(parent_key_t);
                let child_key_t = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let child_key = repository::read_cert_key(child_key_t);

                let tree = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let conf = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let name = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(5, &self))?;

                Ok(FuzzingObject {
                    op_type,
                    parent_key,
                    child_key,
                    tree,
                    conf,
                    name,
                })
            }
        }

        deserializer.deserialize_tuple(6, FuzzingObjectVisitor)
    }
}

impl FuzzingObject {
    pub fn new(
        op_type: OpType,
        parent_key: KeyAndSigner,
        child_key: KeyAndSigner,
        tree: Tree,
        name: String,
        conf: repository::RepoConfig,
    ) -> Self {
        Self {
            op_type,
            parent_key,
            child_key,
            tree,
            name,
            conf,
        }
    }

    pub fn mutate_tree(&mut self) {
        self.tree.mutate();
    }

    pub fn mutate(&mut self) {
        self.tree.mutate();
        let info = match self.tree.get_node(self.tree.mutations[0].node_id) {
            Some(v) => &v.info,
            None => "None",
        };
        // println!("Mutation: {:?}, {}", self.tree.mutations, info);
        self.fix_fields(false, None);
    }

    pub fn fix_digest(&mut self) {
        if self.tree.node_manipulated_by_label("messageDigest") {
            return;
        }
        if self.tree.get_node_by_label("encapsulatedContent").is_none()
            || !self.tree.get_node_by_label("encapsulatedContent").unwrap().tainted
        {
            return;
        }

        let data = self.tree.get_data_by_label("encapsulatedContent").unwrap();
        let hash = sha256::digest(&*data);
        let hash = <[u8; 32]>::from_hex(hash).unwrap().to_vec();
        self.tree.set_data_by_label("messageDigest", hash, true);
    }

    pub fn fix_ski(&mut self) {
        if self.tree.node_manipulated_by_label("subjectKeyIdentifier") {
            return;
        }

        let sub_key_id = <[u8; 20]>::from_hex(self.child_key.get_pub_key().key_identifier().to_string())
            .unwrap()
            .to_vec();

        self.tree.set_data_by_label("subjectKeyIdentifier", sub_key_id.clone(), true);
    }

    pub fn fix_aki(&mut self) {
        if self.tree.node_manipulated_by_label("authorityKeyIdentifier") {
            return;
        }

        let mut hasher = Sha1::new();

        // process input message
        hasher.update(self.parent_key.get_pub_key().bits());
        let res = hasher.finalize();

        self.tree.set_data_by_label("authorityKeyIdentifier", res.to_vec(), true);
    }

    pub fn fix_names(&mut self) {
        // Fix issuer name and subject name

        if !self.tree.node_manipulated_by_label("issuerName") {
            self.tree.set_data_by_label(
                "issuerName",
                self.parent_key.get_pub_key().key_identifier().to_string().as_bytes().to_vec(),
                true,
            );
        }

        if !self.tree.node_manipulated_by_label("subjectName") {
            self.tree.set_data_by_label(
                "subjectName",
                self.child_key.get_pub_key().key_identifier().to_string().as_bytes().to_vec(),
                true,
            );
        }
    }

    pub fn fix_sid(&mut self) {
        let sub_key_id = <[u8; 20]>::from_hex(self.child_key.get_pub_key().key_identifier().to_string())
            .unwrap()
            .to_vec();

        if !self.tree.node_manipulated_by_label("signerIdentifier") {
            self.tree.set_data_by_label("signerIdentifier", sub_key_id, true);
        }
    }

    pub fn fix_subject_key(&mut self) {
        let mut new_bits: Vec<u8> = vec![0];
        new_bits.extend(self.child_key.get_pub_key().bits().to_vec());

        if !self.tree.node_manipulated_by_label("subjectPublicKey") {
            self.tree.set_data_by_label("subjectPublicKey", new_bits, true);
        }
    }

    pub fn fix_validty(&mut self) {
        let now = Utc::now();
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        let utc_time_string = twenty_four_hours_ago.format("%y%m%d%H%M%SZ").to_string();
        let not_before: Vec<u8> = utc_time_string.as_bytes().to_vec();

        let in_three_days = now + chrono::Duration::hours(72);
        let utc_time_string = in_three_days.format("%y%m%d%H%M%SZ").to_string();
        let not_after: Vec<u8> = utc_time_string.as_bytes().to_vec();
        if !self.tree.node_manipulated_by_label("notBefore") {
            self.tree.set_data_by_label("notBefore", not_before, true);
        }

        if !self.tree.node_manipulated_by_label("notAfter") {
            self.tree.set_data_by_label("notAfter", not_after, true);
        }
    }

    pub fn fix_mft_validity(&mut self) {
        let now = Utc::now();
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        // Use GeneralizedTime format: YYYYMMDDHHMMSSZ
        let generalized_time_string = twenty_four_hours_ago.format("%Y%m%d%H%M%SZ").to_string();
        let not_before: Vec<u8> = generalized_time_string.as_bytes().to_vec();

        let in_three_days = now + chrono::Duration::hours(72);
        // Use GeneralizedTime format: YYYYMMDDHHMMSSZ
        let generalized_time_string = in_three_days.format("%Y%m%d%H%M%SZ").to_string();
        let not_after: Vec<u8> = generalized_time_string.as_bytes().to_vec();

        if !self.tree.node_manipulated_by_label("thisUpdate") {
            self.tree.set_data_by_label("thisUpdate", not_before, true);
        }

        if !self.tree.node_manipulated_by_label("nextUpdate") {
            self.tree.set_data_by_label("nextUpdate", not_after, true);
        }
    }

    pub fn fix_crl_location(&mut self) {
        let storage_base_uri;
        let cert_key_uri;
        if self.op_type == OpType::CERTCA || self.op_type == OpType::CERTEE {
            storage_base_uri =
                "rsync://".to_string() + &self.conf.DOMAIN + "/" + &self.conf.BASE_REPO_DIR + &self.conf.CA_TREE[&self.conf.CA_NAME] + "/";
            cert_key_uri = self.conf.BASE_KEY_DIR_l.clone() + &self.conf.CA_TREE[&self.conf.CA_NAME] + ".der";
        } else {
            storage_base_uri = "rsync://".to_string() + &self.conf.DOMAIN + "/" + &self.conf.BASE_REPO_DIR + &self.conf.CA_NAME + "/";
            cert_key_uri = self.conf.BASE_KEY_DIR_l.clone() + &self.conf.CA_NAME + ".der";
        }
        let filename = repository::get_filename_crl_mft(&cert_key_uri);
        let crl_uri = storage_base_uri.clone() + &filename + ".crl";

        if !self.tree.node_manipulated_by_label("crlDistributionPoint") {
            self.tree
                .set_data_by_label("crlDistributionPoint", crl_uri.as_bytes().to_vec(), true);
        }
    }

    pub fn fix_signed_object_location(&mut self) {
        let storage_uri =
            "rsync://".to_string() + &self.conf.DOMAIN + "/" + &self.conf.BASE_REPO_DIR + &self.conf.CA_NAME + "/" + &self.name;

        if !self.tree.node_manipulated_by_label("signedObjectURI") {
            self.tree
                .set_data_by_label("signedObjectURI", storage_uri.as_bytes().to_vec(), true);
        }
    }

    pub fn fix_ca_repository(&mut self) {
        let storage_uri = "rsync://".to_string() + &self.conf.DOMAIN + "/" + &self.conf.BASE_REPO_DIR + &self.conf.CA_NAME + "/";

        if !self.tree.node_manipulated_by_label("caRepositoryURI") {
            self.tree
                .set_data_by_label("caRepositoryURI", storage_uri.as_bytes().to_vec(), true);
        }
    }

    pub fn fix_manifest_uri(&mut self) {
        let cert_key_path = self.conf.BASE_KEY_DIR.clone() + &self.conf.CA_NAME + ".der";
        let storage_uri = "rsync://".to_string()
            + &self.conf.DOMAIN
            + "/"
            + &self.conf.BASE_REPO_DIR
            + &self.conf.CA_NAME
            + "/"
            + &repository::get_filename_crl_mft(&cert_key_path)
            + ".mft";

        if !self.tree.node_manipulated_by_label("rpkiManifestURI") {
            self.tree
                .set_data_by_label("rpkiManifestURI", storage_uri.as_bytes().to_vec(), true);
        }
    }

    pub fn fix_notification_uri(&mut self) {
        let storage_uri = "https://".to_string() + &self.conf.DOMAIN + "/" + &self.conf.BASE_RRDP_DIR + "notification.xml";

        if !self.tree.node_manipulated_by_label("rpkiNotifyURI") {
            self.tree.set_data_by_label("rpkiNotifyURI", storage_uri.as_bytes().to_vec(), true);
        }
    }

    pub fn fix_signer_signature(&mut self, all_fields: bool) {
        if self.tree.get_node_by_label("signerSignedAttributesField").is_none()
            || (!all_fields && !self.tree.get_node_by_label("signerSignedAttributesField").unwrap().tainted)
        {
            return;
        }
        let data = self.tree.get_data_by_label("signerSignedAttributesField").unwrap();
        let data = data[2..].to_vec(); // Remove first two bytes because we need to change them

        let len = data.len();
        let mut res = Vec::with_capacity(len + 4);
        res.push(0x31);
        if len < 128 {
            res.push(len as u8)
        } else if len < 0x10000 {
            res.push(2);
            res.push((len >> 8) as u8);
            res.push(len as u8);
        } else {
            res.push(3);
            res.push((len >> 16) as u8);
            res.push((len >> 8) as u8);
            res.push(len as u8);
        }
        res.extend_from_slice(data.as_ref());

        let sig = self.child_key.sign(&res).to_vec();

        if !self.tree.node_manipulated_by_label("signerSignature") {
            self.tree.set_data_by_label("signerSignature", sig, true);
        }
    }

    pub fn fix_certificate_signature(&mut self) {
        if self.tree.get_node_by_label("certificate").is_none() || !self.tree.get_node_by_label("certificate").unwrap().tainted {
            return;
        }
        let data = self.tree.encode_node(&self.tree.get_node_by_label("certificate").unwrap());
        let sig = self.parent_key.sign(&data).to_vec();
        let mut sig_bits: Vec<u8> = vec![0];
        sig_bits.extend(sig);

        if !self.tree.node_manipulated_by_label("certificateSignature") {
            self.tree.set_data_by_label("certificateSignature", sig_bits, true);
        }
    }

    pub fn fix_fields(&mut self, all_fields: bool, hashlist: Option<Vec<u8>>) {
        // self.tree.fix_sizes(false);
        if self.op_type == OpType::MFT && hashlist.is_some() {
            self.fix_hash_list(hashlist.unwrap());
            self.tree.fix_sizes(true);
        }

        if self.op_type == OpType::MFT && all_fields {
            self.fix_mft_validity();
            self.tree.fix_sizes(true);
        }

        if self.op_type == OpType::ROA || self.op_type == OpType::MFT || self.op_type == OpType::ASPA || self.op_type == OpType::GBR {
            self.fix_digest();
        }

        // This is only necessary in initial run
        if all_fields {
            self.fix_aki();
            self.fix_validty();
            self.fix_names();

            if self.op_type != OpType::CRL {
                self.fix_ski();
                self.fix_sid();
                self.fix_crl_location();
                self.fix_subject_key();
            }

            if self.op_type == OpType::ROA || self.op_type == OpType::MFT || self.op_type == OpType::ASPA || self.op_type == OpType::GBR {
                self.fix_signed_object_location();
            } else if self.op_type == OpType::CERTCA || self.op_type == OpType::CERTEE {
                self.fix_ca_repository();
                self.fix_notification_uri();
                self.fix_manifest_uri();
            }
        }
        // After potentially changing some fields -> Fix their sizes
        self.tree.fix_sizes(true);

        self.fix_signer_signature(all_fields);

        self.fix_certificate_signature();

        self.tree.remove_taint();
    }

    pub fn fix_hash_list(&mut self, hashlist: Vec<u8>) {
        if self.op_type != OpType::MFT {
            println!("ERROR: Fixing Hash List only necessary in Manifest");
        }

        self.tree.set_data_by_label("manifestHashes", hashlist, true);
    }

    pub fn get_hash(&self) -> Vec<u8> {
        let data = self.tree.encode();
        let hash = sha256::digest(&*data);
        let hash = <[u8; 32]>::from_hex(hash).unwrap().to_vec();

        hash
    }

    pub fn get_name_and_hash(&self) -> (String, Vec<u8>) {
        let hash = self.get_hash();
        let name = self.name.clone();
        (name, hash)
    }

    pub fn asn1_name_and_hash(&self) -> TLV {
        let name_tlv = TLV::new(22, self.name.as_bytes().to_vec());

        let hash_v = self.get_hash();

        let mut bs = vec![0];
        bs.extend(hash_v);

        let hash_tlv = TLV::new(3, bs);

        let seq = Sequence::new(vec![name_tlv, hash_tlv]);
        TLV::new(48, seq.data)
    }
}
