use std::{fs, time::Instant};

use crate::{
    generation_interface::OpType,
    publication_point::repository::{self, KeyAndSigner, RepoConfig},
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
use sha1::Digest;
use sha1::Sha1;

// An entire PP
pub struct FuzzingPP {
    pub repositories: Vec<FuzzingRepository>,
}

pub struct RepoInfo {
    pub amount_objects: u16,
    pub ca_index: u16,
}

impl RepoInfo {
    pub fn new(amount_objects: u16, ca_index: u16) -> Self {
        Self { amount_objects, ca_index }
    }

    pub fn default() -> Self {
        Self {
            amount_objects: 102,
            ca_index: 0,
        }
    }
}

pub struct FuzzingRepository {
    pub payloads: Vec<FuzzingObject>,
    pub manifest: FuzzingObject,
    pub crl: FuzzingObject,
    pub conf: RepoConfig,
    pub certificate: FuzzingObject,
    pub repo_info: RepoInfo,
}

impl FuzzingRepository {
    pub fn new(
        payloads: Vec<FuzzingObject>,
        manifest: FuzzingObject,
        crl: FuzzingObject,
        conf: RepoConfig,
        certificate: FuzzingObject,
        repo_info: RepoInfo,
    ) -> Self {
        Self {
            payloads,
            manifest,
            crl,
            conf,
            certificate,
            repo_info,
        }
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

    pub fn mutate_objects(&mut self, amount: u16) {
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
}

pub struct FuzzingObject {
    pub op_type: OpType,
    pub parent_key: KeyAndSigner,
    pub child_key: KeyAndSigner,
    pub tree: Tree,
    pub conf: repository::RepoConfig,
    pub name: String,
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
        println!("Mutation: {:?}", self.tree.mutations);

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

    pub fn fix_singed_attributes(&mut self) {}

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

            if self.op_type == OpType::MFT {}
            if self.op_type != OpType::CRL {
                self.fix_ski();
                self.fix_names();
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
