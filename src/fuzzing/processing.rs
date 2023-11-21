use std::{
    fs::{self, read_dir},
    os::unix::net::{UnixListener, UnixStream},
    str::FromStr,
    thread,
    time::Duration,
};

use crate::{
    asn1p,
    process_util::{self, ObjectFactory, SerializableObject},
    publication_point::{
        fuzzing_interface,
        repository::{self, after_roas_creation, RepoConfig},
    },
    util,
    vrps_analysis::extend_signed_attr,
    FuzzConfig,
};
use crate::{
    fuzzing_loop,
    publication_point::repository::{create_notification, KeyAndSigner},
};
use crate::{generation_interface::OpType, publication_point::repository::create_current_snapshot};
use crate::{process_util::GenerationBatch, publication_point::repository::get_current_session_notification};
use crate::{process_util::ObjectInfo, publication_point::repository::write_notification_file};
use bcder::{
    encode::{self, PrimitiveContent, Values},
    Captured, Mode,
};
use bytes::Bytes;
use openssl::pkey::{PKey, Private};
use rpki::{
    repository::{
        aspa::{Aspa, AspaBuilder, ProviderAs},
        cert::{KeyUsage, Overclaim, TbsCert},
        crypto::{softsigner::OpenSslSigner, PublicKey, PublicKeyFormat, Signer},
        resources::{Asn, Prefix},
        sigobj::SignedObjectBuilder,
        tal::TalInfo,
        x509::Validity,
    },
    uri,
};

use hex::FromHex;

use super::{cert, crl};

pub fn serialize_data(data: &SerializableObject) -> String {
    serde_json::to_string(data).unwrap()
}

pub fn read_serialized_data(factory: &mut ObjectFactory) -> Option<SerializableObject> {
    let sobj = factory.get_object();
    return None;
    //return sobj;
}

pub fn move_files_data(folder: String, filepaths: &Vec<String>, dont_move: bool) {
    if dont_move {
        return;
    }

    for filepath in filepaths {
        let p = folder.clone() + &filepath;
        fs::remove_file(p).unwrap();
    }
}

pub fn after_crl_creation(conf: &RepoConfig) {
    repository::make_manifest("ta", "root", conf);

    repository::add_roa_str(
        &(conf.DEFAULT_IPSPACE_FIRST_OCTET.to_string() + "." + &conf.DEFAULT_IPSPACE_SEC_OCTET.to_string() + ".0.0/24 => 22222"),
        true,
        conf,
    );

    fs::remove_dir_all(&conf.BASE_RRDP_DIR_l);
    let (session_id, serial_number) = get_current_session_notification(conf);

    let (snapshot, snapshot_uri) = create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);
    let notification = create_notification(snapshot_bytes, vec![], &snapshot_uri, 5, session_id, serial_number, conf);
    write_notification_file(notification, conf).unwrap();
}

pub fn handle_serialized_object(data: SerializableObject, conf: &RepoConfig, obj_type: &str) {
    handle_serialized_object_inner(conf, data, obj_type, 0);
}

pub fn handle_serialized_object_inner(conf: &RepoConfig, data: SerializableObject, obj_type: &str, start_index: u16) {
    let mut filenames = vec![];
    let mut objects = vec![];
    let mut index = 0;

    let mfts = data.mfts.unwrap_or(vec![]);
    let roas = data.roas.unwrap_or(vec![]);
    let crls = data.crls.unwrap_or(vec![]);
    let roa_names = data.roa_names.unwrap_or(vec![]);

    for i in 0..data.contents.len() {
        let byte = Bytes::from(data.contents[i].clone());
        let ca_name = "ca".to_string() + &(index + start_index).to_string();

        let filename;
        let ca;

        if obj_type == "cert" {
            filename = ca_name.clone() + ".cer";
            ca = "ta";
        } else if obj_type == "crl" || obj_type == "mft" {
            filename = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";
            ca = &ca_name.as_str();
        } else {
            filename = util::random_file_name();
            ca = "newca";
        }

        repository::write_object_to_disc(&byte, obj_type, &filename, ca, conf);

        filenames.push(data.filenames[i].clone());
        objects.push(byte.clone());

        if obj_type == "crl" {
            let byte_mft = Bytes::from(mfts[i].clone());
            let byte_roa = Bytes::from(roas[i].clone());
            let name_roa = roa_names[i].clone();

            let ca_name = "ca".to_string() + &(index + start_index).to_string();
            index += 1;

            let key_uri = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";

            repository::write_object_to_disc(&byte_mft, "mft", &key_uri, &ca_name, conf);
            repository::write_object_to_disc(&byte_roa, "", &name_roa, &ca_name, conf);
        } else if obj_type == "cert" {
            let ca_name = "ca".to_string() + &(index + start_index).to_string();
            index += 1;

            let key_uri = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";

            let byte_mft = Bytes::from(mfts[i].clone());
            let byte_roa = Bytes::from(roas[i].clone());
            let name_roa = roa_names[i].clone();
            let byte_crl = Bytes::from(crls[i].clone());

            repository::write_object_to_disc(&byte_mft, "mft", &key_uri, &ca_name, conf);
            repository::write_object_to_disc(&byte_crl, "crl", &key_uri, &ca_name, conf);

            repository::write_object_to_disc(&byte_roa, "", &name_roa, &ca_name, conf);
        }
    }

    if obj_type == "crl" || obj_type == "cert" {
        after_crl_creation(conf);
    } else {
        // This function also does all the after-creation-generation (generating mft etc.)
        repository::add_roa_str(
            &(conf.IPv4[0].addr().to_string() + "/" + &conf.IPv4[0].prefix_len().to_string() + " => 22222"),
            true,
            conf,
        );
    }
}

pub fn create_aux_objects(
    conf: &FuzzConfig,
) -> (
    Option<Vec<(Bytes, String)>>,
    Option<Vec<(Bytes, String)>>,
    Option<Vec<(Bytes, String)>>,
) {
    let (roas, crls, mfts);
    if conf.typ == OpType::CRL || conf.typ == OpType::MFT {
        let (cert_keys, _) = util::create_cas(conf.amount.into(), vec![&conf.repo_conf], None);
        roas = Some(util::create_example_roas(conf.amount.into()));
        mfts = None;
        crls = None;
    } else if conf.typ == OpType::CERTCA {
        let (cert_keys, _) = util::create_cas(conf.amount.into(), vec![&conf.repo_conf], None);

        let roas_i = util::create_example_roas(conf.amount.into());
        let crls_i = util::create_example_crls(&cert_keys, conf.amount.into(), &conf.repo_conf);
        let mfts_i = util::create_example_mfts(&cert_keys, conf.amount.into(), &roas_i, &crls_i, &conf.repo_conf);

        roas = Some(roas_i);
        mfts = Some(mfts_i);
        crls = Some(crls_i);
    } else {
        roas = None;
        mfts = None;
        crls = None;
    }

    (roas, crls, mfts)
}

pub fn srun(mut conf: FuzzConfig) {
    for i in 0..conf.amount {
        let ca_name = "ca".to_string() + &i.to_string();
        conf.repo_conf.CA_TREE.insert(ca_name, "ta".to_string());
    }

    let repo_config = &conf.repo_conf.clone();

    let typ = &conf.typ.to_string();

    let mut factory = ObjectFactory::new(50, "/tmp/sock");

    let (roas, crls, mfts) = create_aux_objects(&conf);

    let socket = "/tmp/gensock".to_string() + &conf.id.to_string();
    fs::remove_file(&socket).unwrap_or_default();

    let stream = UnixListener::bind(&socket).unwrap();
    stream.set_nonblocking(true).unwrap();

    fuzzing_loop::send_single_object(&conf.uri);

    create_objects(true, conf, roas, crls, mfts, &stream);

    let data = read_serialized_data(&mut factory);

    if data.is_none() {
        return;
    }

    let data = data.unwrap();

    handle_serialized_object(data, repo_config, typ);
}

pub fn create_objects(
    oneshot: bool,
    conf: FuzzConfig,
    roas: Option<Vec<(Bytes, String)>>,
    crls: Option<Vec<(Bytes, String)>>,
    mfts: Option<Vec<(Bytes, String)>>,
    stream: &UnixListener,
) {
    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf.repo_conf, conf.amount.into(), false);
    let cert_keys;
    let tmp;
    if conf.typ == OpType::CRL || conf.typ == OpType::CERTCA {
        tmp = util::create_cas(conf.amount.into(), vec![&conf.repo_conf], None).0;
        cert_keys = Some(&tmp);
    } else {
        cert_keys = None;
    }
    let dont_move = conf.dont_move;
    let uri = conf.uri.clone();

    loop {
        let data = generate_from_files_plain(
            &conf,
            conf.amount.into(),
            priv_keys.clone(),
            pub_keys.clone(),
            &cert_keys,
            &roas,
            &crls,
            &mfts,
            &stream,
        );

        if data.is_none() {
            continue;
        }

        let data = data.unwrap();

        let serialized = serialize_data(&data);
        process_util::send_new_data(serialized);

        if oneshot {
            return;
        }

        // move_files_data(uri.clone(), &data.filenames, dont_move);

        while process_util::is_stopped() {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn sign_signed_object(data: &Bytes, conf: &RepoConfig, ca_name: &str) -> Vec<u8> {
    let obj = asn1::parse_single::<asn1p::ContentInfoSpec>(&data);

    if obj.is_err() {
        return data.to_vec();
    }
    let mut obj = obj.unwrap();

    let mut content = obj.content.unwrap();

    // Handle SignerInfos

    // TODO Change for other objects
    let signer = repository::read_cert_key(&(conf.BASE_l.clone() + "fuzzing_keys/" + ca_name + "_roa"));

    let si_raw = asn1::write_single(&content.signerInfos).unwrap();
    let si_set = asn1::parse_single::<asn1::SetOf<asn1p::SignerInfos>>(&si_raw);
    if si_set.is_err() {
        return data.to_vec();
    }
    let si_set = si_set.unwrap();
    let si_vec: Vec<asn1p::SignerInfos> = si_set.into_iter().collect();
    let mut si = si_vec[0].clone();
    let tmp = asn1::write_single(&content.encapContentInfo.eContent.unwrap()).unwrap();
    let l;
    if (tmp[1] >> 7) & 1 != 0 {
        // More than 1 length byte
        l = 2 + (tmp[1] & 0x7F) as usize;
    } else {
        l = 2;
    }
    // Need to cut away the size value for the octetstring
    let raw_content: &[u8] = &tmp[l..];
    let d = sha256::digest(raw_content);

    let u = <[u8; 32]>::from_hex(d).unwrap();

    let dig: &[u8] = &Bytes::from(u.to_vec());
    let v = asn1::SetOfWriter::new(vec![dig]);
    let tmp = asn1::write_single(&v).unwrap();
    let tl = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();

    let pk: &[u8] = &signer
        .get_pub_key()
        .key_identifier()
        .encode_ref()
        .to_captured(Mode::Der)
        .into_bytes()[2..];
    si.sid = Some(pk);

    let mut sigattr = vec![];
    for attr in si.signedAttrs.unwrap() {
        // Message Digest
        if attr.contentType.to_string() == "1.2.840.113549.1.9.4" {
            let new_attr = asn1p::SignedAttribute {
                contentType: attr.contentType,
                value: tl,
            };
            sigattr.push(new_attr);
        } else {
            sigattr.push(attr);
        }
    }

    let sw = asn1::SequenceOfWriter::new(sigattr);
    let sa_raw = asn1::write_single(&sw).unwrap();
    let seq = asn1::parse_single::<asn1::SequenceOf<asn1p::SignedAttribute>>(&sa_raw);

    si.signedAttrs = Some(seq.unwrap());

    // Signature in SignedAttributes
    // This is necessary because the RPKI is weird
    let sig: &[u8] = &signer.sign(&extend_signed_attr(&sa_raw[2..].to_vec()));
    let tmp = asn1::write_single(&sig).unwrap();
    let tl = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();
    si.signature = tl;

    let sw = asn1::SetOfWriter::new(vec![si]);
    let tmp = asn1::write_single(&sw).unwrap();
    let si = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();

    content.signerInfos = si;

    obj.content = Some(content);

    let new_bytes = asn1::write_single(&obj).unwrap();

    new_bytes
}

pub fn generate_from_files_plain_inner(
    obj: Vec<(Vec<u8>, ObjectInfo)>,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    ca_keys: &Option<&Vec<KeyAndSigner>>,
    conf: &FuzzConfig,
    roass: &Option<Vec<(Bytes, String)>>,
    crlss: &Option<Vec<(Bytes, String)>>,
    mftss: &Option<Vec<(Bytes, String)>>,
    id: u64,
) -> SerializableObject {
    let mut filenames = vec![];
    let mut contents = vec![];
    let mut crls = vec![];
    let mut mfts = vec![];
    let mut roas = vec![];
    let mut roa_names = vec![];

    let roass = roass.clone().unwrap_or(vec![]);
    let crlss = crlss.clone().unwrap_or(vec![]);
    let mftss = mftss.clone().unwrap_or(vec![]);

    let key_uri = conf.repo_conf.BASE_KEY_DIR_l.clone() + "newca" + ".der";

    let ks = repository::read_cert_key(&key_uri);
    let parent_key = repository::read_cert_key(&(conf.repo_conf.BASE_KEY_DIR_l.clone() + "ta.der"));

    let tmp = vec![];
    let ca_keys = ca_keys.unwrap_or(&tmp);

    for i in 0..obj.len() {
        if conf.typ == OpType::ROA || conf.typ == OpType::MFT || conf.typ == OpType::GBR || conf.typ == OpType::ASPA {
            let a = &obj[i];
            let e_content;
            let mut use_raw = conf.raw;

            // Allows to test objects that already have an EE-Cert by extracting the E-Content
            if conf.no_ee {
                let tmp = asn1p::extract_e_content(Bytes::from(a.0.clone()), Some(&conf.typ.to_string()));
                if tmp.is_none() {
                    e_content = Bytes::from_static(b"\x00\x00");
                    use_raw = true;
                } else {
                    e_content = Bytes::from(tmp.unwrap());
                }
            } else {
                e_content = a.0.clone().into();
            }

            let re;
            if use_raw {
                let s = sign_signed_object(&e_content, &conf.repo_conf, &a.1.ca_index.to_string());
                re = s;
            } else {
                re = fuzzing_interface::generate_signed_data_from_bytes(
                    e_content,
                    &conf.repo_conf,
                    &conf.typ.to_string(),
                    &a.1.filename,
                    true,
                    i.try_into().unwrap(),
                    &ks,
                    priv_keys[i].clone(),
                    pub_keys[i].clone(),
                    "newca",
                    None,
                )
                .to_vec();
            }
            filenames.push(a.1.filename.clone());
            contents.push(re);
        } else if conf.typ == OpType::CRL {
            let ca_name = "ca".to_string() + &i.to_string();

            let a = &obj.clone()[i];

            let re = crl::parse_and_sign(a.0.clone().into(), &ca_keys[i]);

            let mft = util::create_manifest(
                &conf.repo_conf,
                &ca_name,
                &a.1.filename,
                priv_keys[i].clone(),
                pub_keys[i].clone(),
                &ca_keys[i],
                i.try_into().unwrap(),
                re.clone().into(),
                roass[i].clone(),
            );

            filenames.push(a.1.filename.clone());
            contents.push(re.to_vec());
            mfts.push(mft.to_vec().clone());
            roas.push(roass[i].0.to_vec().clone());
            roa_names.push(roass[i].1.clone());
        } else {
            let ca_name = "ca".to_string() + &i.to_string();

            let a = &obj.clone()[i];

            let (re, _) = cert::parse_and_sign(
                a.0.clone().into(),
                &parent_key,
                &conf.repo_conf,
                &ca_keys[i].get_pub_key(),
                &ca_name,
                None,
                None,
                false,
            );

            filenames.push(a.1.filename.clone());
            contents.push(re.to_vec());
            crls.push(crlss[i].0.to_vec().clone());
            mfts.push(mftss[i].0.to_vec().clone());
            roas.push(roass[i].0.to_vec().clone());
            roa_names.push(roass[i].1.clone());
        }
    }
    let ret;
    if conf.typ == OpType::CRL {
        ret = SerializableObject {
            filenames,
            contents,
            crls: None,
            mfts: Some(mfts),
            roas: Some(roas),
            roa_names: Some(roa_names),
            id,
        };
    } else if conf.typ == OpType::CERTCA {
        ret = SerializableObject {
            filenames,
            contents,
            crls: Some(crls),
            mfts: Some(mfts),
            roas: Some(roas),
            roa_names: Some(roa_names),
            id,
        };
    } else {
        ret = SerializableObject {
            filenames,
            contents,
            roas: None,
            crls: None,
            mfts: None,
            roa_names: None,
            id,
        };
    }

    ret
}

pub fn read_objects(stream: &UnixListener) -> Option<GenerationBatch> {
    process_util::get_batch(stream)
}

pub fn generate_from_files_plain(
    conf: &FuzzConfig,
    amount: u32,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    ca_keys: &Option<&Vec<KeyAndSigner>>,
    roas: &Option<Vec<(Bytes, String)>>,
    crls: &Option<Vec<(Bytes, String)>>,
    mfts: &Option<Vec<(Bytes, String)>>,
    stream: &UnixListener,
) -> Option<SerializableObject> {
    // let obj = util::read_files_from_folder(&conf.uri, amount);

    let batch = read_objects(stream);
    if batch.is_none() {
        thread::sleep(Duration::from_millis(100));
        return None;
    }

    let batch = batch.unwrap();

    let ret = generate_from_files_plain_inner(batch.contents, priv_keys, pub_keys, ca_keys, &conf, roas, crls, mfts, batch.id);

    process_util::acknowledge(conf.id, batch.id);

    Some(ret)
}
