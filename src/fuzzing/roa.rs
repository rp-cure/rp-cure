use std::{
    fs::{self, read_dir},
    str::FromStr,
    thread,
    time::Duration,
};

use crate::{
    process_util::{self, ObjectFactory},
    publication_point::{
        fuzzing_interface,
        repository::{self, after_roas_creation, RepoConfig},
    },
    FuzzConfig,
};
use bcder::{
    encode::{self, Values},
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

use crate::{asn1p, consts, util};

pub fn encode_aspa(providers: Vec<ProviderAs>, customer: Asn) -> Bytes {
    let provider_as_set_captured = Captured::from_values(
        Mode::Der,
        encode::sequence(encode::slice(providers.as_slice(), |prov| prov.encode())),
    );

    let s = encode::sequence((customer.encode(), &provider_as_set_captured));

    s.to_captured(Mode::Der).into_bytes()
}

fn make_aspa(customer_as: Asn, mut providers: Vec<ProviderAs>) -> Aspa {
    let signer = OpenSslSigner::new();

    let issuer_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
    let issuer_uri = uri::Rsync::from_str("rsync://example.com/parent/ca.cer").unwrap();
    let crl_uri = uri::Rsync::from_str("rsync://example.com/ca/ca.crl").unwrap();
    let asa_uri = uri::Rsync::from_str("rsync://example.com/ca/asa.asa").unwrap();

    let issuer_cert = {
        let repo_uri = uri::Rsync::from_str("rsync://example.com/ca/").unwrap();
        let mft_uri = uri::Rsync::from_str("rsync://example.com/ca/ca.mft").unwrap();

        let pubkey = signer.get_key_info(&issuer_key).unwrap();

        let mut cert = TbsCert::new(
            12u64.into(),
            pubkey.to_subject_name(),
            Validity::from_secs(86400),
            None,
            pubkey,
            KeyUsage::Ca,
            Overclaim::Refuse,
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(repo_uri));
        cert.set_rpki_manifest(Some(mft_uri));
        cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
        let cert = cert.into_cert(&signer, &issuer_key).unwrap();

        cert.validate_ta(TalInfo::from_name("foo".into()).into_arc(), true).unwrap()
    };

    let mut aspa = AspaBuilder::empty(customer_as);
    for provider in &providers {
        aspa.add_provider(*provider).unwrap();
    }
    let aspa = aspa
        .finalize(
            SignedObjectBuilder::new(123_u64.into(), Validity::from_secs(86400), crl_uri, issuer_uri, asa_uri),
            &signer,
            &issuer_key,
        )
        .unwrap();
    let encoded = aspa.to_captured();
    let decoded = Aspa::decode(encoded.as_slice(), true).unwrap();

    assert_eq!(encoded.as_slice(), decoded.to_captured().as_slice());

    let (_, attestation) = decoded.process(&issuer_cert, true, |_| Ok(())).unwrap();

    aspa
}

fn create_aspa() {
    let asn = Asn::from_u32(5);
    let providers: Vec<ProviderAs> = vec![
        ProviderAs::new_v4(2.into()),
        ProviderAs::new(3.into()),
        ProviderAs::new_v6(4.into()),
    ];
    let b = encode_aspa(providers, asn);
    fs::write("./aspa_examples/example2.asa", &b);
    return;
    // let aspa = make_aspa(asn, providers);
    // fs::write("example.asa", aspa.encode_ref().to_captured(Mode::Der).into_bytes()).unwrap();
}

pub fn handle_serialized_object_new(factory: ObjectFactory, conf: &RepoConfig, obj_type: &str) {
    let data = util::read_serialized_data_new(factory);

    if data.is_empty() {
        return;
    }

    handle_serialized_object_inner(conf, data, obj_type);
}

pub fn handle_serialized_object(path: &str, conf: &RepoConfig, index: u32, _: Option<Vec<(Bytes, String)>>, obj_type: &str) {
    let data = util::read_serialized_data(path);

    // If data is empty -> Skip this file
    if data.is_empty() {
        return;
    }
    handle_serialized_object_inner(conf, data, obj_type);
}

pub fn handle_serialized_object_inner(conf: &RepoConfig, data: Vec<(String, Vec<u8>)>, obj_type: &str) {
    let mut filenames = vec![];
    let mut objects = vec![];

    for date in data {
        let byte = Bytes::from(date.1);
        filenames.push(date.0.clone());
        objects.push(byte.clone());

        let random_s = util::random_file_name();
        repository::write_object_to_disc(&byte, obj_type, &random_s, "newca", conf);
    }
    repository::add_roa_str(
        &(conf.IPv4[0].addr().to_string() + "/" + &conf.IPv4[0].prefix_len().to_string() + " => 22222"),
        true,
        conf,
    );
    after_roas_creation(filenames, objects, "ta", conf, true);
}

pub fn srun(conf: FuzzConfig) {
    let repo_config = &conf.repo_conf.clone();

    let typ = &conf.typ.to_string();
    let total_amount = conf.amount;

    let factory = ObjectFactory::new(total_amount);
    create_objects(true, conf);

    handle_serialized_object_new(factory, repo_config, typ);
}

pub fn create_objects(oneshot: bool, conf: FuzzConfig) {
    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf.repo_conf, conf.amount.into(), false);
    let dont_move = conf.dont_move;
    let uri = conf.uri.clone();

    loop {
        let data = generate_from_files_plain(&conf, conf.amount.into(), priv_keys.clone(), pub_keys.clone());

        if data.is_empty() {
            return;
        }

        let serialized = util::serialize_data_new(&data);
        process_util::send_new_data(serialized);

        if oneshot {
            return;
        }

        util::move_files_data(uri.clone(), &data, dont_move);

        while process_util::is_stopped() {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn generate_from_files_plain_inner(
    obj: Vec<(String, Bytes)>,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    conf: &FuzzConfig,
) -> Vec<(String, Vec<u8>)> {
    let mut objects = vec![];

    let key_uri = conf.repo_conf.BASE_KEY_DIR_l.clone() + "newca" + ".der";

    let ks = repository::read_cert_key(&key_uri);
    let l = obj.len();
    for i in 0..l {
        let a = &obj[i];
        let e_content;
        let mut use_raw = false;

        // Allows to test objects that already have an EE-Cert by extracting the E-Content
        if conf.no_ee {
            let tmp = asn1p::extract_e_content(Bytes::from(a.1.clone()), Some(&conf.typ.to_string()));
            if tmp.is_none() {
                e_content = Bytes::from_static(b"\x00\x00");
                use_raw = true;
            } else {
                e_content = Bytes::from(tmp.unwrap());
            }
        } else {
            e_content = a.1.clone();
        }

        let re;
        if use_raw {
            re = e_content;
        } else {
            re = fuzzing_interface::generate_signed_data_from_bytes(
                e_content,
                &conf.repo_conf,
                &conf.typ.to_string(),
                &a.0,
                true,
                i.try_into().unwrap(),
                &ks,
                priv_keys[i].clone(),
                pub_keys[i].clone(),
                "newca",
                None,
            );
        }

        objects.push((a.0.clone(), re.to_vec()));
    }
    objects
}

pub fn generate_from_files_plain(
    conf: &FuzzConfig,
    amount: u32,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
) -> Vec<(String, Vec<u8>)> {
    let obj = util::read_files_from_folder(&conf.uri, amount);
    generate_from_files_plain_inner(obj, priv_keys, pub_keys, &conf)
}
