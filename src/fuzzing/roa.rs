use std::{thread, time::Duration, fs::{self, read_dir}, str::FromStr};

use bcder::{Mode, encode::{Values, self}, Captured};
use bytes::Bytes;
use openssl::pkey::{Private, PKey};
use rpki::{repository::{crypto::{PublicKey, PublicKeyFormat, softsigner::OpenSslSigner, Signer}, aspa::{ProviderAs, AspaBuilder, Aspa}, resources::{Asn, Prefix}, sigobj::SignedObjectBuilder, x509::Validity, tal::TalInfo, cert::{Overclaim, KeyUsage, TbsCert}}, uri};
use crate::publication_point::{repository::{RepoConfig, after_roas_creation, self}, fuzzing_interface};

use crate::{util, consts, asn1p};


pub fn encode_aspa(providers: Vec<ProviderAs>, customer: Asn) -> Bytes{
    let provider_as_set_captured = Captured::from_values(
        Mode::Der,
        encode::sequence(
            encode::slice(
                providers.as_slice(),
                |prov| prov.encode()
            )
        )
    );
    
    let s = encode::sequence((
        customer.encode(),
        &provider_as_set_captured,
    ));

    s.to_captured(Mode::Der).into_bytes()
}

fn make_aspa(
    customer_as: Asn,
    mut providers: Vec<ProviderAs>,
) -> Aspa {
    let signer = OpenSslSigner::new();

    let issuer_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
    let issuer_uri = uri::Rsync::from_str(
        "rsync://example.com/parent/ca.cer"
    ).unwrap();
    let crl_uri = uri::Rsync::from_str(
        "rsync://example.com/ca/ca.crl"
    ).unwrap();
    let asa_uri = uri::Rsync::from_str(
        "rsync://example.com/ca/asa.asa"
    ).unwrap();
    
    let issuer_cert = {
        let repo_uri = uri::Rsync::from_str(
            "rsync://example.com/ca/"
        ).unwrap();
        let mft_uri = uri::Rsync::from_str(
            "rsync://example.com/ca/ca.mft"
        ).unwrap();

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

        cert.validate_ta(
            TalInfo::from_name("foo".into()).into_arc(), true
        ).unwrap()

        
    };

    let mut aspa = AspaBuilder::empty(customer_as);
    for provider in &providers {
        aspa.add_provider(*provider).unwrap();
    }
    let aspa = aspa.finalize(
        SignedObjectBuilder::new(
            123_u64.into(),
            Validity::from_secs(86400),
            crl_uri, 
            issuer_uri,
            asa_uri
        ),
        &signer,
        &issuer_key
    ).unwrap();
    let encoded = aspa.to_captured();
    let decoded = Aspa::decode(encoded.as_slice(), true).unwrap();
    
    assert_eq!(encoded.as_slice(), decoded.to_captured().as_slice());
    
    let (_, attestation) = decoded.process(
        &issuer_cert, true, |_| Ok(())
    ).unwrap();
    
    aspa
}


fn create_aspa(){
    let asn = Asn::from_u32(5);
    let providers: Vec<ProviderAs> = vec![
        ProviderAs::new_v4(2.into()),
        ProviderAs::new(3.into()),
        ProviderAs::new_v6(4.into())
    ];
    let b = encode_aspa(providers, asn);
    fs::write("./aspa_examples/example2.asa", &b);
    return;
    // let aspa = make_aspa(asn, providers);
    // fs::write("example.asa", aspa.encode_ref().to_captured(Mode::Der).into_bytes()).unwrap();
}

/*
Create ROAs like object generation would create them to test behavior of the fuzzer
 */
pub fn create_test_roas() -> String{
    let mut v = vec![];
    for i in 0..10{
        let roa_string = "10.0.0.0/24 = ".to_string() + & i.to_string();
        let (roa_builder, _) = repository::process_roa_string(&roa_string).unwrap();
        let roa_bytes = roa_builder.to_attestation().encode_ref().to_captured(Mode::Der).into_bytes();
    
        
        v.push(("roa".to_string() + &i.to_string(), roa_bytes));
    
    }

    let cws = util::get_cwd() + "/";

    let conf = repository::create_default_config_abs(consts::domain.to_string(), cws.to_string(), "".to_string());

    let amount = v.len();

    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf, amount.try_into().unwrap(), true);

    let data = generate_from_files_plain_inner(v, conf, priv_keys, pub_keys, false, "roa");
    util::serialize_data(&data)

}


pub fn handle_serialized_object(path: &str, conf: &RepoConfig, index: u32, _: Option<Vec<(Bytes, String)>>, obj_type: &str) {
    let data = util::read_serialized_data(path);
    // If data is empty -> Skip this file
    if data.is_empty(){
        return;
    }
    handle_serialized_object_inner(conf, index, data, obj_type);
}

pub fn handle_serialized_object_inner(conf: &RepoConfig, _: u32, data: Vec<(String, Vec<u8>)>, obj_type: &str) {
    let mut filenames = vec![];
    let mut objects = vec![];

    for date in data {
        let byte = Bytes::from(date.1);
        filenames.push(date.0.clone());
        objects.push(byte.clone());

        let random_s = util::random_file_name();
        repository::write_object_to_disc(&byte, obj_type, &random_s, "newca", conf);
    }
    // repository::add_roa_str("10.0.0.0/24 => 11111", true, conf);
    repository::add_roa_str(&(conf.IPv4[0].addr().to_string() + "/" + &conf.IPv4[0].prefix_len().to_string() + " => 22222"), true, conf);
    // repository::add_roa_str("185.157.45.0/24 => 1337", true, conf);
    // repository::add_roa_str("89.23.72.0/23 => 28964", true, conf);


    // fs::remove_file(path).unwrap();
    thread::sleep(Duration::from_millis(10));
    after_roas_creation(filenames, objects, "ta", conf, true);
}


pub fn do_both(obj_folder: &str, no_ee: bool, obj_type: &str, conf: &RepoConfig) {
    let cws = util::get_cwd() + "/";
    let folder;
    if obj_folder.starts_with("/"){
        folder = obj_folder.to_string();
    }
    else{
        folder = cws.clone() + obj_folder;
    }
    let obj_folder = cws + "obj_cache/";
    let amount;
    if fs::metadata(folder.clone()).is_ok() && fs::metadata(folder.clone()).unwrap().is_file(){
        amount = 1;
    }
    else{
        amount = read_dir(folder.clone()).unwrap().count();
    }

    fs::remove_dir_all(obj_folder.clone());
    fs::create_dir_all(obj_folder.clone());

    create_objects(folder.clone(), 2, true, true, amount.try_into().unwrap(), no_ee, obj_type, conf);
    let paths = read_dir(obj_folder.clone()).unwrap();
    for path in paths {
        let p = path.unwrap().path();
        let file_name = p.to_str().unwrap();
        //util::clear_repo(&conf);

        handle_serialized_object(file_name, &conf, 1, None, obj_type);
        break;
    }
}


pub fn create_objects(folder: String, max_file_amount: u16, dont_move: bool, oneshot: bool, amount: u32, no_ee: bool, obj_type: &str, conf: &RepoConfig) {
    let cws = util::get_cwd() + "/";

    // let amount = 10000;

    let (priv_keys, pub_keys) = fuzzing_interface::load_ee_ks(&conf, amount, false);

    let output_folder = cws + "obj_cache/";
    let mut c = 0;
    loop {
        c += 1;
        let data = generate_from_files_plain(&folder, conf.clone(), amount, priv_keys.clone(), pub_keys.clone(), no_ee, obj_type);
        if data.len() == 0 {
            println!("No more Objects in Folder {} - Exiting Process", folder);
            return;
        }

        util::serialize_data(&data);

        util::move_files_data(folder.clone(), &data, dont_move);
        // if c == 5{
        //     return;
        // }
        if oneshot{
            return;
        }

        // If folder is sufficiently full -> Wait
        while util::fileamount_in_folder(&output_folder) >= max_file_amount.into() {
            thread::sleep(Duration::from_millis(100));
        }
    }
}


pub fn generate_from_files_plain_inner(
    obj: Vec<(String, Bytes)>,
    conf: RepoConfig,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    no_ee: bool,
    obj_type: &str
) -> Vec<(String, Vec<u8>)> {
    let mut objects = vec![];

    let key_uri = conf.BASE_KEY_DIR_l.clone() + "newca" + ".der";

    let ks = repository::read_cert_key(&key_uri);
    let l = obj.len();
    for i in 0..l {
        let a = &obj[i];
        let e_content;
        let mut use_raw = false;

        // Allows to test objects that already have an EE-Cert by extracting the E-Content
        if no_ee{
            let tmp = asn1p::extract_e_content(Bytes::from(a.1.clone()), Some(obj_type));
            if tmp.is_none(){
                e_content = Bytes::from_static(b"\x00\x00");
                use_raw = true;
            }
            else{
                e_content = Bytes::from(tmp.unwrap());
            }
        }
        else{
            e_content = a.1.clone();
        }
        
        let re;
        if use_raw{
            re = e_content;
        }
        else{
            re = fuzzing_interface::generate_signed_data_from_bytes(
                e_content,
                &conf,
                obj_type,
                &a.0,
                true,
                i.try_into().unwrap(),
                &ks,
                priv_keys[i].clone(),
                pub_keys[i].clone(),
                "newca",
                None
            );
        }

        // if i % 100 == 0{
        //     println!("Processed {} objects", i);
        // }
        objects.push((a.0.clone(), re.to_vec()));
        
        
    }
    objects
}

pub fn generate_from_files_plain(
    folder: &str,
    conf: RepoConfig,
    amount: u32,
    priv_keys: Vec<PKey<Private>>,
    pub_keys: Vec<PublicKey>,
    no_ee: bool,
    obj_type: &str
) -> Vec<(String, Vec<u8>)> {
    let obj = util::read_files_from_folder(folder, amount);
    generate_from_files_plain_inner(obj, conf, priv_keys, pub_keys, no_ee, obj_type)
}
