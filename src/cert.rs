use asn1::{self, BitString, SequenceOf, GeneralizedTime, OctetStringEncoded};
use bcder::{Mode, OctetString};
use bcder::encode::{Values, PrimitiveContent};
use bytes::Bytes;
use chrono::{DateTime, Utc, Local, Duration};
use hex::ToHex;
use openssl::pkey::{PKey, Private};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rpki_testing::repository;
use rpki::repository::crypto::PublicKey;
use rpki_testing::fuzzing_interface;
use rpki_testing::repository::{RepoConfig};
use rpki_testing::repository::KeyAndSigner;
use serde_json::value;
use std::collections::HashMap;
use std::fs::read_dir;
use std::{fs, thread};
use rpki_testing::fuzzing_interface::load_ee_ks;
use hex::FromHex;

use crate::{mft, util, asn1p, consts};

// fn generate_aki_bytes(signer: &KeyAndSigner){
//     let kid = signer.get_pub_key().key_identifier().to_string();
//     let issuer_bytes = asn1::write_single(&x).unwrap();

//     let a = asn1::parse_single::<asn1::Tlv>(&issuer_bytes).unwrap();
//     let tuv = TypeAndValue{
//         attrType: asn1::ObjectIdentifier::from_string("2.5.4.3").unwrap(),
//         attrValue: a,
//     };

//     let a = signer.get_pub_key().key_identifier().to_encoded_bytes(Mode::Der);

//     let con = AKIContent{
//         keyIdentifier: Some(&a),
//         authorityCertIssuer: None,
//         authorityCertSerialNumber: None,
//     };

//     let b = asn1::write_single(&con).unwrap();

//     let t = asn1::parse_single::<asn1::Tlv>(&b).unwrap();
//     let octetstr = asn1::OctetStringEncoded::new(t);
//     let issuer_bytes = asn1::write_single(&octetstr).unwrap();

//     let a = asn1::parse_single::<asn1::Tlv>(&issuer_bytes).unwrap();

// }


fn handle_subjectKeyIdentifier(raw_bytes: Vec<u8>, key_identifier: Bytes) -> Vec<u8>{
    // let res = asn1::parse_single::<asn1p::TypeAndValue>(&raw_bytes);
    // if res.is_err(){
    //     return raw_bytes;
    // }
    // let val = res.unwrap();
    let atype = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    let t = asn1::write_single(&atype).unwrap();
    let atype = asn1::parse_single::<asn1::Tlv>(&t).unwrap();


    let a: &[u8] = &key_identifier.to_vec();
    let octetstr = asn1::OctetStringEncoded::new(a);
    let issuer_bytes = asn1::write_single(&octetstr).unwrap();



    let a = asn1::parse_single::<asn1::Tlv>(&issuer_bytes).unwrap();
    let tuv = asn1p::TypeAndValue{
        attrType: atype,
        attrValue: a,
    };
    let r = asn1::write_single(&tuv).unwrap();
    r
}


fn handle_authorityKeyIdentifier(key_identifier: Bytes) -> Vec<u8>{

    let atype = asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap();
    let t = asn1::write_single(&atype).unwrap();
    let atype = asn1::parse_single::<asn1::Tlv>(&t).unwrap();

    let a: &[u8] = &key_identifier.to_vec();
    let b = asn1p::AuthorityKeyIdentifier{keyIdentifier: Some(a)};


    let octetstr = asn1::OctetStringEncoded::new(b);
    let issuer_bytes = asn1::write_single(&octetstr).unwrap();



    let a = asn1::parse_single::<asn1::Tlv>(&issuer_bytes).unwrap();
    let tuv = asn1p::TypeAndValue{
        attrType: atype,
        attrValue: a,
    };
    let r = asn1::write_single(&tuv).unwrap();
    r
}


fn handle_subjectInfoAcces(raw_bytes: Vec<u8>, ca_name: &str, conf: &RepoConfig, own_uri: Option<&str>, is_ee: bool) -> Vec<u8>{
    let base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR.clone() + ca_name + "/";
    // let parent_crl_uri = conf.BASE_REPO_DIR_l.clone() + "/" + &conf.CA_TREE[ca_name] + "/" + parent_finger_print + ".crl";
    let key_uri = conf.BASE_KEY_DIR_l.clone() + ca_name + ".der";
    let fname = repository::get_filename_crl_mft(&key_uri);

    let mft_uri = base_uri.clone() + &fname + ".mft";
    let repo_uri = base_uri.clone();
    let notification_uri = "https://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_RRDP_DIR_l.clone() + "notification.xml";

    let mut all_fields = vec![];

    // caRepository
    if is_ee{
        let key = "1.3.6.1.5.5.7.48.11".to_string();
        let identifier = asn1::ObjectIdentifier::from_string(&key).unwrap();
        all_fields.push(asn1p::InfoAccessField{identifier: identifier, val: Some(asn1::IA5String::new(&own_uri.unwrap()).unwrap())});

        let iaf = asn1::parse_single::<asn1p::SubjectInfoAccess>(&raw_bytes).unwrap();
        let iaf = iaf.fields.get();
        for field in iaf.clone().into_iter(){
            if field.identifier.to_string() == "1.3.6.1.5.5.7.48.11"{
                continue;
            }
            all_fields.push(field);
        }
    }
    else{
        let key = "1.3.6.1.5.5.7.48.5".to_string();
        let identifier = asn1::ObjectIdentifier::from_string(&key).unwrap();
        all_fields.push(asn1p::InfoAccessField{identifier: identifier, val: Some(asn1::IA5String::new(&repo_uri).unwrap())});
        
    
        let key = "1.3.6.1.5.5.7.48.10".to_string();
        let identifier = asn1::ObjectIdentifier::from_string(&key).unwrap();
        all_fields.push(asn1p::InfoAccessField{identifier: identifier, val: Some(asn1::IA5String::new(&mft_uri).unwrap())});
        
    
        let key = "1.3.6.1.5.5.7.48.13".to_string();
        let identifier = asn1::ObjectIdentifier::from_string(&key).unwrap();
        all_fields.push(asn1p::InfoAccessField{identifier: identifier, val: Some(asn1::IA5String::new(&notification_uri).unwrap())});
    }
    
    

    let ww = asn1::SequenceOfWriter::new(all_fields);
    let write_res = asn1::write_single(&ww).unwrap();
    let res = asn1::parse_single::<asn1::SequenceOf<asn1p::InfoAccessField>>(&write_res).unwrap();
    let octetstr = asn1::OctetStringEncoded::new(res);

    let key = "1.3.6.1.5.5.7.1.11".to_string();
    let identifier = asn1::ObjectIdentifier::from_string(&key).unwrap();

    let b = asn1p::SubjectInfoAccess{
        identifier: identifier,
        fields: octetstr,
    };

    let ret = asn1::write_single(&b).unwrap();


    ret
}


pub fn handle_crl_distribution_points(crl_uri: &str) -> Vec<u8> {
    let ia = asn1::IA5String::new(crl_uri).unwrap();
    let g = asn1p::GeneralName{UniformResourceIdentifier: Some(ia)};

    let d = asn1p::DistributionPointName{fullname: Some(g)};

    let x = asn1p::DistributionPoint{distributionPoint: Some(d)};

    let s = asn1::SequenceOfWriter::new(vec![x]);
    let b = asn1::write_single(&s).unwrap();
    let a = asn1::parse_single::<asn1::SequenceOf<asn1p::DistributionPoint>>(&b).unwrap();
    let octetstr = asn1::OctetStringEncoded::new(a);

    let i = asn1::ObjectIdentifier::from_string("2.5.29.31").unwrap();
    let r = asn1p::CrlDistributionPoints{identifier: i, crlDistributionPoints: octetstr};
    let ret = asn1::write_single(&r).unwrap();
    ret
}


pub fn handle_basicConstraints(is_ee: bool) -> Vec<u8>{
    let a = asn1p::BasicConstraints{ca: !is_ee};
    let ret = asn1::write_single(&a).unwrap();
    let x = asn1::OctetStringEncoded::new(&a);
    let t = asn1::write_single(&x).unwrap();
    let b = asn1::parse_single::<asn1::Tlv>(&t).unwrap();

    let ex = asn1p::ExtensionValue{identifier: asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap(), critical: true, value: b};

    let ret = asn1::write_single(&ex).unwrap();
    ret
}


pub fn handle_authorityInfoAccess(parent_uri: &str) -> Vec<u8>{
    let uri = asn1::IA5String::new(parent_uri).unwrap();

    let iden = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.2").unwrap();
    let f = asn1p::InfoAccessField{identifier: iden, val: Some(uri)};

    let ww = asn1::SequenceOfWriter::new(vec![f]);
    let write_res = asn1::write_single(&ww).unwrap();
    let res = asn1::parse_single::<asn1::SequenceOf<asn1p::InfoAccessField>>(&write_res).unwrap();
    let octetstr = asn1::OctetStringEncoded::new(res);
    let tmp = asn1::write_single(&octetstr).unwrap();
    let v = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();

    let i = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.1");
    let b = asn1p::ExtensionValue{identifier: i.unwrap(), critical: false, value: v};
    asn1::write_single(&b).unwrap()
}

pub fn handle_certificatePolicies() -> Vec<u8>{
    let p = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.14.2").unwrap();
    let pi = asn1p::PolicyInformation{policyIdentifier: p, policy: None};
    let sw = asn1::SequenceOfWriter::new(vec![pi]);
    let write_res = asn1::write_single(&sw).unwrap();
    let res = asn1::parse_single::<asn1::SequenceOf<asn1p::PolicyInformation>>(&write_res).unwrap();
    let octetstr = asn1::OctetStringEncoded::new(res);

    // let b = hex::decode(b"300A06082B06010505070E02").unwrap();
    // let x = asn1::parse_single::<asn1::OctetStringEncoded>(&b).unwrap();
    // // let b = Bytes::from("300C300A06082B06010505070E02");
    // let u: &[u8] = &b;


    // let oc = asn1::OctetStringEncoded::new(&x);
    let tmp = asn1::write_single(&octetstr).unwrap();
    let v = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();

    let i = asn1::ObjectIdentifier::from_string("2.5.29.32");
    let b = asn1p::ExtensionValue{identifier: i.unwrap(), critical: true, value: v};
    asn1::write_single(&b).unwrap()
}


// pub fn handle_ipblocks() -> Vec<u8>{
//     let p = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.7").unwrap();
//     let b = Bytes::from(hex::decode("01").unwrap());
//     let oc = OctetStringEncoded::new(b);
//     let ad_fam = asn1::write_single(&oc);
// }

pub fn check_replace_ev(data: &Vec<u8>, change_everything: bool) -> bool{
    let r = asn1::parse_single::<asn1p::ExtensionValue>(data);
    if r.is_err(){
        return false;
    }
    if change_everything{
        return true;
    }
    let r = r.unwrap();
    let a = asn1::write_single(&r.value);
    if a.is_err(){
        return false;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        return true;
    }
    return false;
}

pub fn check_replace_tv(data: &Vec<u8>, change_everything: bool) -> (bool, bool){
    let mut ret =  (false, false);
    let r = asn1::parse_single::<asn1p::TypeAndValue>(data);
    if r.is_err(){
        return ret;
    }
    if change_everything{
        return (true, true);
    }
    let r = r.unwrap();
    let a = asn1::write_single(&r.attrType);
    if a.is_err(){
        return ret;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        ret.0 = true;
    }

    let a = asn1::write_single(&r.attrValue);
    if a.is_err(){
        return ret;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        ret.1 = true;
    }
    ret

}

pub fn check_replace_validity(data: &Vec<u8>, change_everything: bool) -> (bool, bool){
    let mut ret =  (false, false);
    let r = asn1::parse_single::<asn1p::Validity>(data);
    if r.is_err(){
        return ret;
    }
    if change_everything{
        return (true, true);
    }

    let r = r.unwrap();
    let a = asn1::write_single(&r.notBefore);
    if a.is_err(){
        return ret;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        ret.0 = true;
    }

    let a = asn1::write_single(&r.notAfter);
    if a.is_err(){
        return ret;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        ret.1 = true;
    }
    ret

}

pub fn check_replace_subjectPublicKeyInfo(data: &Vec<u8>, change_everything: bool) -> (bool, bool){
    let mut ret =  (false, false);
    let r = asn1::parse_single::<asn1p::SubjectPublicKeyInfo>(data);
    if r.is_err(){
        return ret;
    }
    if change_everything{
        return (true, true);
    }
    let r = r.unwrap();
    let a = asn1::write_single(&r.algorithm);
    if a.is_err(){
        return ret;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        ret.0 = true;
    }

    let a = asn1::write_single(&r.subjectPublicKey);
    if a.is_err(){
        return ret;
    }
    let a = a.unwrap();
    if a.len() == 3 && a[2] == 0x00{
        ret.1 = true;
    }
    ret

    
}

pub fn parse_and_sign(data: Bytes, parent: &KeyAndSigner, conf: &RepoConfig, pub_key: &PublicKey, ca_name: &str, parent_uri: Option<&str>, object_uri: Option<&str>, is_ee: bool) -> (Vec<u8>, i32) {
    // TODO Make this configurable
    let change_validity = false;
    let change_policies = false;
    let replace_names = false;
    let replace_basic_constraints = false;

    let mut rng = rand::thread_rng();
    // return data.to_vec();
    let parent_uri = match parent_uri{
        Some(x) => x,
        None => "rsync://my.server.com/data/my.server.com/tal/ta.cer",
    };

    let inte = rng.gen_range(0..10000);
    let new_key;
    if is_ee{
        new_key = Some(repository::make_cert_key(&(conf.BASE_KEY_DIR_l.clone() + &inte.to_string() + ".der"), "rsa"));
    }
    else{
        new_key = None;
    }


    let mut pub_key = pub_key;
    let v;
    if new_key.is_some(){
        v = new_key.unwrap().get_pub_key();
        pub_key = &v;
    };
    

    let change_anything = true;
    let add_non = true;

    let parent_id = parent.get_pub_key().key_identifier().to_string();
    let child_id = pub_key.key_identifier().to_string();
    let a = asn1::parse_single::<asn1p::Certificate>(&data);
    if a.is_err(){
        println!("Couldnt parse {}", a.err().unwrap());
        return (data.to_vec(), 0);
    }

    let mut obj = a.unwrap();


    let serial = obj.tbsCert.serialNumber;
    let e;
    if serial.is_some() && false{
        let x = asn1::write_single(&serial.unwrap()).unwrap();
        let v = asn1::parse_single::<asn1::BigInt>(&x);
        if v.is_ok(){
            let new_serial = rng.gen_range(0..1000000);
            let b = new_serial.to_encoded_bytes(Mode::Der);
            let x = asn1::BigInt::new(&b).unwrap();
            e = asn1::write_single(&x).unwrap();
            let ns = asn1::parse_single::<asn1::Tlv>(&e).unwrap();
            obj.tbsCert.serialNumber = Some(ns);
        }
    }

    let validity = obj.tbsCert.validity;

    let issuer = obj.tbsCert.issuer;
    let iss_val;
    let tmp;
    if issuer.is_some(){
        let v = issuer.unwrap();
        let a = asn1::write_single(&v).unwrap();
        let b = asn1::parse_single::<asn1::SequenceOf<asn1::SetOf<asn1p::TypeAndValue>>>(&a);
        if b.is_ok(){
            let b = b.unwrap();
            let mut aval = false;
            let mut cval = false;
            // This initialization is never used, its just so that the compiler does not complain
            let mut at = v;
            let mut av = v;
            // This is needed to decide if something in the object needs to be replaced

            let mut value_vec = vec![];

            for v_x in b{
                for v in v_x.clone().into_iter(){
                    let t = asn1::write_single(&v.attrType).unwrap();
                    let a = asn1::parse_single::<asn1::ObjectIdentifier>(&t);
                    if a.is_ok(){
                        let x = a.unwrap();
                        if x.to_string() != "2.5.4.3" && is_ee{
                            value_vec.push(v_x.clone());
                            continue;
                        }
                    }
                    
                    (aval, cval) = check_replace_tv(&asn1::write_single(&v).unwrap(), change_anything);
                    at = v.attrType;
                    av = v.attrValue;
                    break;
                }                
            }
                

            let oid = asn1::ObjectIdentifier::from_string("2.5.4.3").unwrap();
            let v = asn1::PrintableString::new(&parent_id);
            let c = asn1::write_single(&v).unwrap();
            let d = asn1::parse_single::<asn1::Tlv>(&c).unwrap();
            tmp = asn1::write_single(&oid).unwrap();
            let oido = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();
            if replace_names || !is_ee{
                if aval {
                    at = oido;
                }
                if cval {
                    av = d;
                }
            }
            let tv = asn1p::TypeAndValue{attrType: at, attrValue: av};
            let w = asn1::SetOfWriter::new(vec![tv]);
            let c = asn1::write_single(&w).unwrap();
            let d = asn1::parse_single::<asn1::SetOf<asn1p::TypeAndValue>>(&c).unwrap();

            value_vec.push(d);

            // let mut seq_el = vec![];
            // for vi in 0..value_vec.len(){
            //     let v = &value_vec[vi];
            //     let w = asn1::SetOfWriter::new(vec![v]);
            //     let c = asn1::write_single(&w).unwrap();
            //     let d = asn1::parse_single::<asn1::SetOf<asn1p::TypeAndValue>>(&c).unwrap();
            //     seq_el.push(d);
            // }
            

            value_vec.reverse();
            let sw = asn1::SequenceOfWriter::new(value_vec);
            iss_val = asn1::write_single(&sw).unwrap();
            let d = asn1::parse_single::<asn1::Tlv>(&iss_val).unwrap();
            // iss_val = asn1::write_single(&new_name).unwrap();
            // let d = asn1::parse_single::<asn1::Tlv>(&iss_val).unwrap();

            obj.tbsCert.issuer = Some(d)
    



        }
        else{
            println!("Could not parse issuer {}", b.err().unwrap());
        }
    }

    let subject = obj.tbsCert.subject;
    let sub_val;
    let tmp;
    if subject.is_some(){
        let v = subject.unwrap();
        let a = asn1::write_single(&v).unwrap();
        let b = asn1::parse_single::<asn1::SequenceOf<asn1::SetOf<asn1p::TypeAndValue>>>(&a);
        if b.is_ok(){
            let b = b.unwrap();
            let mut aval = false;
            let mut cval = false;
            // This initialization is never used, its just so that the compiler does not complain
            let mut at = v;
            let mut av = v;

            let mut value_vec = vec![];
            // This is needed to decide if something in the object needs to be replaced
            for v_x in b{
                for v in v_x.clone().into_iter(){
                    let t = asn1::write_single(&v.attrType).unwrap();
                    let a = asn1::parse_single::<asn1::ObjectIdentifier>(&t);
                    if a.is_ok(){
                        let x = a.unwrap();
                        if x.to_string() != "2.5.4.3"{
                            value_vec.push(v_x.clone());
                            continue;
                        }
                    }
                    (aval, cval) = check_replace_tv(&asn1::write_single(&v).unwrap(), change_anything);
                    at = v.attrType;
                    av = v.attrValue;
                    break;
                }
            }

            let oid = asn1::ObjectIdentifier::from_string("2.5.4.3").unwrap();
            let v = asn1::PrintableString::new(&child_id);
            let c = asn1::write_single(&v).unwrap();
            let d = asn1::parse_single::<asn1::Tlv>(&c).unwrap();
            tmp = asn1::write_single(&oid).unwrap();
            let oido = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();
            if replace_names {
                if aval {
                    at = oido;
                }
                if cval {
                    println!("Replacing subject name");
                    av = d;
                }
            }
            

            let tv = asn1p::TypeAndValue{attrType: at, attrValue: av};
            let w = asn1::SetOfWriter::new(vec![tv]);
            let c = asn1::write_single(&w).unwrap();
            let d = asn1::parse_single::<asn1::SetOf<asn1p::TypeAndValue>>(&c).unwrap();

            value_vec.push(d);

            value_vec.reverse();
            let sw = asn1::SequenceOfWriter::new(value_vec);
            sub_val = asn1::write_single(&sw).unwrap();
            let d = asn1::parse_single::<asn1::Tlv>(&sub_val).unwrap();

            obj.tbsCert.subject = Some(d)
        }

    }


    let val;
    let tmp1;
    let tmp2;
    // if validity.is_some() && !is_ee{
    if validity.is_some() && change_validity{

        // Dont want to replace validity in EE-Cert
        // This might change in the future

        let v = validity.unwrap();
        let a = asn1::write_single(&v).unwrap();
        let b = asn1::parse_single::<asn1p::Validity>(&a);
        if b.is_ok(){
            let mut e = b.unwrap();
            let (aval, bval) = check_replace_validity(&asn1::write_single(&e).unwrap(), change_anything);
            let c = asn1::UtcTime::new(chrono::offset::Local::now().into()).unwrap();
            let d = asn1::UtcTime::new((chrono::offset::Local::now() + Duration::days(5)).into()).unwrap();
            tmp1 = asn1::write_single(&c).unwrap();
            tmp2 = asn1::write_single(&d).unwrap();
            if aval{
                e.notBefore = c;
            }
            if bval {
                e.notAfter = d;

            }
    
            val = asn1::write_single(&e).unwrap();
            obj.tbsCert.validity = Some(asn1::parse_single::<asn1::Tlv>(&val).unwrap());
        }
        else{
        }
    }

    // Replace SubjectKey
    let spk = obj.tbsCert.subjectPublicKeyInfo;
    let si;
    let ret;
    if spk.is_some() {
        let val = spk.unwrap();
        let (_, bval) = check_replace_subjectPublicKeyInfo(&asn1::write_single(&val).unwrap(), change_anything);

        if bval{
            let child_key = pub_key.encode_ref().to_captured(Mode::Der).into_bytes();
           
            let pk_der = asn1::BitString::new(&child_key, 0).unwrap();
            ret = pk_der.as_bytes().to_vec();
            si = asn1::parse_single::<asn1::Tlv>(&ret);
            let x = si.unwrap(); 
    
            obj.tbsCert.subjectPublicKeyInfo = Some(x);
        }
        
    }


    // Replace AKI
    let aus = obj.tbsCert.resourceCertificateExtensions.clone();
    if aus.is_none() {
        println!("None extensions");
        return (data.to_vec(), 0);
    }
    let aus = aus.unwrap();
    
    let mut all_exts = HashMap::new();


    for ex in aus.clone(){
        let by = asn1::write_single(&ex).unwrap();
        let tmp = asn1::parse_single::<asn1p::ExtensionValue>(&by);
        let iden;
        if tmp.is_ok(){
            iden = tmp.unwrap().identifier.to_string();
        }
        else{
            iden = thread_rng().sample_iter(&Alphanumeric).take(12).map(char::from).collect();        
        }

        all_exts.insert(iden, asn1::write_single(&ex).unwrap());
    }

    let mut updatedExtensions = vec![];


    let mut to_skip_once = vec![];
    // SubjectInfoAccess
    let key = "1.3.6.1.5.5.7.1.11".to_string();
    if all_exts.contains_key(&key) || add_non{
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0{
            let si = handle_subjectInfoAcces(val.clone(), ca_name, &conf, object_uri, is_ee);
            updatedExtensions.push(si);
            to_skip_once.push(key);
        }
    } 

    //SKI
    let key = "2.5.29.14".to_string();
    if all_exts.contains_key(&key) || add_non{
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0{
            let si = handle_subjectKeyIdentifier(val.clone(), pub_key.key_identifier().to_encoded_bytes(Mode::Der));
            updatedExtensions.push(si);
            to_skip_once.push(key);
        }
    }



    //AKI
    let key = "2.5.29.35".to_string();
    // TODO
    if all_exts.contains_key(&key) || add_non {
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0  {
            let si = handle_authorityKeyIdentifier(parent.get_pub_key().key_identifier().to_encoded_bytes(Mode::Der));
            updatedExtensions.push(si);
            to_skip_once.push(key);
        }
    }

    // CRL Distribution Points
    let key = "2.5.29.31".to_string();
    if all_exts.contains_key(&key) || add_non{
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0{
            let parent_name = match is_ee{
                true => &conf.CA_NAME,
                false => &conf.CA_TREE[&conf.CA_NAME],
            };
            
            let file_name = repository::get_filename_crl_mft(&(conf.BASE_KEY_DIR_l.clone() + &parent_name + ".der"));
            let crl_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + &parent_name + "/" + &file_name + ".crl";

            let si = handle_crl_distribution_points(&crl_uri);
            updatedExtensions.push(si);
            to_skip_once.push(key);
        }
    }

    // Basic Constraints
    let key = "2.5.29.19".to_string();
    if replace_basic_constraints && (all_exts.contains_key(&key) || add_non){
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0{
            let si = handle_basicConstraints(is_ee);
            if !is_ee{
                updatedExtensions.push(si);
            }
            to_skip_once.push(key);    
        }
    }

    // AuthorityInfoAccess
    let key = "1.3.6.1.5.5.7.1.1".to_string();
    if all_exts.contains_key(&key) || add_non{
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0{
            let si = handle_authorityInfoAccess(parent_uri);
            updatedExtensions.push(si);
            to_skip_once.push(key);    
        }
    }

    // Certificate Policies
    let key = "2.5.29.32".to_string();
    if change_policies && (all_exts.contains_key(&key) || add_non){
        let v = vec![];
        let val = match all_exts.get(&key){
            Some(x) => x,
            None => &v,
        };
        if check_replace_ev(val, change_anything) || val.len() == 0{
            let si = handle_certificatePolicies();
            updatedExtensions.push(si);
            to_skip_once.push(key);    
        }
    }

    for ex in all_exts.clone(){
        if to_skip_once.contains(&ex.0){
            continue;
        } 
        let tmp = all_exts.get(&ex.0).unwrap().to_vec();

        updatedExtensions.push(tmp);
        
    }

    let mut pu = vec![];
    for i in 0..updatedExtensions.len(){
        let e = &updatedExtensions[i];
        let v = asn1::parse_single::<asn1::Tlv>(&e);
        pu.push(v.unwrap());
    }
    let sigalg = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.11").unwrap();
    let tmp = asn1::write_single(&sigalg).unwrap();
    let sigalg = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();

    let sa = asn1p::AlgorithmIdentifier{
        algorithm: sigalg.clone(),
        parameters: None
    };

    let tmp = asn1::write_single(&sa).unwrap();
    let sigalg = asn1::parse_single::<asn1::Tlv>(&tmp).unwrap();

    obj.tbsCert.signature = Some(sigalg);

    let ww = asn1::SequenceOfWriter::new(pu);
    
    let b = asn1::write_single(&ww).unwrap();
    let e = asn1::parse_single::<asn1::SequenceOf<asn1::Tlv>>(&b).unwrap();
    obj.tbsCert.resourceCertificateExtensions = Some(e);

    let ver = asn1::write_single(&2).unwrap();
    let cert2 = asn1p::tbsCertificate2{
        version: Some(asn1::parse_single::<asn1::Tlv>(&ver).unwrap()),
        serialNumber: obj.tbsCert.serialNumber,
        signature: obj.tbsCert.signature,
        issuer: obj.tbsCert.issuer,
        validity: obj.tbsCert.validity,
        subject: obj.tbsCert.subject,
        subjectPublicKeyInfo: obj.tbsCert.subjectPublicKeyInfo,
        resourceCertificateExtensions: obj.tbsCert.resourceCertificateExtensions,
    };

    // let content = asn1::write_single(&obj.tbsCert).unwrap();
    let content = asn1::write_single(&cert2).unwrap();

    let sig = parent.sign(&content);

    obj.signatureAlgorithm = sigalg;
    obj.signatureValue = BitString::new(&sig, 0).unwrap();


    let new_obj = asn1p::Certificate2{
        tbsCert: cert2,
        signatureAlgorithm: obj.signatureAlgorithm,
        signatureValue: obj.signatureValue,
    };


    let new_bytes = asn1::write_single(&new_obj).unwrap();
    (new_bytes, inte)
}

pub fn handle_serialized_object_inner(data: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)>, conf: &RepoConfig, start_index: u32){
    let mut filenames = vec![];
    let mut objects = vec![];
    let mut index = 0;

    for date in data {
        let ca_name = "ca".to_string() + &(index + start_index).to_string();
        index += 1;
        let byte = Bytes::from(date.1);
        let byte_crl = Bytes::from(date.2);
        let byte_mft = Bytes::from(date.3);

        let byte_roa = Bytes::from(date.4);

        let uri_roa = date.5;

        filenames.push(date.0.clone());
        objects.push(byte.clone());

        let key_uri = conf.BASE_KEY_DIR_l.clone() + &ca_name + ".der";

        repository::write_object_to_disc(&byte_crl, "crl", &key_uri, &ca_name, conf);
        repository::write_object_to_disc(&byte_mft, "mft", &key_uri, &ca_name, conf);
        repository::write_object_to_disc(&byte_roa, "", &(uri_roa), &ca_name, conf);

        repository::write_object_to_disc(&byte, "cer", &(ca_name + ".cer"), "ta", conf);
    }

    // repository::add_roa_str("10.0.0.0/24 => 22222", true, conf);


    repository::make_manifest("ta", "root", conf);

    fs::remove_dir_all(&conf.BASE_RRDP_DIR_l);
    let (session_id, serial_number) = repository::get_current_session_notification(conf);

    let (snapshot, snapshot_uri) = repository::create_current_snapshot(session_id, serial_number, None, false, conf, None, None);

    let mut snapshot_content = vec![];
    snapshot.write_xml(&mut snapshot_content).unwrap();
    let snapshot_bytes = Bytes::from(snapshot_content);
    let notification = repository::create_notification(snapshot_bytes, vec![], &snapshot_uri, 5, session_id, serial_number, conf);
    repository::write_notification_file(notification, conf).unwrap(); 
}

pub fn handle_serialized_object(path: &str, conf: &RepoConfig, _: u32, _: Option<Vec<(Bytes, String)>>, _: &str) {
    let data = read_serialized_data(path);
    handle_serialized_object_inner(data, conf, 0);
}


pub fn generate_from_files_plain(
    folder: &str,
    conf: &RepoConfig,
    amount: u32,
    _: &Vec<PKey<Private>>,
    _: &Vec<PublicKey>,
    ca_keys: &Vec<KeyAndSigner>,
    _: &str,
    roas: &Vec<(Bytes, String)>,
    crls: &Vec<(Bytes, String)>,
    mfts: &Vec<(Bytes, String)>,
) -> Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> {
    let obj = util::read_files_from_folder(folder, amount);

    let mut objects = vec![];

    let parent_key = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.clone() + "ta.der"));
    for i in 0..obj.clone().len() {
        let a = &obj.clone()[i];

        let name = "ca".to_string() + &i.to_string();
        let (re, _) = parse_and_sign(a.1.clone(), &parent_key, &conf, &ca_keys[i].get_pub_key(), &name, None, None, false);

        objects.push((a.0.clone(), re.to_vec(), crls[i].0.to_vec(), mfts[i].0.to_vec(), roas[i].0.to_vec(), roas[i].1.clone()));
    }

    objects
}

// Serialize Byte Vector to a random file in obj_cache folder
pub fn serialize_data(val: &Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)>) -> String {
    let s = serde_json::to_string(&val).unwrap();
    let filename = util::get_cwd() + "/obj_cache/" + &util::random_file_name();

    fs::write(&filename, s).unwrap();
    filename
}

pub fn read_serialized_data(filename: &str) -> Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> {
    let s = fs::read_to_string(filename).unwrap();
    let c = serde_json::from_str::<Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)>>(&s);
    if c.is_err(){
        return vec![];
    }
    c.unwrap()
}

pub fn move_files_data(folder: String, filepaths: &Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)>, dont_move: bool) {
    // For Debugging
    if dont_move {
        return;
    }

    for filepath in filepaths {
        let p = folder.clone() + &filepath.0;
        fs::remove_file(p).unwrap();
    }
}

pub fn create_objects(folder: String, max_file_amount: u16, dont_move: bool, oneshot: bool, amount: u32) {
    let mut conf = repository::create_default_config(consts::domain.to_string());
    let (cert_keys, _) = util::create_cas(amount, vec![&conf], None);
    for i in 0..amount{
        let name = "ca".to_string() + &i.to_string();
        conf.CA_TREE.insert(name, "ta".to_string());
    }

    let cws = util::get_cwd() + "/";
    let output_folder = cws + "obj_cache/";
    let (priv_keys, pub_keys) = load_ee_ks(&conf, amount, false);

    let roas = util::create_example_roas(&cert_keys, amount, &conf);    
    let crls = util::create_example_crls(&cert_keys, amount, &conf);
    let mfts = util::create_example_mfts(&cert_keys, amount, &roas, &crls, &conf);

    for i in 0..amount{
        conf.CA_TREE.insert("ca".to_string() + &i.to_string(), "ta".to_string());
    }

    loop {
        let data = generate_from_files_plain(&folder, &conf, amount, &priv_keys, &pub_keys, &cert_keys, "cer", &roas, &crls, &mfts);
        
        if data.len() == 0 {
            println!("No more Objects in Folder {} - Exiting Process", folder);
            return;
        }
        
        serialize_data(&data);

        move_files_data(folder.clone().to_string(), &data, dont_move);

        if oneshot{
            break;
        }
        // If folder is sufficiently full -> Wait
        while util::fileamount_in_folder(&output_folder) >= max_file_amount.into() {
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}


pub fn do_both(folder: &str, conf: &RepoConfig) {
    let cws = util::get_cwd() + "/";
    // let folder = cws.clone() + "example_cer/";
    let obj_folder = cws + "obj_cache/";

    let amount;
    if fs::metadata(folder.clone()).is_ok() && fs::metadata(folder.clone()).unwrap().is_file(){
        amount = 1;
    }
    else{
        amount = read_dir(folder.clone()).unwrap().count();
    }

    create_objects(folder.to_string().clone(), 2, true, true, amount.try_into().unwrap());
    let paths = fs::read_dir(obj_folder.clone()).unwrap();
    for path in paths {
        let p = path.unwrap().path();
        let file_name = p.to_str().unwrap();
        handle_serialized_object(file_name, &conf, 1, None, "");
        fs::remove_file(file_name).unwrap();
        break;
    }
}


// pub fn test_cert(){
//     let uri = "/home/nvogel/git/rpki-fuzzing/example_cer/newca.cer";
//     let newuri = "/home/nvogel/git/rpki-fuzzing/example_cer/newca2.cer";
//     let key_uri = "/home/nvogel/git/rpki-fuzzing/data/keys/ta.der";

//     let ks = repository::read_cert_key(key_uri);
//     let b = fs::read(uri).unwrap();

//     let res = parse_and_sign(b.clone().into(), &ks);

//     fs::write(newuri, res).unwrap();
// }
