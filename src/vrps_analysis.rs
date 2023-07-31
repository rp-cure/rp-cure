use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Index,
    path::Path,
    str::FromStr,
    vec,
};

use crate::fuzzing::{cert, crl, roa};
use crate::publication_point::{
    repository::{self, RepoConfig},
    rp_interaction::RoaContents,
};
use crate::{
    asn1p::{self, Certificate},
    util,
};
use crate::{fuzzing, FuzzConfig};
use asn1::oid;
use bcder::{
    encode::{PrimitiveContent, Values},
    Mode,
};
use bytes::Bytes;
use chrono::{Duration, Timelike};
use hex::{FromHex, ToHex};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rasn::{ber, der};
use rpki::{
    repository::{
        crypto::digest,
        resources::{self, Addr, IpBlock},
        roa::RouteOriginAttestation,
        sigobj::SignedObject,
    },
    rrdp::Hash,
};

use serde_json::Value;
use sha256;

pub fn start_analysis(conf: FuzzConfig) {
    let uri = conf.uri;
    let typ = conf.typ.to_string();
    let ty = conf.subtype;

    let ss = analyse_vrps(false).0;

    let base_routinator = "base_routinator/";
    let base_fort = "base_fort";
    let base_client = "base_client";
    let base_octo = "base_octo";
    let bases = vec![base_routinator, base_octo, base_fort, base_client];

    let mut report = "--- Inconsistency Report ---\n\n".to_string();

    if ty == "raw_folder" {
        let paths = fs::read_dir(&uri).unwrap();

        let tmp_folder = util::get_cwd() + "/tmp/";

        for path_t in paths {
            let p = path_t.unwrap();
            report += "<Inconsistency>\n";
            report += "Filename: ";
            report += p.file_name().to_str().unwrap();
            report += "\n";
            let tmp = p.path();
            let path_pre = tmp.as_os_str().to_string_lossy();
            let newpath = tmp_folder.clone() + p.file_name().to_str().unwrap();
            let con = fs::read(&*path_pre).unwrap();

            let o = get_content_ips(Bytes::from(con.clone()));
            let mut conf = repository::create_default_config("my.server.com".to_string());

            conf.IPBlocks.extend(o);
            // conf.IPv4.extend(o1);
            // conf.IPv6.extend(o2);

            repository::initialize_repo(&mut conf, false, None);

            if typ == "mft" || typ == "roa" || typ == "gbr" || typ == "aspa" {
                let newcon = fix_econtent(Bytes::from(con), &conf);
                fs::write(&newpath, newcon).unwrap();
            } else {
                fs::write(&newpath, con).unwrap();
            }

            let path = newpath;

            // TODO
            // if typ == "mft" {
            //     fuzzing::mft::do_both(&path, true, &conf);
            // } else if typ == "crl" {
            //     fuzzing::crl::do_both(&path, &mut conf);
            // } else if typ == "roa" {
            //     fuzzing::roa::do_both(&path, true, "roa", &conf);
            // } else if typ == "gbr" {
            //     fuzzing::roa::do_both(&path, true, "gbr", &conf);
            // } else if typ == "aspa" {
            //     fuzzing::roa::do_both(&path, true, "aspa", &conf);
            // } else if typ == "cert" {
            //     fuzzing::cert::do_both(&path, &conf);
            // } else {
            //     panic!("Unknown object type!");
            // }
            let re = util::run_rp_processes("error");
            for r in re {
                if r.1 {
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
            for n in rp_names {
                let l = util::read_rp_log(n);
                report += &("<".to_string() + n + " log>\n");
                report += &l;
                report += "\n\n";
            }
            println!("{}", report);
            return;
        }
    } else if ty == "folder" {
        let mut report = "".to_string();
        util::clear_caches();
        report += "<Inconsistency>\n";
        report += "Folder: ";
        report += &uri;
        report += "\n";

        let err = handle_folder(&uri);
        if err {
            println!("Error in parsing MFT, following RPs miss the ROAs");

            report += "Error while processing folder!";
        } else {
            report += "No inconsistencies found!";
        }

        let re = util::run_rp_processes("error");
        for r in re {
            if r.1 {
                println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
            }
        }
        let (vrps, diffr, _, roas) = util::get_rp_vrps();
        if diffr {
            let (dif, ssets) = analyse_vrps(true);
            let mut sw = 0;
            for i in 0..ssets.len() {
                let rpv = &ssets[i];
                for v in rpv {
                    // if ss[i].contains(v) {
                    //     println!("{} Switched validity {}", i, v);
                    //     sw += 1;
                    // }
                }
            }
            if sw == roas[0].len() {
                report += "All ROAs switched Validity -> Likely something wrong with parent!";
            }
            report += &format!("No inconsistencies found! {}\n\n", roas[0].len().to_string());
        } else {
            let rp_names = vec!["routinator", "octorpki", "fort", "client"];

            report += "<Differences>\n";
            for i in 0..rp_names.len() {
                continue;
                // let d = dif[i].clone().into_iter().map(|x| x.to_string()).collect::<Vec<String>>().join("\n");
                // report += &("<Missing from ".to_string() + rp_names[i] + ">\n");
                // report += &d;
                // report += "\n\n";
            }

            let d = find_dif_roas(Some(vec![&(util::get_cwd().clone() + "/data/my.server.com/repo/newca/")]));
            report += "<Detailed Info>\n";
            if d.len() > 5 {
                report += "Too many differences to show!\n\n";
            } else {
                for di in d {
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
            for n in rp_names {
                let l = util::read_rp_log(n);
                report += &("<".to_string() + n + " log> (Length: " + &roas[ind].len().to_string() + ")\n");
                report += &l;
                report += "\n\n";
                ind += 1;
            }
        }

        println!("Report: {}", report);
    } else if ty == "cache" {
        let folders = fs::read_to_string(&uri).unwrap();
        let mut skipped_once = true;
        let mut cu = 0;

        let mut miss_from_rps = vec![0, 0, 0, 0];

        let mut total_subnet = 0;
        let mut total_prefix = 0;

        println!("total amount {}", folders.split("\n").collect::<Vec<&str>>().len());
        for f in folders.split("\n") {
            util::clear_caches();
            if f.contains("amazon") {
                continue;
            }
            cu += 1;
            println!("CU {}", cu);
            if cu < 0 {
                continue;
            }
            if cu == 0 {
                break;
            }
            if f.is_empty() {
                continue;
            }
            if !skipped_once {
                skipped_once = true;
                continue;
            }

            let err = handle_folder(&f);

            if err {
                report += &format!("Error while processing folder {}!\n\n", &f);
                continue;
            }

            let re = util::run_rp_processes("error");
            for r in re {
                if r.1 {
                    println!("\n\n   ---> RP {} crashed!!\n\n", r.0);
                }
            }
            let (vrps, diffr, _, roas) = util::get_rp_vrps();

            if diffr {
                let (dif, ssets) = analyse_vrps(true);
                let mut sw = 0;
                for i in 0..ssets.len() {
                    let rpv = &ssets[i];
                    for v in rpv {
                        // if ss[i].contains(v) {
                        //     // println!("{} Switched validity {}", i, v);
                        //     sw += 1;
                        // }
                    }
                }
                // if sw == roas[0].len(){
                report += format!(
                    "{} / {} ROAs switched Validity -> Likely something wrong with parent!",
                    sw,
                    roas[0].len()
                )
                .as_str();
                let (tu, nu) = check_mft_validity(&f);
                report += &format!("Manifest validity {:?} - {:?}", tu, nu);

                // let ct = chrono::Utc::now();

                // if ct > nu.as_chrono().to_owned() || ct < tu.as_chrono().to_owned(){
                //     report += &format!("Manifest validity {:?} - {:?}", tu, nu);
                //     println!("Manifest not valid");
                // }

                // }

                report += &format!(
                    "No inconsistencies found! Roa length: {}, Folder: {}\n\n",
                    roas[0].len().to_string(),
                    &f
                );
                continue;
            }

            let oo = check_only_octo(&roas);
            total_subnet += oo.0;
            total_prefix += oo.1;
            if (oo.0 != 0 || oo.1 != 0) && roas[0].len() == roas[1].len() + (oo.0 + oo.1) as usize {
                report += &format!("All inconsistencies are Octo Optimizations! {}\n\n", oo.0 + oo.1);
                continue;
            } else {
                println!("no octo opti {:?}", oo);
            }

            let maxi_rp = roas.iter().map(|x| x.len()).max().unwrap();
            let highest_rp = roas.iter().position(|x| x.len() == maxi_rp).unwrap();
            let base = bases[highest_rp];

            for i in 0..roas.len() {
                if roas[i].len() == 0 {
                    let miss = find_affected_entries(&f, base);
                    miss_from_rps[i] += miss;
                }
            }

            report += "<Inconsistency>\n";
            report += "Folder: ";
            report += &f;
            report += "\n";

            // report += "<VRPS>\n";
            // report += &vrps;
            let rp_names = vec!["routinator", "octorpki", "fort", "client"];

            report += "<Differences>\n";
            for i in 0..rp_names.len() {
                continue;
                // let d = dif[i].clone().into_iter().map(|x| x.to_string()).collect::<Vec<String>>().join("\n");
                // report += &("<Missing from ".to_string() + rp_names[i] + ">\n");
                // report += &d;
                // report += "\n\n";
            }

            let d = find_dif_roas(Some(vec![&(util::get_cwd().clone() + "/data/my.server.com/repo/newca/")]));
            report += "<Detailed Info>\n";
            if d.len() > 5 {
                report += "Too many differences to show!\n\n";
            } else {
                for di in d {
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
            for n in rp_names {
                let l = util::read_rp_log(n);
                report += &("<".to_string() + n + " log> (Length: " + &roas[ind].len().to_string() + ")\n");
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

fn normalize_aia_uri(uri: &str) -> String {
    let v: Vec<&str> = uri.split("/").into_iter().collect();
    let x = &v[3..];
    let ret = x.join("/");
    ret
}

// Extract the URI from the AIA extension of a Mft Certificate
pub fn get_issuer_cert_uri(uri: &str) -> String {
    let con = fs::read(uri).unwrap();
    // println!("{}", base64::encode(&con));
    let mut mft = asn1::parse_single::<asn1p::ContentInfoMft>(&con);
    let b_tmp;
    if mft.is_err() {
        b_tmp = convert_to_ber(Bytes::from(con.clone()));
        mft = asn1::parse_single::<asn1p::ContentInfoMft>(&b_tmp);
        if mft.is_err() {
            return "".to_string();
        } else {
            println!("MFT parsed");
        }
    }
    let mft = mft.unwrap();
    for cert in mft.content.unwrap().certificates.unwrap() {
        for ex in cert.tbsCert.resourceCertificateExtensions.unwrap() {
            let b = asn1::write_single(&ex).unwrap();
            let c = asn1::parse_single::<asn1p::ExtensionValue>(&b).unwrap();
            if c.identifier.to_string() == "1.3.6.1.5.5.7.1.1" {
                let tmp = asn1::write_single(&c.value).unwrap();
                let aia = asn1::parse_single::<asn1::OctetStringEncoded<asn1::SequenceOf<asn1p::InfoAccessField>>>(&tmp).unwrap();
                let val: Vec<asn1p::InfoAccessField> = aia.get().clone().into_iter().collect();
                let acc = val[0].val.clone().unwrap().as_str();
                let acc = normalize_aia_uri(acc);
                return acc;
            }
        }
    }
    return "".to_string();
}

pub fn load_mft() {
    let uri = "base/";
    let con = fs::read(uri).unwrap();
    asn1::parse_single::<asn1p::ContentInfoMft>(&con).unwrap();
}

pub fn load_objects(folder_uri: &str) -> (Option<String>, Option<String>, Vec<String>, Vec<String>) {
    let mut mft: Option<String> = None;
    let mut crl: Option<String> = None;
    let mut objects = vec![];
    let mut ignored_files = vec![];

    let mut crls = vec![];
    let mut mfts = vec![];

    for u in fs::read_dir(folder_uri).unwrap().into_iter() {
        let e = u.unwrap();
        let path = e.path();
        if e.file_name().to_str().unwrap().ends_with("mft") {
            if crl.is_some() {
                let s1 = crl.clone().unwrap();
                let s2 = &("/".to_string() + e.file_name().to_str().unwrap().to_string().split(".").next().unwrap());
                if !s1.contains(s2) {
                    // println!("A1 {}, {}", s1, s2);
                    ignored_files.push(path.to_str().unwrap().to_string());
                    mfts.push(path.to_str().unwrap().to_string());

                    continue;
                }
            }
            if mft.is_some() {
                ignored_files.push(path.to_str().unwrap().to_string());

                continue;
            }

            mfts.push(path.to_str().unwrap().to_string());

            mft = Some(path.to_str().unwrap().to_string());
        } else if e.file_name().to_str().unwrap().ends_with("crl") {
            if mft.is_some() {
                let s1 = mft.clone().unwrap();
                let s2 = &("/".to_string() + e.file_name().to_str().unwrap().to_string().split(".").next().unwrap());
                if !s1.contains(s2) {
                    // println!("A2 {}, {}", s1, s2);
                    ignored_files.push(path.to_str().unwrap().to_string());
                    crls.push(path.to_str().unwrap().to_string());
                    continue;
                }
                // println!("Mft: {} , CRL: {}, {}", mft.clone().unwrap(), e.file_name().to_str().unwrap().to_string().split(".").next().unwrap(), mft.clone().unwrap().contains( e.path().to_str().unwrap().to_string().split(".").next().unwrap()));
            }
            if crl.is_some() {
                ignored_files.push(path.to_str().unwrap().to_string());

                continue;
            }

            crl = Some(path.to_str().unwrap().to_string());
            crls.push(path.to_str().unwrap().to_string());
        } else if e.file_name().to_str().unwrap().ends_with("cer")
            || e.file_name().to_str().unwrap().ends_with("q7Tq8.roa")
            || e.file_name().to_str().unwrap().ends_with(".gbr")
        {
            // Child certs are not important to as ATM
            continue;
        } else {
            objects.push(path.to_str().unwrap().to_string());
        }
    }

    // let mut crl_mft_pairs = vec![];
    // for i in 0..mfts.len(){
    //     let mft = &mfts[i];

    //     let mut found_one = false;
    //     for j in 0..crls.len(){
    //         let crl = &crls[j];

    //         if mft.contains(&Path::new(&crl).file_name().unwrap().to_str().unwrap().split(".").next().unwrap()){
    //             crl_mft_pairs.push((mft.clone(), crl.clone()));
    //             found_one = true;
    //             break;
    //         }

    //     }

    //     // This is not ideal but should never happen
    //     if !found_one{
    //         ignored_files.push(mft.clone());
    //     }
    // }

    // let chosen_index = 0;
    // let mft = Some(crl_mft_pairs[chosen_index].0.clone());
    // let crl = Some(crl_mft_pairs[chosen_index].1.clone());
    // for i in 0..crl_mft_pairs.len(){
    //     if i != chosen_index{
    //         ignored_files.push(crl_mft_pairs[i].0.clone());
    //         ignored_files.push(crl_mft_pairs[i].1.clone());
    //     }
    // }

    if mft.is_none() || crl.is_none() {
        println!("Error in folder {}", &folder_uri);
    }

    if mft.is_none() && mfts.len() > 0 {
        mft = Some(mfts[0].clone());
    }
    if crl.is_none() && crls.len() > 0 {
        crl = Some(crls[0].clone());
    }

    (mft, crl, objects, ignored_files)
}

pub fn handle_cer_i(
    data: Vec<u8>,
    conf: &RepoConfig,
    parent_uri: Option<&str>,
    storage_uri: Option<&str>,
    ee_cert: bool,
) -> (Vec<u8>, Vec<(u8, IpBlock)>, i32) {
    let cert = asn1::parse_single::<asn1p::Certificate>(&data).unwrap();

    let mut ret = vec![];
    if !ee_cert {
        get_ips_from_cert(&mut ret, cert);
    }

    let parent = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.to_string() + "ta.der"));
    let child = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.to_string() + "newca.der"));

    // Key_int is the index of the key in the cert (Serving as the filename, e.g. 1.der)
    let parsed;
    let key_int;
    if !ee_cert {
        (parsed, key_int) = cert::parse_and_sign(
            Bytes::from(data),
            &parent,
            conf,
            &child.get_pub_key(),
            "newca",
            parent_uri,
            storage_uri,
            ee_cert,
        );
    } else {
        (parsed, key_int) = cert::parse_and_sign(
            Bytes::from(data),
            &child,
            conf,
            &child.get_pub_key(),
            "newca",
            parent_uri,
            storage_uri,
            ee_cert,
        );
    }

    // Return the IPs in the Certificate
    (parsed, ret, key_int)
}

pub fn handle_cer(cer_uri: &str, conf: &RepoConfig) -> (Vec<u8>, Vec<(u8, IpBlock)>, i32) {
    // println!("Reading cert {}", cer_uri);
    let data = fs::read(cer_uri).unwrap();
    handle_cer_i(data, conf, None, None, false)
}

pub fn handle_crl(crl_uri: &str, conf: &RepoConfig) -> Vec<u8> {
    let data = fs::read(crl_uri).unwrap();
    let signer = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.to_string() + "newca.der"));
    let new_bytes = crl::parse_and_sign(Bytes::from(data), &signer);
    return new_bytes;
}

pub fn extend_signed_attr(sa: &Vec<u8>) -> Vec<u8> {
    let len = sa.len();
    let mut res = Vec::with_capacity(len + 4);
    res.push(0x31); // SET
    if len < 128 {
        res.push(len as u8)
    } else if len < 0x10000 {
        res.push(2);
        res.push((len >> 8) as u8);
        res.push(len as u8);
    } else {
        panic!("overly long signed attrs");
    }
    res.extend_from_slice(sa);
    res
}

pub fn handle_signed_object(data: &Bytes, storage_uri: &str, conf: &RepoConfig) -> Vec<u8> {
    let mut obj = asn1::parse_single::<asn1p::ContentInfoSpec>(&data);

    if obj.is_err() {
        return vec![];
    }
    let mut obj = obj.unwrap();
    // let mut ret = vec![];
    let change_validity = false;

    let mut content = obj.content.unwrap();

    // Handle Certificate
    let c;
    let mut cer_data = vec![];
    for cert in content.certificates.unwrap() {
        c = cert;
        cer_data = asn1::write_single(&c).unwrap();
        break;
    }

    let parent_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "ta/newca.cer";
    let (cer_bytes, _, key_int) = handle_cer_i(cer_data, conf, Some(&parent_uri), Some(storage_uri), true);
    let cert_new = asn1::parse_single::<asn1p::Certificate>(&cer_bytes).unwrap();
    let sw = asn1::SetOfWriter::new(vec![cert_new]);
    let tmp = asn1::write_single(&sw).unwrap();
    let v = asn1::parse_single::<asn1::SetOf<asn1p::Certificate>>(&tmp).unwrap();
    content.certificates = Some(v);

    // Handle SignerInfos
    let signer = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.to_string() + &key_int.to_string() + ".der"));

    let si_raw = asn1::write_single(&content.signerInfos).unwrap();
    let si_set = asn1::parse_single::<asn1::SetOf<asn1p::SignerInfos>>(&si_raw).unwrap();
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

pub fn get_filename(data: &str) -> String {
    let s: Vec<&str> = data.split("/").collect();
    let filename = s[s.len() - 1];
    filename.to_string()
}

pub fn handle_objects(object_uris: Vec<String>, conf: &RepoConfig) -> HashMap<String, Vec<u8>> {
    let mut ret = HashMap::new();

    let base_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "newca/";
    let local_base = conf.BASE_REPO_DIR_l.to_string() + "newca/";
    for obj_uri in object_uris {
        let filename = get_filename(&obj_uri);
        let obj = fs::read(&obj_uri).unwrap();
        let storage_uri = base_uri.clone() + &filename;
        let parsed = handle_signed_object(&Bytes::from(obj), &storage_uri, conf);
        if parsed.is_empty() {
            continue;
        }
        fs::write(local_base.clone() + &filename, &parsed).unwrap();
        ret.insert(filename.clone(), parsed);
    }
    ret
}

pub fn is_ber(content: Bytes) -> bool {
    let by: &[u8] = &content.to_vec();

    let signed = SignedObject::decode(by, false);
    if signed.is_ok() {
        let signed = SignedObject::decode(by, true);
        return signed.is_err();
    }

    false
}

pub fn convert_to_ber(content: Bytes) -> Bytes {
    let by: &[u8] = &content.to_vec();

    let signed = SignedObject::decode(by, false);
    if signed.is_err() {
        return content;
    }
    let signed = signed.unwrap();
    let r = signed.encode_ref();
    let mut target = vec![];
    signed.encode_ref().write_encoded(Mode::Ber, &mut target).unwrap();
    target.into()
}

pub fn handle_mft(data: &Bytes, crl_data: (String, Vec<u8>), entries: HashMap<String, Vec<u8>>, conf: &RepoConfig) -> Vec<u8> {
    let mut parsed = asn1::parse_single::<asn1p::ContentInfoMft>(&data).unwrap();
    let mut mft = parsed.content.unwrap();
    let change_validity = false;

    // First handle content
    let econ = mft.encapContentInfo.eContent.unwrap();
    let mut manifest = econ.get();

    let mut new_entries = vec![];
    let mut bytes_vec = vec![];
    let mut bs;

    let tmp: &[u8] = &crl_data.1;
    let hash = sha256::digest(tmp);
    let hash = <[u8; 32]>::from_hex(hash).unwrap();
    let hash = Bytes::from(hash.to_vec().clone());
    bytes_vec.push((crl_data.0, hash));

    let mut seen = vec![];

    for entr in manifest.fileHash.clone() {
        let s = entr.file.as_str().to_string();

        if !entries.contains_key(&s) && !s.ends_with("crl") && !s.ends_with("mft") {
            let new_entry = asn1p::FileAndHash {
                file: entr.file,
                hash: entr.hash,
            };
            // new_entries.push(new_entry);
            continue;
        } else if !entries.contains_key(&s) {
            continue;
        }

        let e: &[u8] = &entries.get(&s).unwrap();
        let hash = sha256::digest(e);
        let hashi = <[u8; 32]>::from_hex(hash).unwrap();
        let out_tmp = Bytes::from(hashi.to_vec().clone());
        bytes_vec.push((s.clone(), out_tmp.clone()));
        seen.push(s.clone());
    }

    for x in entries {
        if x.0.ends_with("crl") || x.0.ends_with("mft") || seen.contains(&x.0) {
            continue;
        }
        let e: &[u8] = &x.1;
        let hash = sha256::digest(e);
        let hashi = <[u8; 32]>::from_hex(hash).unwrap();
        let out_tmp = Bytes::from(hashi.to_vec().clone());
        bytes_vec.push((x.0.clone(), out_tmp.clone()));
    }

    for i in 0..bytes_vec.len() {
        let b = &bytes_vec[i];
        bs = asn1::BitString::new(&b.1, 0).clone();
        let bs = bs.unwrap();
        let new_entry = asn1p::FileAndHash {
            file: asn1::IA5String::new(&b.0).unwrap(),
            hash: bs,
        };
        new_entries.push(new_entry);
    }

    let sw = asn1::SequenceOfWriter::new(new_entries.clone());

    let tmp = asn1::write_single(&sw).unwrap();
    let sw = asn1::parse_single::<asn1::SequenceOf<asn1p::FileAndHash>>(&tmp).unwrap();

    let t = chrono::offset::Utc::now();
    let nt = t.with_nanosecond(0).unwrap();

    let c;
    let d;
    if change_validity {
        c = asn1::GeneralizedTime::new(nt.into()).unwrap();
        d = asn1::GeneralizedTime::new((nt + Duration::days(5)).into()).unwrap();
    } else {
        c = manifest.thisUpdateTime.clone();
        d = manifest.nextUpdateTime.clone().unwrap();
    }
    // manifest.thisUpdateTime.clone()
    // manifest.nextUpdateTime.clone(),

    let newmft = asn1p::Manifest {
        manifestNumber: manifest.manifestNumber,
        thisUpdateTime: c,
        nextUpdateTime: Some(d),
        fileHash: sw,
        fileHashAlg: manifest.fileHashAlg.clone(),
    };
    mft.encapContentInfo.eContent = Some(asn1::OctetStringEncoded::new(newmft));

    parsed.content = Some(mft);

    let new_bytes = asn1::write_single(&parsed).unwrap();

    let cert_key_path = conf.BASE_KEY_DIR_l.clone() + "newca.der";
    let filename = repository::get_filename_crl_mft(&cert_key_path);
    let storage_uri = "rsync://".to_string() + &conf.DOMAIN + "/" + &conf.BASE_REPO_DIR + "newca/" + &filename + ".mft";
    handle_signed_object(&Bytes::from(new_bytes), &storage_uri, conf)
    // return new_entries.as_slice().to_vec().clone();
}

pub fn find_base(cer_uri: &str, folder_uri: &str) -> Option<String> {
    for i in 0..folder_uri.matches("/").count() {
        let tmp = folder_uri.split("/").collect::<Vec<&str>>();
        let tmp = tmp[0..tmp.len() - i].to_vec();
        let tmp = tmp.join("/");
        let tmp = tmp + "/";
        let cert = tmp.clone() + cer_uri;
        let md = fs::metadata(cert.clone());
        if md.is_ok() && md.unwrap().is_file() {
            return Some(cert);
        }
    }

    // In depth search if its not in the same folder
    let c = cer_uri.split("/").collect::<Vec<&str>>();
    let mut cer_name = c.last().unwrap();
    if cer_name.is_empty() {
        println!("Was empty");
        cer_name = &c[c.len() - 2];
    }
    for i in 0..folder_uri.matches("/").count() {
        let tmp = folder_uri.split("/").collect::<Vec<&str>>();
        let tmp = tmp[0..tmp.len() - i].to_vec();
        let tmp = tmp.join("/");
        let tmp = tmp + "/";
        let fs = find_files_with_extension(&tmp, "cer");
        for f in fs {
            if f.ends_with(cer_name) {
                return Some(f);
            }
        }
    }
    return None;
}

pub fn find_entry(vec1: &Vec<RoaContents>, val: &RoaContents) -> (bool, bool) {
    if val.ip_addr.is_ipv4() && val.prefix > 24 || val.ip_addr.is_ipv6() && val.prefix > 48 {
        return (false, true);
    }
    for v in vec1 {
        if v.as_id != val.as_id {
            continue;
        }
        let p = v.prefix.clone();
        let p2 = val.prefix.clone();

        if v.ip_addr.is_ipv4() && val.ip_addr.is_ipv4() {
            let net1 = Ipv4Net::new(Ipv4Addr::from_str(&v.ip_addr.to_string()).unwrap(), p).unwrap();
            let net2 = Ipv4Net::new(Ipv4Addr::from_str(&val.ip_addr.to_string()).unwrap(), p2).unwrap();

            if net1.contains(&net2) {
                return (true, false);
            }
        } else if v.ip_addr.is_ipv6() && val.ip_addr.is_ipv6() {
            let net1 = Ipv6Net::new(Ipv6Addr::from_str(&v.ip_addr.to_string()).unwrap(), p).unwrap();
            let net2 = Ipv6Net::new(Ipv6Addr::from_str(&val.ip_addr.to_string()).unwrap(), p2).unwrap();

            if net1.contains(&net2) {
                return (true, false);
            }
        }
    }
    // println!("NOPE {}/{}", val.ip_addr, val.prefix);
    return (false, false);
}

pub fn check_only_octo(v: &Vec<Vec<RoaContents>>) -> (i32, i32) {
    let mut has_super_net = 0;
    let mut large_prefix = 0;
    // OctoRPKI is at array position [1]

    if !(v[0].len() == v[2].len() && v[0].len() == v[3].len() && v[0].len() != v[1].len()) {
        return (0, 0);
    } else {
        let ov = &v[1];
        for val in &v[0] {
            if ov.contains(&val) {
                continue;
            }
            let (a, b) = find_entry(&ov, val);
            if a {
                has_super_net += 1;
            } else if b {
                large_prefix += 1;
            }
        }
    }
    return (has_super_net, large_prefix);
}

pub fn check_mft_validity(folder_uri: &str) -> (asn1::GeneralizedTime, asn1::GeneralizedTime) {
    let (mft, crl, objects, _) = load_objects(folder_uri);
    let mft_raw = fs::read(&mft.unwrap()).unwrap();
    let mut parsed = asn1::parse_single::<asn1p::ContentInfoMft>(&mft_raw).unwrap();
    let tmp = parsed.content.unwrap();
    let tmp = tmp.encapContentInfo.eContent.unwrap();
    let mft = tmp.get();
    let this_update = mft.thisUpdateTime.clone();
    let next_update = mft.nextUpdateTime.clone().unwrap().clone();
    return (this_update, next_update);
}

pub fn handle_ignored_files(file_uris: Vec<String>, conf: &RepoConfig) -> HashMap<String, Vec<u8>> {
    let mut ret = HashMap::new();

    for uri in file_uris {
        let p = Path::new(&uri);
        let filename = p.file_name().unwrap().to_str().unwrap().to_string();
        let con = fs::read(&uri).unwrap();
        let fixed;
        if filename.ends_with("crl") {
            fixed = handle_crl(&uri, conf);
        } else {
            fixed = fix_econtent(con.into(), &conf);
        }
        fs::write(&(conf.BASE_REPO_DIR_l.to_string() + "newca/" + &filename), &fixed).unwrap();
        ret.insert(uri, fixed);
    }
    ret
}

pub fn handle_folder(folder_uri: &str) -> bool {
    let (mft, crl, objects, ignored_files) = load_objects(folder_uri);
    let mft = mft.unwrap();
    let crl = crl.unwrap();

    let cert_uri_r = get_issuer_cert_uri(&mft);

    if cert_uri_r.is_empty() {
        // println!("Error: Could not parse issuer cert uri");
        // println!("Object {}", base64::encode(fs::read(&mft).unwrap()));
        return true;
    }

    let base_i = find_base(&cert_uri_r, folder_uri);
    if base_i.is_none() {
        println!("Error: Could not find base");
        return true;
    }
    let base = base_i.unwrap();
    let cert_uri;
    // If we have an absolute path, take this path, else prepend the base
    if base.starts_with("/") {
        cert_uri = base;
    } else {
        cert_uri = base.to_string() + &cert_uri_r;
    }

    let mut conf = repository::create_default_config("my.server.com".to_string());

    // First handle Certificate
    let (cert_bytes, ips, _) = handle_cer(&cert_uri, &conf);
    conf.IPBlocks.extend(ips);

    repository::initialize_repo(&mut conf, false, None);
    fs::write(&(conf.BASE_REPO_DIR_l.to_string() + "ta/newca.cer"), cert_bytes).unwrap();

    // Handle CRL
    let crl_bytes = handle_crl(&crl, &conf);
    let cert_key_path = conf.BASE_KEY_DIR_l.to_string() + "newca.der";
    let raw_filename = repository::get_filename_crl_mft(&cert_key_path);
    let crl_filename = raw_filename.clone() + ".crl";
    fs::write(conf.BASE_REPO_DIR_l.clone() + "newca/" + &crl_filename, &crl_bytes).unwrap();

    // Handle Objects
    let mut objects = handle_objects(objects, &conf);

    // Handle Ignored MFTs and CRLs
    // let add_obj = handle_ignored_files(ignored_files, &conf);
    // objects.extend(add_obj);

    // Handle MFT
    let mft_raw = fs::read(&mft).unwrap();
    let mft_bytes = handle_mft(&Bytes::from(mft_raw), (crl_filename, crl_bytes), objects, &conf);
    let mft_filename = raw_filename + ".mft";
    fs::write(conf.BASE_REPO_DIR_l.clone() + "newca/" + &mft_filename, mft_bytes).unwrap();

    // Create remaining objects
    repository::make_manifest("ta", "root", &conf);
    let (session_id, serial_number) = repository::get_current_session_notification(&conf);
    repository::finalize_snap_notification(session_id, serial_number, vec![], vec![], &conf);

    return false;
}

pub fn bitstring_to_ip(bs: asn1::BitString, family: u8) -> (IpAddr, u8) {
    let c = bs.as_bytes();
    let pre_len = (c.len() * 8) - bs.padding_bits() as usize;

    if family == 1 {
        let mut tmp_arr: [u8; 4] = [0 as u8, 0 as u8, 0 as u8, 0 as u8];
        for i in 0..4 {
            if i < c.len() {
                tmp_arr[i] = c[i];
            }
        }

        let ipa = Ipv4Addr::from(tmp_arr);
        return (IpAddr::from(ipa), pre_len as u8);
    } else {
        let mut tmp_arr: [u8; 16] = [0 as u8; 16];
        for i in 0..16 {
            if i < c.len() {
                tmp_arr[i] = c[i];
            }
        }
        let ipa = Ipv6Addr::from(tmp_arr);
        return (IpAddr::from(ipa), pre_len as u8);
    }
}

pub fn example_bs() -> RepoConfig {
    let mut conf = repository::create_default_config("my.server.com".to_string());
    let a1 = Addr::from_v4_str("1.1.1.0").unwrap();
    let a2 = Addr::from_v4_str("1.1.2.0").unwrap();
    let b = IpBlock::from((a1, a2, 24 as u8, 24 as u8));
    conf.IPBlocks.extend(vec![(1, b)]);

    conf
}

pub fn get_ips_from_cert(ret: &mut Vec<(u8, IpBlock)>, cert: asn1p::Certificate) {
    let extensions = cert.tbsCert.resourceCertificateExtensions.unwrap();
    for ext in extensions {
        let by = asn1::write_single(&ext).unwrap();
        let ex = asn1::parse_single::<asn1p::ExtensionValue>(&by).unwrap();

        if ex.identifier.to_string() == "1.3.6.1.5.5.7.1.7".to_string() {
            let w = asn1::write_single(&ex.value).unwrap();
            let oc = asn1::parse_single::<asn1::OctetStringEncoded<asn1::SequenceOf<asn1p::ipAddrBlocks>>>(&w).unwrap();
            for blocks in oc.get().clone().into_iter() {
                let fam = blocks.addressFamily[1];

                for a in blocks.addresses.unwrap() {
                    let r = asn1::write_single(&a).unwrap();

                    // Since this is a choice, it can either be a bit string or a range
                    let c = asn1::parse_single::<asn1::BitString>(&r);

                    if c.is_ok() {
                        let addr_raw = c.unwrap();
                        let a = bitstring_to_ip(addr_raw, fam);
                        let pre = resources::Prefix::new(a.0, a.1);
                        let bl = IpBlock::from(pre);
                        ret.push((fam, bl));
                    } else {
                        let r = asn1::parse_single::<asn1p::IpAddrRange>(&r).unwrap();
                        let a1 = bitstring_to_ip(r.min.clone(), fam);
                        let a2 = bitstring_to_ip(r.max.clone(), fam);

                        let pre1 = Addr::from(a1.0);

                        let pre2 = Addr::from(a2.0);

                        let bl = IpBlock::from((pre1, pre2, a1.1, a2.1));

                        ret.push((fam, bl));
                    }
                }
            }
        }
    }
}

pub fn get_content_ips(content: Bytes) -> Vec<(u8, IpBlock)> {
    let mut new_obj = asn1::parse_single::<asn1p::ContentInfo>(&content).unwrap();
    let cont = new_obj.content.unwrap();
    let tmp = cont.encapContentInfo.eContent.unwrap();
    let c = tmp.get();
    // let mut ret4 = vec![];
    // let mut ret6 = vec![];
    let mut ret = vec![];

    let x = cont.certificates.unwrap();
    for cert in x {
        get_ips_from_cert(&mut ret, cert);
    }
    ret

    // for b in c.ipAddrBlocks.clone(){
    //     let fam = b.addressFamily[1];
    //     for a in b.addresses{
    //         let c = a.address.as_bytes();
    //         let pre_len = (c.len()*8) - a.address.padding_bits() as usize;

    //         if fam == 1{
    //             let mut tmp_arr: [u8; 4] = [0 as u8, 0 as u8, 0 as u8, 0 as u8];
    //             for i in 0..4{
    //                 if i < c.len(){
    //                     tmp_arr[i] = c[i];
    //                 }
    //             }
    //             ret4.push(Ipv4Net::new(Ipv4Addr::from(tmp_arr), pre_len.try_into().unwrap()).unwrap());
    //         }
    //         else{
    //             let mut tmp_arr: [u8; 16] = [0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8];
    //             for i in 0..16{
    //                 if i < c.len(){
    //                     tmp_arr[i] = c[i];
    //                 }
    //             }
    //             ret6.push(Ipv6Net::new(Ipv6Addr::from(tmp_arr), pre_len.try_into().unwrap()).unwrap());
    //         }
    //     }
    // }
    // (ret4, ret6)
}

pub fn fix_econtent(content: Bytes, conf: &RepoConfig) -> Vec<u8> {
    let parent_key = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.clone() + "ta.der"));

    let ca_key = repository::read_cert_key(&(conf.BASE_KEY_DIR_l.clone() + "newca.der"));

    let mut new_obj = asn1::parse_single::<asn1p::SignedDataObjectSpec>(&content).unwrap();
    let mut certificate = None;
    let mut con = new_obj.content.unwrap();
    for v in con.certificates.unwrap() {
        certificate = Some(v);
        break;
    }
    if certificate.is_none() {
        return vec![];
    }
    let cert = certificate.unwrap();

    let bi = asn1::write_single(&cert).unwrap();
    let (new_cert, _) = cert::parse_and_sign(bi.into(), &ca_key, &conf, &parent_key.get_pub_key(), "newca", None, None, false);
    let v = asn1::parse_single::<asn1p::Certificate>(&new_cert).unwrap();

    let w = asn1::SetOfWriter::new(vec![v]);
    let tmp = asn1::write_single(&w).unwrap();
    let s = asn1::parse_single::<asn1::SetOf<asn1p::Certificate>>(&tmp);
    con.certificates = Some(s.unwrap());
    new_obj.content = Some(con);

    let new_obj = asn1::write_single(&new_obj).unwrap();

    new_obj
}

fn check_prefix_len(ip: String) -> bool {
    let pre_len = ip.split("/").collect::<Vec<&str>>()[1].parse::<i32>().unwrap();
    if ip.contains(":") {
        return false;
    } else {
        return pre_len > 24;
    }
}

pub fn load_vrps(self_run: bool) -> Vec<Vec<String>> {
    let base = util::get_cwd() + "/output/";
    let mut vrps_locations = vec![];
    let rp_names = vec!["routinator", "octo", "fort", "client"];

    for n in rp_names {
        vrps_locations.push(base.clone().to_string() + "vrps_" + n + ".txt");
    }

    if !self_run {
        vrps_locations = vec![];
    }

    let mut vrps_s = vec![];
    for loc in vrps_locations {
        // println!("{}", loc);
        vrps_s.push(fs::read_to_string(loc).unwrap());
    }

    let mut more_spec = vec![0, 0, 0, 0];

    let mut all_vrps = vec![];
    for i in 0..vrps_s.len() {
        println!("Handling i {}", i);
        let v = vrps_s[i].clone();
        let mut vrps = vec![];

        // In case of octo we need to handle it as JSON
        if i == 1 {
            if self_run {
                // println!("Handling octo {}", &v);
            }
            let js: Value = serde_json::from_str(&v).unwrap();
            let a = &js["roas"];
            let b = a.as_array().unwrap();

            for roa in b {
                let ip_r = roa["prefix"].to_string();
                let ip = ip_r[1..ip_r.len() - 1].to_string();
                let asn_r = roa["asn"].to_string();
                let mut asn;
                if i == 3 {
                    asn = asn_r.clone();
                } else {
                    asn = asn_r[1..asn_r.len() - 1].to_string();
                }
                if !asn.starts_with("AS") {
                    asn = "AS".to_string() + &asn;
                }
                // if i == 0{
                //     println!("asn vs asn_r {} {}", asn, asn_r);
                // }
                let maxlength = roa["maxLength"].to_string();

                if check_prefix_len(ip.clone()) {
                    // Dont add larger than /24 in IPv4
                    more_spec[i] += 1;
                    continue;
                }

                let s = asn + "," + &ip + "," + &maxlength;

                vrps.push(s);
            }
        }
        // In all other cases handle it as CSV
        else {
            let mut skipped_first_line = false;
            for u in v.split("\n") {
                if !skipped_first_line {
                    skipped_first_line = true;
                    continue;
                }
                if u.is_empty() {
                    continue;
                }
                let s: Vec<String> = u.split(",").map(|x| x.to_string()).collect();
                if check_prefix_len(s[1].clone()) {
                    // Dont add larger than /24 in IPv4
                    more_spec[i] += 1;

                    continue;
                }
                vrps.push(s[0].clone() + "," + &s[1].clone() + "," + &s[2].clone());
            }
        }

        all_vrps.push(vrps);
    }

    println!("Length routinator: {}", all_vrps[0].len());
    println!("Length octorpki: {}", all_vrps[1].len());
    println!("Length fort: {}", all_vrps[2].len());
    println!("Length client: {}", all_vrps[3].len());
    // println!("More Specifics: {:?}", more_spec);

    all_vrps
}

pub fn store_roa_map(map: HashMap<String, String>) {
    let mut ret = "".to_string();
    for e in map.keys() {
        let value = map.get(e);
        ret += &(e.clone() + "|" + value.unwrap() + "\n");
    }
    fs::write("roa_map.txt", ret).unwrap();
}

pub fn load_roa_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let content = fs::read_to_string("roa_map.txt").unwrap();
    for line in content.split("\n") {
        if line.is_empty() {
            continue;
        }
        let s: Vec<String> = line.split("|").map(|x| x.to_string()).collect();
        map.insert(s[0].clone(), s[1].clone());
    }
    map
}

pub fn indepth_analysis() {
    let roa_map = load_roa_content(None);
    store_roa_map(roa_map);
    let roa_map = load_roa_map();

    let (not_in, vrps) = analyse_vrps(false);
    println!("{:?}", not_in[0]);
    for i in 0..not_in.len() {
        println!("{}: {}", i, not_in[i].len());
    }

    let mut c = 0;
    for en in not_in[3].iter() {
        c += 1;
        if c > 10 {
            break;
        }
        println!("{}, {}", en, roa_map.get(en).unwrap());
    }
}

pub fn analyse_vrps(self_run: bool) -> (Vec<HashSet<String>>, Vec<Vec<String>>) {
    let all_vrps = load_vrps(self_run);
    let set_r: HashSet<String> = HashSet::from_iter(all_vrps[0].iter().cloned());
    let set_o: HashSet<String> = HashSet::from_iter(all_vrps[1].iter().cloned());
    let set_f: HashSet<String> = HashSet::from_iter(all_vrps[2].iter().cloned());
    let set_c: HashSet<String> = HashSet::from_iter(all_vrps[3].iter().cloned());

    let mut all_sets = HashSet::new();
    all_sets.extend(set_r.clone());
    all_sets.extend(set_f.clone());
    all_sets.extend(set_o.clone());
    all_sets.extend(set_c.clone());

    let mut not_in = vec![HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new()];

    for entr in all_sets {
        if !set_r.contains(&entr) {
            not_in[0].insert(entr.clone());
        }
        if !set_o.contains(&entr) {
            not_in[1].insert(entr.clone());
        }
        if !set_f.contains(&entr) {
            not_in[2].insert(entr.clone());
        }
        if !set_c.contains(&entr) {
            not_in[3].insert(entr.clone());
        }
    }

    (not_in, all_vrps)
}

fn find_files_with_extension(folder_uri: &str, file_extension: &str) -> Vec<String> {
    let folder_path = Path::new(folder_uri);
    let mut files = Vec::new();

    if let Ok(entries) = fs::read_dir(folder_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    files.extend(find_files_with_extension(path.to_str().unwrap(), file_extension));
                } else if let Some(extension) = path.extension() {
                    if extension == file_extension {
                        files.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    files
}

pub fn find_roas(bases: Vec<&str>) -> Vec<Vec<String>> {
    let mut roa_uris = vec![];
    for base in bases {
        let r = find_files_with_extension(base, "roa");
        roa_uris.push(r.clone());
        println!("Found {} ROAs", r.len());
    }

    roa_uris
}

pub fn find_mfts(bases: Vec<&str>) -> Vec<Vec<String>> {
    let mut roa_uris = vec![];
    for base in bases {
        let r = find_files_with_extension(base, "mft");
        roa_uris.push(r);
        // println!("Found {} ROAs", r.len());
    }

    roa_uris
}

pub fn handle_uniqueness4(umap: &HashMap<String, Vec<(Ipv4Net, u8)>>, key: &str, net: (Ipv4Net, u8)) -> Vec<(Ipv4Net, u8)> {
    if umap.contains_key(key) {
        let addr_vec = umap.get(key).unwrap();
        let mut ret = vec![];
        let mut i = 0;
        let mut was_contained = false;
        for addr in addr_vec {
            i += 1;

            // TODO Maxlength
            if addr.0.contains(&net.0) {
                ret.push(*addr);
                was_contained = true;
                break;
            } else if net.0.contains(&addr.0) {
                ret.push(net);
                was_contained = true;
                break;
            } else {
                ret.push(*addr);
            }
        }
        if was_contained {
            for j in i..addr_vec.len() {
                ret.push(addr_vec[j]);
            }
        } else {
            ret.push(net);
        }

        return ret;
    } else {
        return vec![net];
    }
}

// This is not pretty at all but the module is private and I cant be bothered making this more pretty atm
pub fn handle_uniqueness6(umap: &HashMap<String, Vec<(Ipv6Net, u8)>>, key: &str, net: (Ipv6Net, u8)) -> Vec<(Ipv6Net, u8)> {
    if umap.contains_key(key) {
        let addr_vec = umap.get(key).unwrap();
        let mut ret = vec![];
        let mut i = 0;
        let mut was_contained = false;
        for addr in addr_vec {
            i += 1;

            if addr.0.contains(&net.0) {
                ret.push(*addr);
                was_contained = true;
                break;
            } else if net.0.contains(&addr.0) {
                ret.push(net);
                was_contained = true;
                break;
            } else {
                ret.push(*addr);
            }
        }
        if was_contained {
            for j in i..addr_vec.len() {
                ret.push(addr_vec[j]);
            }
        } else {
            ret.push(net);
        }

        return ret;
    } else {
        return vec![net];
    }
}

pub fn vrps_from_roa(content: Bytes) -> Vec<String> {
    let roa_r = asn1::parse_single::<asn1p::ContentInfo>(&content);
    let roa;
    let b;
    let mut ret = vec![];
    if roa_r.is_err() {
        // Some objects are still BER encoded, we use rpki parsing to decode them
        let by: &[u8] = &content.to_vec();

        let signed = SignedObject::decode(by, false);
        if signed.is_err() {
            return vec![];
        }
        let signed = signed.unwrap();
        b = signed.content().to_bytes();
        let ro = asn1::parse_single::<asn1p::ROA>(&b);
        if ro.is_err() {
            return vec![];
        }
        roa = ro.unwrap();
        // println!("Was BER");
    } else {
        let tmp = roa_r.unwrap();
        let tmp = tmp.content.unwrap().encapContentInfo.eContent.unwrap();
        roa = tmp.get().clone();
    }
    let as_id = roa.asID;

    for i in roa.ipAddrBlocks.clone() {
        for add in i.addresses {
            let b = add.address.as_bytes();

            let pre_len = (b.len() * 8) - add.address.padding_bits() as usize;

            let ml = match add.maxLength {
                Some(x) => x,
                None => pre_len as u8,
            };
            let adr_s;
            let mut net4 = None;
            let mut net6 = None;
            if i.addressFamily[1] == 1 {
                let mut tmp_arr: [u8; 4] = [0 as u8, 0 as u8, 0 as u8, 0 as u8];
                for i in 0..4 {
                    if i < b.len() {
                        tmp_arr[i] = b[i];
                    }
                }

                let ad = Ipv4Addr::from(tmp_arr);
                net4 = Some((Ipv4Net::new(ad, pre_len.try_into().unwrap()).unwrap(), ml));
                adr_s = ad.to_string() + "/" + &pre_len.to_string();
            } else if i.addressFamily[1] == 2 {
                let mut tmp_arr: [u8; 16] = [
                    0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8, 0 as u8,
                    0 as u8, 0 as u8, 0 as u8,
                ];
                for i in 0..16 {
                    if i < b.len() {
                        tmp_arr[i] = b[i];
                    }
                }

                let ad = Ipv6Addr::from(tmp_arr);
                net6 = Some((Ipv6Net::new(ad, pre_len.try_into().unwrap()).unwrap(), ml));
                adr_s = ad.to_string() + "/" + &pre_len.to_string();
            } else {
                println!("Unknown address family {}", i.addressFamily[1]);
                continue;
            }

            // let addr = Ipv4Addr::new(tmp_arr[0], tmp_arr[1], tmp_arr[2], tmp_arr[3]);
            let out = "AS".to_string() + &as_id.to_string() + "," + &adr_s + "," + &ml.to_string();
            ret.push(out);
        }
    }
    return ret;
}

pub fn as_anal() {
    let (miss, all_vrps) = analyse_vrps(false);
    // Routinator, Octo, Fort, Client
    let mut cause_prefix = 0;

    let mut removed_pres: HashMap<String, i32> = HashMap::new();

    for v in miss[1].clone().into_iter() {
        let parts = v.split(",").collect::<Vec<&str>>();
        let as_id = parts[0].to_string();
        let net = parts[1].to_string();

        let is_v4 = net.contains(".");
        let ml = parts[2].to_string();
        let ip = net.parse::<IpNet>().unwrap();
        let pl = ip.prefix_len();
        if is_v4 && pl > 24 || !is_v4 && pl > 48 {
            cause_prefix += 1;
            if removed_pres.contains_key(&as_id) {
                let mut val: i32 = removed_pres.get(&as_id).unwrap().to_owned();
                val += 1;
                removed_pres.insert(as_id, val);
            } else {
                removed_pres.insert(as_id, 1);
            }
        } else {
            // println!("Not this {}", v);
        }
    }

    println!("Cause prefix: {}/{}", cause_prefix, miss[1].len());
    println!("Removed prefixes: {:?}/{}", removed_pres, miss[1].len());
    println!("Contains {}", removed_pres.keys().len());
}

pub fn as_anal3() {
    let (miss, all_vrps) = analyse_vrps(false);
    // Routinator, Octo, Fort, Client
    let mut cause_prefix = 0;
    let mut ct = 0;

    let mut removed_pres: HashMap<String, i32> = HashMap::new();

    for v in miss[0].clone().into_iter() {
        let parts = v.split(",").collect::<Vec<&str>>();
        let as_id = parts[0].to_string();
        let net = parts[1].to_string();

        let is_v4 = net.contains(".");
        let ml = parts[2].to_string();
        let ip = net.parse::<IpNet>().unwrap();
        let pl = ip.prefix_len();
        if as_id == "AS39891" {
            cause_prefix += 1;
        }
    }

    for v in all_vrps[2].clone().into_iter() {
        let parts = v.split(",").collect::<Vec<&str>>();
        let as_id = parts[0].to_string();
        let net = parts[1].to_string();

        let is_v4 = net.contains(".");
        let ml = parts[2].to_string();
        let ip = net.parse::<IpNet>().unwrap();
        let pl = ip.prefix_len();
        if as_id == "AS39891" {
            ct += 1;
        }
    }

    println!("Cause prefix: {}/{}", cause_prefix, miss[1].len());
    println!("CT {}", ct);
    println!("Contains {}", removed_pres.keys().len());
}

pub fn as_anal2() {
    // let roa_map = load_roa_content(None);
    // store_roa_map(roa_map.clone());
    let roa_map = load_roa_map();
    let (miss, all_vrps) = analyse_vrps(false);
    // Routinator, Octo, Fort, Client
    let mut cause_prefix = 0;

    let mut removed_pres: HashMap<String, i32> = HashMap::new();

    let mut other_folders = HashSet::new();

    for v in miss[3].clone().into_iter() {
        let parts = v.split(",").collect::<Vec<&str>>();
        let as_id = parts[0].to_string();
        if as_id != "AS39891" {
            continue;
        }
        println!("Found one {}", v);

        let net = parts[1].to_string();

        let is_v4 = net.contains(".");
        let ml = parts[2].to_string();
        let ip = net.parse::<IpNet>().unwrap();
        let pl = ip.prefix_len();

        let roa_raw = fs::read(roa_map.get(&v).unwrap()).unwrap();
        let roa = asn1::parse_single::<asn1p::ContentInfoRoaFull>(&roa_raw);

        if roa.is_err() {
            println!("Parse Error");
            continue;
        }

        let roa = roa.unwrap();

        let roa = roa.content.unwrap();

        let (cs, vrp) = analyse_roa(roa);

        if !cs.certChars.unwrap().multiSubjectField {
            let folder = Path::new(&roa_map.get(&v).unwrap()).parent().unwrap().to_string_lossy().to_string();
            other_folders.insert(folder);
            continue;
        }

        cause_prefix += 1;

        if removed_pres.contains_key(&as_id) {
            let mut val: i32 = removed_pres.get(&as_id).unwrap().to_owned();
            val += 1;
            removed_pres.insert(as_id, val);
        } else {
            removed_pres.insert(as_id, 1);
        }
    }

    println!("Cause prefix: {}/{}", cause_prefix, miss[2].len());
    println!("Removed prefixes: {:?}/{}", removed_pres, miss[1].len());
    println!("Other folders {:?}", other_folders);
    // println!("Contains {}", removed_pres.contains_key("AS149013"));
}

pub fn load_roa_content(bases: Option<Vec<&str>>) -> HashMap<String, String> {
    let bases = match bases {
        Some(x) => x,
        None => {
            let ba = vec![];
            ba
        }
    };
    let all_uris = find_roas(bases);
    let mut all_entries = HashSet::new();
    let mut roa_map = HashMap::new();
    // let mut umap4 = HashMap::new();
    // let mut umap6 = HashMap::new();

    let mut v4 = 0;
    let mut v6 = 0;

    let mut parse_err = 0;

    let mut finsihed_rps = 0;
    for rp_u in all_uris {
        finsihed_rps += 1;
        for uri in rp_u {
            // println!("URI: {}", &uri);
            let content = fs::read(&uri).unwrap();
            let vrps = vrps_from_roa(content.into());

            for out in vrps {
                if out.contains("AS6939,2a07:54c2:b00b::/48") {
                    println!("Hurricane {}, {}", out.clone(), &uri);
                }
                // let net = Ipv4Net::new(addr, pre_len.try_into().unwrap()).unwrap();
                all_entries.insert(out.clone());
                roa_map.insert(out, uri.clone());
            }
        }
        println!("Finished RPs {}", finsihed_rps);
    }

    // Flatten map
    // let mut final_arr = vec![];
    // for k in umap4.keys(){
    //     let arr = umap4.get(k).unwrap();
    //     for v in arr{
    //         final_arr.push(v.0.to_string());
    //     }
    // }

    // for k in umap6.keys(){
    //     let arr = umap6.get(k).unwrap();
    //     for v in arr{
    //         final_arr.push(v.0.to_string());
    //     }
    // }

    // println!("All Entries {}", final_arr.len());
    // println!("Length 4: {}, Length 6: {}", umap4.len(), umap6.len());
    // println!("Unique entries {}", all_entries.len());
    // println!("V4: {}, V6: {}, Total: {}", v4, v6, v4 + v6);
    println!("Parse Errors {}", parse_err);

    roa_map
}

pub fn find_dif_roas(locations: Option<Vec<&str>>) -> Vec<(String, String)> {
    let roa_map = load_roa_content(locations);
    // for v in roa_map.keys(){
    //     if v.starts_with("AS6393"){
    //         println!("V {}", roa_map.get(&v).unwrap())
    //     }
    // }

    let all_vrps = load_vrps(false);
    let set_r: HashSet<String> = HashSet::from_iter(all_vrps[0].iter().cloned());
    let set_f: HashSet<String> = HashSet::from_iter(all_vrps[1].iter().cloned());
    let set_o: HashSet<String> = HashSet::from_iter(all_vrps[2].iter().cloned());
    let set_c: HashSet<String> = HashSet::from_iter(all_vrps[3].iter().cloned());

    // println!("roa_map {:?}", roa_map.keys());

    let mut deviating = vec![];

    let mut sets = HashSet::new();
    sets.extend(&set_r);
    sets.extend(&set_f);
    sets.extend(&set_o);
    sets.extend(&set_c);

    let mut co = 0;

    for v in sets {
        if !set_r.contains(v) || !set_f.contains(v) || !set_o.contains(v) || !set_c.contains(v) {
            // If any RP does not contain this ROA -> Store it
            if !roa_map.contains_key(v) {
                println!("Continued");
                continue;
            }
            let uri = roa_map.get(v).unwrap();
            deviating.push((v.clone(), uri.clone()));
        }
    }
    // println!("Deviating {}, {:?}", deviating.len(), deviating[0]);
    deviating
}

pub fn log_folders() {
    let dif_roas = find_dif_roas(None);
    println!("Dif roas {}", dif_roas.len());
    let mut dif_folders = HashSet::new();

    for roa in dif_roas {
        let folder = Path::new(&roa.1).parent().unwrap().to_string_lossy().to_string();
        dif_folders.insert(folder);
    }

    let mut output_s = "".to_string();
    for i in dif_folders {
        output_s += &i;
        output_s += "\n";
    }

    fs::write("dif_folders.txt", output_s).unwrap();
}

pub fn check_missing_vrps(uri: &str) -> (Vec<i32>, Vec<String>) {
    let ss = analyse_vrps(false).0;
    let mut all_vrps = vec![];

    println!("URI: {}", uri);

    for u in fs::read_dir(uri).unwrap() {
        let p = u.unwrap();
        let pa = p.path().to_str().unwrap().to_string();
        if pa.ends_with(".roa") {
            let con = fs::read(pa.clone()).unwrap();
            let vrps = vrps_from_roa(con.into());
            all_vrps.extend(vrps);
        }
    }

    let mut missing = vec![0, 0, 0, 0];
    for i in 0..ss.len() {
        for v in all_vrps.iter() {
            if ss[i].contains(v) {
                missing[i] += 1;
            }
        }
    }
    (missing, all_vrps)
}

pub fn folder_uri_from_cer(content: Bytes) -> String {
    let cert = asn1::parse_single::<asn1p::Certificate>(&content).unwrap();
    let ext = cert.tbsCert.resourceCertificateExtensions.unwrap();
    for e in ext {
        let tmp = asn1::write_single(&e).unwrap();
        let ev = asn1::parse_single::<asn1p::ExtensionValue>(&tmp).unwrap();
        if ev.identifier.to_string() == "1.3.6.1.5.5.7.1.11" {
            let tmp = asn1::write_single(&ev.value).unwrap();
            let sia = asn1::parse_single::<asn1p::SubjectInfoAccess>(&tmp).unwrap();
            let oc = sia.fields.get();
            for field in oc.clone().into_iter() {
                if field.identifier.to_string() == "1.3.6.1.5.5.7.48.5" {
                    return strip_rsync(field.val.unwrap().as_str());
                }
            }
        }
    }
    return "".to_string();
}

pub fn strip_rsync(uri: &str) -> String {
    if uri.contains("rsync") {
        let tmp = uri.split("rsync://").collect::<Vec<&str>>();
        let tmp = tmp[2..tmp.len()].to_vec();
        let tmp = tmp.join("/");

        return tmp.to_string();
    }
    uri.to_string()
}

// pub fn find_folder(base_uri: &str, uri: &str){
//     for i in 0..uri.matches("/").count(){
//         let tmp = uri.split("/").collect::<Vec<&str>>();
//         let tmp = tmp[i..tmp.len()].to_vec();
//         let tmp = tmp.join("/");
//         let tmp = tmp + "/";
//         let cert = tmp.clone() + cer_uri;
//         let md = fs::metadata(cert.clone());
//         if md.is_ok() && md.unwrap().is_file(){
//             return Some(cert);
//         }
//     }

//     let deepest = Path::new(uri).parent().unwrap().to_string_lossy().to_string();
// }

pub fn find_affected_entries(uri: &str, base_uri: &str) -> i32 {
    let mut c = 0;
    for u in fs::read_dir(uri).unwrap() {
        let p = u.unwrap();
        let pa = p.path().to_str().unwrap().to_string();
        if pa.ends_with(".roa") {
            let con = fs::read(pa.clone()).unwrap();
            let vrps = vrps_from_roa(con.into());
            c += vrps.len() as i32;
        } else if pa.ends_with(".cer") {
            let con = fs::read(pa.clone()).unwrap();
            let folder = folder_uri_from_cer(con.into());
            let folder = base_uri.to_string() + &folder;
            c += find_affected_entries(&folder, base_uri);
        }
    }
    return c;
}

pub fn analyse_extensions(exts: Vec<asn1p::ExtensionValue>) -> ExtCharacteristics {
    let count = exts.len();
    let mut crl_dis_amount = 0;
    let mut aki_count = 0;
    let mut aki_non_default = false;
    let mut amount_aia = 0;
    let mut amount_policies = 0;
    let mut non_default_policy = false;
    let mut has_address_blocks = false;
    let mut has_as_resources = false;

    for ex in exts {
        let id = ex.identifier.to_string();

        // AKI
        if id == "2.5.29.35" {
            let bw = asn1::write_single(&ex.value).unwrap();
            let aki = asn1::parse_single::<asn1::OctetStringEncoded<asn1p::AKIContent>>(&bw).unwrap();
            let aki = aki.get();
            aki_count = 1;
            if aki.keyIdentifier.is_none() {
                aki_non_default = true;
            }
        }
        // CRL Distribution Points
        else if id == "2.5.29.31" {
            let bw = asn1::write_single(&ex.value).unwrap();
            let crl = asn1::parse_single::<asn1::OctetStringEncoded<asn1::SequenceOf<asn1p::DistributionPoint>>>(&bw).unwrap();
            let crl = crl.get();
            for p in crl.clone().into_iter() {
                let po = p.distributionPoint.unwrap();
                crl_dis_amount += 1;
            }
        }
        // Authority Info Access
        else if id == "1.3.6.1.5.5.7.1.1" {
            let bw = asn1::write_single(&ex.value).unwrap();
            let aia = asn1::parse_single::<asn1::OctetStringEncoded<asn1::SequenceOf<asn1p::InfoAccessField>>>(&bw).unwrap();
            let aia = aia.get();
            amount_aia = aia.clone().into_iter().count();
        }
        // Certificate Policies
        else if id == "1.3.6.1.5.5.7.14.2" {
            let bw = asn1::write_single(&ex.value).unwrap();
            let cp = asn1::parse_single::<asn1::OctetStringEncoded<asn1p::certificatePolicies>>(&bw).unwrap();
            let cp = cp.get();
            amount_policies = cp.policies.clone().into_iter().count();
            for c in cp.policies.clone().into_iter() {
                let id = c.policyIdentifier.to_string();
                if id != "1.3.6.1.5.5.7.14.2" {
                    non_default_policy = true;
                }
            }
        }
        // IP Resources
        else if id == "1.3.6.1.5.5.7.1.7" {
            let bw = asn1::write_single(&ex.value).unwrap();

            let mut bs = asn1::parse_single::<asn1::OctetStringEncoded<asn1::SequenceOf<asn1p::ipAddrBlocks>>>(&bw);
            if bs.is_err() {
                let bs = asn1::parse_single::<asn1::OctetStringEncoded<asn1::SequenceOf<asn1p::ipAddrBlocksNone>>>(&bw).unwrap();
                has_address_blocks = false;
            } else {
                has_address_blocks = true;
            }
            // let bs = bs.get();
            // for b in bs.clone().into_iter(){
            //     if b.addresses.{
            //         has_address_blocks = true;
            //     }
            // }
        }
        // AS Resourcen
        else if id == "1.3.6.1.5.5.7.1.8" {
            let bw = asn1::write_single(&ex.value).unwrap();

            let bs = asn1::parse_single::<asn1::OctetStringEncoded<asn1p::ASIdentifierChoice>>(&bw).unwrap();
            let bs = bs.get();
            if bs.asIdsOrRanges.is_some() {
                let bs = bs.asIdsOrRanges.clone().unwrap();
                for b in bs.clone().into_iter() {
                    if b.AsRange.is_some() {
                        has_as_resources = true;
                    }
                }
            }
        }
    }

    ExtCharacteristics {
        extCount: count.try_into().unwrap(),
        crl_dis_amount: crl_dis_amount.try_into().unwrap(),
        aki_count: aki_count.try_into().unwrap(),
        aki_non_default: aki_non_default,
        aia_count: amount_aia.try_into().unwrap(),
        policy_count: amount_policies.try_into().unwrap(),
        policy_non_default: non_default_policy,
        has_address_blocks: has_address_blocks,
        has_as_resources: has_as_resources,
    }
}

pub fn analyse_cert(cert: asn1p::CertificateFull) -> CertCharacteristics {
    let ext = cert.tbsCert.crlExtensions.unwrap();
    let ext_arr = ext.clone().into_iter().collect::<Vec<asn1p::ExtensionValue>>();
    let ex_char = analyse_extensions(ext_arr);

    let issuer = cert.tbsCert.issuer.unwrap();
    let iv = issuer.clone().into_iter().filter(|x| x.clone().count() > 1).count() > 0;
    let issuer_amount = issuer.count();
    let multi_issuer = iv;

    let subject = cert.tbsCert.subject.unwrap();
    let iv = subject.clone().into_iter().filter(|x| x.clone().count() > 1).count() > 0;

    let iv = subject
        .clone()
        .into_iter()
        .filter(|x| {
            (x.clone()
                .into_iter()
                .filter(|y| y.attrType.to_string() == "2.5.4.11" || y.attrType.to_string() == "2.5.4.10"))
            .count()
                > 0
        })
        .count()
        > 0;
    let multi_subject = iv;

    let subject_amount = subject.count();

    CertCharacteristics {
        extChars: ex_char,
        multiIssuer: issuer_amount > 1,
        multiIssuerField: multi_issuer,
        multiSubject: subject_amount > 1,
        multiSubjectField: multi_subject,
    }
}

pub fn analyse_mft(signedData: asn1p::SignedDataMftFull) -> SOCharacteristics {
    let certs = signedData.certificates.unwrap();
    let cert_count = certs.clone().count();
    let cert_chars = analyse_cert(certs.last().unwrap());
    SOCharacteristics {
        certCount: cert_count.try_into().unwrap(),
        certChars: Some(cert_chars),
        is_ber: false,
    }
}

pub fn analyse_roa(signedData: asn1p::SignedDataRoaFull) -> (SOCharacteristics, Vec<String>) {
    let certs = signedData.certificates.unwrap();
    let cert_count = certs.clone().count();
    let cert_chars = analyse_cert(certs.last().unwrap());
    let char = SOCharacteristics {
        certCount: cert_count.try_into().unwrap(),
        certChars: Some(cert_chars),
        is_ber: false,
    };

    let mut ret = vec![];
    let tmp = signedData.encapContentInfo.eContent.unwrap();
    let sc = tmp.get();
    let asid = sc.asID;

    for b in sc.ipAddrBlocks.clone().into_iter() {
        let fam = b.addressFamily[1];

        for a in b.addresses {
            let r = asn1::write_single(&a).unwrap();

            // Since this is a choice, it can either be a bit string or a range
            let c = asn1::parse_single::<asn1::BitString>(&r);
            let c = a.address;
            let addr_raw = c;
            let bs = bitstring_to_ip(addr_raw, fam);
            let pre = resources::Prefix::new(bs.0, bs.1);
            let bl = IpBlock::from(pre);

            // let bl;
            // if c.is_ok(){
            //     let addr_raw = c.unwrap();
            //     let a = bitstring_to_ip(addr_raw, fam);
            //     let pre = resources::Prefix::new(a.0, a.1);
            //     bl = IpBlock::from(pre);

            // }
            // else{
            //     println!("r {:?}", base64::encode(&r));

            //     let r = asn1::parse_single::<asn1p::IpAddrRange>(&r).unwrap();
            //     let a1 = bitstring_to_ip(r.min.clone(), fam);
            //     let a2 = bitstring_to_ip(r.max.clone(), fam);

            //     let pre1 = Addr::from(a1.0);

            //     let pre2 = Addr::from(a2.0);

            //     bl = IpBlock::from((pre1, pre2, a1.1, a2.1));
            // }

            let s;
            if fam == 1 {
                s = bl.display_v4().to_string();
            } else {
                s = bl.display_v6().to_string();
            }

            let ml = match a.maxLength {
                Some(x) => x.to_string(),
                None => s.split("/").last().unwrap().to_string(),
            };
            let fs = format!("AS{},{},{}", asid, s, ml);
            ret.push(fs);
        }
    }
    return (char, ret);
}

pub fn find_object_differences_roa() {
    let bases = vec![];
    let roa_uris = find_roas(bases.clone());

    // println!("Total amount of ROAs {}", mft_uris[0].len());
}

pub fn find_object_differences(typ: &str) {
    let vrps = load_vrps(false);

    let bases = vec![];
    let uris;
    if typ == "mft" {
        uris = find_mfts(bases.clone());
    } else if typ == "roa" {
        uris = find_roas(bases.clone());
    } else {
        panic!("Unknown type");
    }
    println!("Total amount of Files {}", uris[0].len());

    let mut parse_errors = 0;
    let mut ber_encoded = 0;

    let mut map = HashMap::new();
    let mut seen = HashSet::new();

    for ur in 0..uris.len() {
        let d = uris[ur].clone();
        for i in 0..d.len() {
            let u = &d[i];
            let b = fs::read(&u).unwrap();
            // println!("Roa content {}", base64::encode(&b));

            if seen.contains(&b) {
                continue;
            }

            if is_ber((b.clone()).into()) {
                ber_encoded += 1;
                let ob = SOCharacteristics {
                    certCount: 0,
                    certChars: None,
                    is_ber: true,
                };
                map.insert(u.clone(), (ob, vec![]));
                continue;
            }

            seen.insert(b.clone());
            if typ == "mft" {
                let mft = asn1::parse_single::<asn1p::ContentInfoMftFull>(&b);

                if mft.is_err() {
                    parse_errors += 1;
                    continue;
                }

                let mft = mft.unwrap();
                let mft = mft.content.unwrap();
                let cs = analyse_mft(mft);
                map.insert(u.clone(), (cs, vec![]));
            } else if typ == "roa" {
                let roa = asn1::parse_single::<asn1p::ContentInfoRoaFull>(&b);

                if roa.is_err() {
                    parse_errors += 1;
                    continue;
                }

                let roa = roa.unwrap();

                let roa = roa.content.unwrap();

                let (cs, vrp) = analyse_roa(roa);

                if vrp.contains(&"AS6393".to_string()) {
                    println!("Found Hurricane ROA {} ", &u);
                }

                map.insert(u.clone(), (cs, vrp));
            }
        }
    }

    println!("Parse Errors: {}", parse_errors);

    let (not_in, vrps) = analyse_vrps(false);
    let mut total_not_in = HashSet::new();
    for n in not_in {
        for e in n {
            total_not_in.insert(e);
        }
    }

    let mut counters: HashMap<SOCharacteristics, Vec<i32>> = HashMap::new();
    let mut add_count = 0;

    let mut map_to_file: HashMap<SOCharacteristics, String> = HashMap::new();

    for k in map.keys() {
        add_count += 1;
        if add_count % 10000 == 0 {
            println!("Finsihed {} of {}", add_count, map.len());
        }
        let v = map.get(k).unwrap();
        let a = &v.0;
        let mut c: Vec<i32>;
        if counters.contains_key(&a.clone()) {
            c = counters.get(&a).unwrap().clone().to_vec();
            c[0] += 1;
        } else {
            c = vec![1, 0, 0, 0, 0];
        }

        for x in v.1.clone().into_iter() {
            if total_not_in.contains(&x) {
                for r in 0..vrps.len() {
                    let va = &vrps[r];

                    let mut contained_all = true;
                    for inn in v.1.clone().into_iter() {
                        if !va.contains(&inn) {
                            contained_all = false;
                            break;
                        }
                    }
                    if contained_all {
                        c[r + 1] += 1;
                    } else {
                        if r == 0 {
                            map_to_file.insert(a.clone(), k.clone());
                        }
                    }
                }
            } else {
                for r in 0..vrps.len() {
                    c[r + 1] += 1;
                }
            }

            break;
        }

        // Check which RP contains this

        // for r in 0..vrps.len(){
        //     let va = &vrps[r];

        //     let mut contained_all = true;
        //     for x in v.1.clone().into_iter(){
        //         if !va.contains(&x){
        //             contained_all = false;
        //             break;
        //         }
        //     }
        //     if contained_all{
        //         c[r+1] += 1;
        //     }
        // }
        counters.insert(a.clone(), c);
    }
    println!("Map to File {:?}", map_to_file);
    println!("{:?}", counters);
    println!("Diverse MFTs: {}", counters.keys().len());
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtCharacteristics {
    pub extCount: i32,
    pub crl_dis_amount: i32,
    pub aki_count: i32,
    pub aki_non_default: bool,
    pub aia_count: i32,
    pub policy_non_default: bool,
    pub policy_count: i32,
    pub has_address_blocks: bool,
    pub has_as_resources: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertCharacteristics {
    pub extChars: ExtCharacteristics,
    // Multiple Issuers
    pub multiIssuer: bool,
    // Multiple Fields inside Issuer
    pub multiIssuerField: bool,

    pub multiSubject: bool,
    pub multiSubjectField: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SOCharacteristics {
    pub certCount: i32,
    pub certChars: Option<CertCharacteristics>,
    pub is_ber: bool,
}
