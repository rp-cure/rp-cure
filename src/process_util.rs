use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
};

use reqwest::Response;

use crate::coverage_interface;

fn accept_new_client(stream: &UnixListener) -> String {
    let op = stream.accept();
    if op.is_err() {
        return "".to_string();
    }
    let (mut s, _) = op.unwrap();

    let mut b = String::new();
    s.read_to_string(&mut b).unwrap();
    return b;
}

fn read_all_clients(stream: &UnixListener) -> Vec<String> {
    let mut ret = vec![];

    loop {
        let re = accept_new_client(stream);
        if re.is_empty() {
            break;
        }
        ret.push(re);
    }
    ret
}

pub fn send_new_data(data: String) {
    send_new_data_s(data, "/tmp/sock");
}

pub fn send_new_data_s(data: String, socket: &str) {
    let mut stream = match UnixStream::connect(socket) {
        Err(er) => {
            println!("An Error occured {:?}", er);
            return;
        }
        Ok(stream) => stream,
    };

    match stream.write_all(&data.as_bytes()) {
        Err(_) => return,
        Ok(_) => {}
    }

    drop(stream);
}

pub fn acknowledge(worker_id: u8, batch_id: u16) {
    // let coverage_info = coverage_interface::get_coverage("routinator");
    let response = ReponseObject {
        worker_id: worker_id,
        batch_id: batch_id,
        coverage: 0.0,
    };

    let serialized = serde_json::to_string(&response).unwrap();

    send_new_data_s(serialized, "/tmp/ack");
}

pub fn count_acks(stream: &UnixListener) -> HashMap<u8, u16> {
    let ret = read_all_clients(stream);
    let mut map = HashMap::new();

    for v in ret {
        let val = v.parse::<u8>().unwrap();
        if map.contains_key(&val) {
            let tmp = map.get_mut(&val).unwrap();
            *tmp += 1;
            continue;
        } else {
            map.insert(val, 1);
        }
    }

    map
}

pub fn get_responses(stream: &UnixListener) -> Vec<ReponseObject> {
    let arr = read_all_clients(stream);
    let mut ret = vec![];

    for v in arr {
        let val = serde_json::from_str::<ReponseObject>(&v).unwrap();
        ret.push(val);
    }

    ret
}

fn stop_generation() {
    fs::write("/tmp/.stop_generation", "stop").unwrap();
}

// Send start signal
fn start_generation() {
    fs::remove_file("/tmp/.stop_generation");
}

pub fn is_stopped() -> bool {
    std::path::Path::new("/tmp/.stop_generation").exists()
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct SerializableObject {
    pub filenames: Vec<String>,
    pub contents: Vec<Vec<u8>>,
    pub mfts: Option<Vec<Vec<u8>>>,
    pub crls: Option<Vec<Vec<u8>>>,
    pub roas: Option<Vec<Vec<u8>>>,
    pub roa_names: Option<Vec<String>>,
    pub id: u16,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ObjectInfo {
    pub manipulated_fields: Vec<String>,
    pub filename: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct GenerationBatch {
    pub contents: Vec<(Vec<u8>, ObjectInfo)>,
    pub typ: String,
    pub id: u16,
}

pub struct ObjectFactory {
    pub objects: Vec<String>,
    pub stream: UnixListener,
    pub ackstream: UnixListener,
    // Max amount of objects in pipeline
    pub limit: u16,
}

impl ObjectFactory {
    pub fn new(limit: u16, socket: &str) -> ObjectFactory {
        fs::remove_file(&socket).unwrap_or_default();

        let s = UnixListener::bind(&socket).unwrap();
        s.set_nonblocking(true).unwrap();

        let ack = "/tmp/ack".to_string();
        fs::remove_file(&ack).unwrap_or_default();

        let s2 = UnixListener::bind(&ack).unwrap();
        s2.set_nonblocking(true).unwrap();

        start_generation();
        ObjectFactory {
            objects: vec![],
            stream: s,
            ackstream: s2,
            limit,
        }
    }

    pub fn get_object(&mut self) -> Option<SerializableObject> {
        let new_objs = read_all_clients(&self.stream);
        self.objects.extend(new_objs);

        if self.objects.len() >= self.limit.into() {
            stop_generation();
        } else {
            start_generation();
        }

        if self.objects.len() > 0 {
            let o = self.objects.pop().unwrap();
            let ret = serde_json::from_str::<SerializableObject>(&o).unwrap();
            return Some(ret);
        } else {
            return None;
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ReponseObject {
    pub worker_id: u8,
    pub batch_id: u16,
    pub coverage: f64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct CoverageObject {
    pub function_coverage: f64,
    pub line_coverage: f64,
    pub batch_id: u16,
}

pub struct CoverageFactory {
    pub stream: UnixListener,
}

impl CoverageFactory {
    pub fn new() -> CoverageFactory {
        let socket = "/tmp/coverage".to_string();
        fs::remove_file(&socket).unwrap_or_default();

        let s = UnixListener::bind(&socket).unwrap();
        s.set_nonblocking(true).unwrap();

        CoverageFactory { stream: s }
    }

    pub fn get_coverages(&mut self) -> Vec<CoverageObject> {
        let new_objs = read_all_clients(&self.stream);
        let mut ret = vec![];
        for obj in new_objs {
            let res = serde_json::from_str::<CoverageObject>(&obj).unwrap();
            ret.push(res);
        }
        ret
    }
}

pub struct GenerationFactory {
    pub objects: Vec<String>,
    pub stream: UnixListener,
    // Max amount of objects in pipeline
    pub limit: u16,
    pub cur_socket: u8,
    pub amount_sockets: u8,
    pub sent_objects: HashMap<u8, u16>,
}

impl GenerationFactory {
    pub fn new(limit: u16, amount_sockets: u8) -> GenerationFactory {
        let socket = "/tmp/ack".to_string();
        fs::remove_file(&socket).unwrap_or_default();

        let s = UnixListener::bind(&socket).unwrap();
        s.set_nonblocking(true).unwrap();

        let sent_objects = HashMap::new();

        GenerationFactory {
            objects: vec![],
            stream: s,
            limit,
            cur_socket: 0,
            amount_sockets,
            sent_objects,
        }
    }

    pub fn send_batch(&mut self, data: String) -> Vec<ReponseObject> {
        // Check which socket needs more objects
        let initial_socket = self.cur_socket;
        loop {
            if !self.sent_objects.contains_key(&self.cur_socket) {
                break;
            }

            if self.sent_objects.get(&self.cur_socket).unwrap() >= &self.limit {
                let next_socket = (self.cur_socket + 1) % self.amount_sockets;
                if next_socket == initial_socket {
                    return vec![];
                }
                self.cur_socket = next_socket;
            } else {
                break;
            }
        }

        send_new_data_s(data, &("/tmp/gensock".to_string() + &self.cur_socket.to_string()));
        self.cur_socket = (self.cur_socket + 1) % self.amount_sockets;

        // Store that we sent this object
        if self.sent_objects.contains_key(&self.cur_socket) {
            let tmp = self.sent_objects.get_mut(&self.cur_socket).unwrap();
            *tmp += 1;
        } else {
            self.sent_objects.insert(self.cur_socket, 1);
        }

        // Count how many objects were acknowledged
        let res = get_responses(&self.stream);
        for val in &res {
            if self.sent_objects.contains_key(&val.worker_id) {
                let tmp = self.sent_objects.get_mut(&val.worker_id).unwrap();
                *tmp -= 1;
            }
        }

        return res;

        // let acks = count_acks(&self.stream);
        // for val in acks {
        //     if self.sent_objects.contains_key(&val.0) {
        //         let tmp = self.sent_objects.get_mut(&val.0).unwrap();
        //         *tmp -= val.1;
        //     }
        // }

        // return true;
    }
}

pub fn get_batch(stream: &UnixListener) -> Option<GenerationBatch> {
    let re = accept_new_client(stream);
    if re.is_empty() {
        return None;
    }

    let ret = serde_json::from_str::<GenerationBatch>(&re).unwrap();
    return Some(ret);
}

pub fn send_ack(id: &str) {
    send_new_data_s(id.to_string(), "/tmp/ack");
}
