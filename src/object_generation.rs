use std::{
    collections::{HashMap, VecDeque},
    fs,
    thread::{self, current},
    time::Duration,
};

use rand::{seq::SliceRandom, Rng};
use rpki::rrdp::Hash;

use crate::{
    fuzzing::processing,
    process_util::{self, CoverageFactory, GenerationBatch, GenerationFactory, ObjectInfo},
    publication_point::repository,
};

fn mutate(data: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    for _ in 0..rng.gen_range(0..10) {
        let mut rng = rand::thread_rng();

        // Chose a random mutation
        match rng.gen_range(0..4) {
            0 => {
                // Bit flipping
                let byte = rng.gen_range(0..data.len());
                let bit = rng.gen_range(0..8);
                data[byte] ^= 1 << bit;
            }
            1 => {
                // Byte flipping
                let byte = rng.gen_range(0..data.len());
                data[byte] = !data[byte];
            }
            2 => {
                // Arithmetic operations
                let byte = rng.gen_range(0..data.len());
                let change = rng.gen_range(1..128);
                if rng.gen_bool(0.5) {
                    data[byte] = data[byte].wrapping_add(change as u8);
                } else {
                    data[byte] = data[byte].wrapping_sub(change as u8);
                }
            }
            3 => {
                // Insertion of known interesting integers
                if data.len() >= 4 {
                    let byte = rng.gen_range(0..(data.len() - 3));
                    let interesting_ints: [u8; 4] = [0, 255, 127, 128];
                    let interesting_int = *interesting_ints.choose(&mut rng).unwrap();
                    for i in 0..4 {
                        data[byte + i] = interesting_int;
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

fn mutate_batch(inputs: &Vec<(Vec<u8>, ObjectInfo)>) -> Vec<Vec<u8>> {
    let mut outputs = Vec::new();
    let num_inputs = inputs.len();
    let num_mutations_per_input = 1000 / num_inputs;

    for input_i in inputs {
        let input = &input_i.0;
        for _ in 0..num_mutations_per_input {
            let mut data = input.clone();
            if data.is_empty() {
                outputs.push(data);
                continue;
            }

            mutate(&mut data);

            outputs.push(data);
        }
    }

    outputs
}

pub fn random_mutation(corpus: Vec<u8>) -> Vec<u8> {
    corpus
}

pub fn generate_objects(typ: &str, amount: u32) -> Vec<Vec<u8>> {
    let mut objects = vec![];

    let data: Vec<u8> = vec![1, 2, 3, 4, 5];

    for i in 0..amount {
        objects.push(data.clone());
    }

    objects
}

pub fn random_id() -> u16 {
    let mut rng = rand::thread_rng();
    let id = rng.gen_range(0..u16::MAX);
    id
}

pub struct SucessTracker {
    pub parent_id: u16,
    pub children_ids: Vec<u16>,
    pub child_coverage: HashMap<u16, f64>,
}

impl SucessTracker {
    pub fn new(parent_id: u16, children_ids: Vec<u16>) -> SucessTracker {
        SucessTracker {
            parent_id,
            children_ids,
            child_coverage: HashMap::new(),
        }
    }

    pub fn best_coverage(&mut self) -> u16 {
        let mut best_coverage = -1.0;
        let mut best_id = 0;
        for (id, coverage) in self.child_coverage.iter() {
            if coverage > &best_coverage {
                best_coverage = *coverage;
                best_id = *id;
            }
        }
        return best_id;
    }

    pub fn add_coverage(&mut self, child_id: u16, coverage: f64) -> bool {
        self.child_coverage.insert(child_id, coverage);
        return self.child_coverage.len() == self.children_ids.len();
    }
}

pub fn start_generation() {
    let mut factory = GenerationFactory::new(100, 1);
    let mut coverage_factory = CoverageFactory::new();

    let mut queue = VecDeque::new();
    let mut map = HashMap::new();
    let mut parent_map = HashMap::new();

    let mut success = HashMap::new();

    let conf = repository::create_default_config("my.server.com".to_string());

    // How many objects per batch min
    let deflation_limit = 10;

    // How many times to divide a batch
    let deflation_rate = 10;

    let mut best_coverage: f64 = 0.0;
    let mut current_best = None;

    loop {
        // thread::sleep(Duration::from_millis(1000));
        let batch;
        if queue.is_empty() {
            let mut objects = vec![];
            let info = ObjectInfo {
                manipulated_fields: vec![],
                filename: "tmp.txt".to_string(),
            };
            let v;
            if current_best.is_none() {
                // println!("Generating new batch");

                let base_roa = repository::create_random_roa(&conf).0.to_vec();
                v = vec![(base_roa.clone(), info)];
            } else {
                println!("Using cached best");

                v = current_best.clone().unwrap();
            }
            let v = mutate_batch(&v);

            for o in v {
                let info = ObjectInfo {
                    manipulated_fields: vec![],
                    filename: "tmp.txt".to_string(),
                };
                objects.push((o, info));
            }

            batch = GenerationBatch {
                typ: "roa".to_string(),
                contents: objects,
                id: random_id(),
            };
        } else {
            batch = queue.pop_front().unwrap();
        }

        map.insert(batch.id, batch.clone());

        let serialized = serde_json::to_string(&batch).unwrap();

        let mut responses = factory.send_batch(serialized.clone());

        while responses.is_none() {
            thread::sleep(Duration::from_millis(1000));
            responses = factory.send_batch(serialized.clone());
            println!("Sleeping for a little");
        }

        let cloned_map = map.clone();

        let responses = coverage_factory.get_coverages();

        for re in responses {
            println!("Coverage {}", re.line_coverage);

            let index = re.batch_id;

            if !parent_map.contains_key(&index) {
                // If new batch is better than what we had -> use it
                // TODO This needs more sophisticated logic, we cant discard batches completly if they are not better

                if re.line_coverage > best_coverage || re.line_coverage == 0.0 {
                    best_coverage = re.line_coverage;

                    // Code duplication to below, fix this
                    let b = map.get(&re.batch_id).unwrap();
                    current_best = Some(b.contents.clone());

                    let mut new_ids = vec![];
                    for i in 0..deflation_rate {
                        let new_batch =
                            b.contents[b.contents.len() / deflation_rate * i..b.contents.len() / deflation_rate * (i + 1)].to_vec();
                        let new_id = random_id();

                        let new_batch = GenerationBatch {
                            typ: "roa".to_string(),
                            contents: new_batch,
                            id: new_id,
                        };

                        new_ids.push(new_id);

                        parent_map.insert(new_id, re.batch_id);

                        queue.push_back(new_batch);
                    }
                    success.insert(re.batch_id, SucessTracker::new(re.batch_id, new_ids));
                }
            } else {
                let parent_index = parent_map.get(&index).unwrap();
                let success_object: &mut SucessTracker = success.get_mut(parent_index).unwrap();
                let finished = success_object.add_coverage(index, re.line_coverage);

                if finished {
                    let best_id = success_object.best_coverage();
                    let best_batch = cloned_map.get(&best_id).unwrap();

                    if best_batch.contents.len() > deflation_limit {
                        // Deflate by half

                        let mut new_ids = vec![];
                        for i in 0..deflation_rate {
                            let new_batch = best_batch.contents
                                [best_batch.contents.len() / deflation_rate * i..best_batch.contents.len() / deflation_rate * (i + 1)]
                                .to_vec();
                            let new_id = random_id();

                            let new_batch = GenerationBatch {
                                typ: "roa".to_string(),
                                contents: new_batch,
                                id: new_id,
                            };

                            new_ids.push(new_id);

                            parent_map.insert(new_id, best_id);
                            map.insert(new_id, new_batch.clone());

                            queue.push_back(new_batch);
                        }
                        success.insert(best_id, SucessTracker::new(best_id, new_ids));
                    } else {
                        // Inflate back to original size by generating mutations of object
                        let mut objects = vec![];
                        println!("inflating");
                        let mutated = mutate_batch(&best_batch.contents);
                        println!("Mutation finished");
                        for o in mutated {
                            let info = ObjectInfo {
                                manipulated_fields: vec![],
                                filename: "tmp.txt".to_string(),
                            };
                            objects.push((o, info));
                        }

                        let batch = GenerationBatch {
                            typ: "roa".to_string(),
                            contents: objects,
                            id: random_id(),
                        };

                        map.insert(batch.id, batch.clone());

                        queue.push_back(batch);
                    }
                }
            }
        }
    }
}

pub fn send_single_object(uri: &str) {
    thread::sleep(Duration::from_millis(1000));
    let content = fs::read_to_string(uri).unwrap();

    let info = ObjectInfo {
        manipulated_fields: vec![],
        filename: "tmp.txt".to_string(),
    };

    let b64 = base64::decode(&content.trim());
    let c;
    if b64.is_err() {
        c = fs::read(uri).unwrap();
    } else {
        c = b64.unwrap();
    }

    let contents = vec![(c, info)];

    let batch = GenerationBatch {
        typ: "typ".to_string(),
        contents,
        id: 0,
    };

    let serialized = serde_json::to_string(&batch).unwrap();

    process_util::send_new_data_s(serialized, "/tmp/gensock0");
}
