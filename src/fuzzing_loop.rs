use std::{
    cmp::max,
    collections::{HashMap, HashSet, VecDeque},
    fs,
    thread::{self, current},
    time::Duration,
};

use bytes::Bytes;
use rand::{prelude::Distribution, seq::SliceRandom, Rng};

use crate::{
    asn1p,
    fuzzing::processing,
    fuzzing_repo::FuzzingPP,
    process_util::{self, CoverageFactory, GenerationBatch, GenerationFactory, ObjectInfo},
    publication_point::repository,
    util::create_example_roas,
};
use crate::{fuzzing_repo, mutator};
use rand::distributions::WeightedIndex;

fn generate_number() -> u8 {
    let mut rng = rand::thread_rng();
    let weights = [25, 50, 17, 8, 4, 2, 1]; // 0 appears with a weight of 50, 1 with a weight of 25, etc.
    let dist = WeightedIndex::new(&weights).unwrap();

    dist.sample(&mut rng) as u8
}

fn mutate(data: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    let num_mutations = generate_number();
    // let num_mutations = 0;
    for _ in 0..num_mutations {
        // Mutation types with their probabilities
        let mutation_types = [(0, 20), (1, 15), (2, 20), (3, 15), (4, 10), (5, 10), (6, 10)];
        let chosen_type = mutation_types.choose_weighted(&mut rng, |&(_, weight)| weight).unwrap().0;

        match chosen_type {
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
            4 => {
                // Chunk swapping
                if data.len() > 2 {
                    let size = rng.gen_range(1..(data.len() / 2));
                    let first_start = rng.gen_range(0..(data.len() - 2 * size));
                    let second_start = rng.gen_range((first_start + size)..(data.len() - size));
                    let mut cloned = data.clone();
                    data[first_start..(first_start + size)].swap_with_slice(&mut cloned[second_start..(second_start + size)]);
                }
            }
            5 => {
                // Data duplication
                if data.len() > 1 {
                    let size = rng.gen_range(1..(data.len() / 2));
                    let source = rng.gen_range(0..(data.len() - 2 * size));
                    let target = rng.gen_range((source + size)..(data.len() - size));
                    let cloned = data.clone();

                    data[target..(target + size)].clone_from_slice(&cloned[source..(source + size)]);
                }
            }
            6 => {
                // Data insertion
                let byte = rng.gen_range(0..data.len());
                let new_data: Vec<u8> = (0..rng.gen_range(1..10)).map(|_| rng.gen()).collect();
                data.splice(byte..byte, new_data);
            }
            _ => unreachable!(),
        }
    }
}

fn mutate_batch(inputs: &Vec<(Vec<u8>, ObjectInfo)>, size: u32) -> Vec<Vec<u8>> {
    let mut outputs = Vec::new();
    let num_inputs = inputs.len();
    let num_mutations_per_input = size / num_inputs as u32;

    // Keep parent generation
    // for obj in inputs {
    //     outputs.push(obj.0.clone());
    // }

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

pub fn random_id() -> u16 {
    let mut rng = rand::thread_rng();
    let id = rng.gen_range(0..u16::MAX);
    id
}

pub struct SucessTracker {
    pub parent_id: u16,
    pub children_ids: Vec<u16>,
    pub child_coverage: HashMap<u16, HashSet<u64>>,
}

impl SucessTracker {
    pub fn new(parent_id: u16, children_ids: Vec<u16>) -> SucessTracker {
        SucessTracker {
            parent_id,
            children_ids,
            child_coverage: HashMap::new(),
        }
    }

    pub fn best_coverage(&mut self) -> (u16, HashSet<u64>) {
        let mut best_coverage = -1.0;
        let mut best_id = 0;
        let mut new_functions = HashSet::new();
        for (id, coverage) in self.child_coverage.iter() {
            if coverage.len() as f64 > best_coverage {
                best_coverage = coverage.len() as f64;
                new_functions = coverage.clone();
                best_id = *id;
            }
        }
        return (best_id, new_functions);
    }

    pub fn add_coverage(&mut self, child_id: u16, coverage: HashSet<u64>) -> bool {
        self.child_coverage.insert(child_id, coverage);
        return self.child_coverage.len() == self.children_ids.len();
    }
}

fn split_batch(contents: &Vec<(Vec<u8>, ObjectInfo)>, deflation_rate: usize) -> Vec<GenerationBatch> {
    let mut new_batches = vec![];

    let mut rng = rand::thread_rng();
    for i in 0..deflation_rate {
        let v = rng.gen_range(0..10);

        let new_batch = contents[contents.len() / deflation_rate * i..contents.len() / deflation_rate * (i + 1)].to_vec();

        // Either decrease size or inflate to max
        let length;
        if v > 5 {
            length = new_batch.len();
        } else {
            length = 1000;
        }
        let new_batch = mutation(&new_batch, length.try_into().unwrap());

        new_batches.push(new_batch);
    }

    new_batches
}

pub fn get_key_id(data: Bytes) {
    let inf = asn1::parse_single::<asn1p::ContentInfoRoaFull>(&data).unwrap();
    let h = inf
        .content
        .unwrap()
        .certificates
        .unwrap()
        .next()
        .unwrap()
        .tbsCert
        .subject
        .unwrap()
        .next()
        .unwrap()
        .next()
        .unwrap()
        .attrValue;
    let b = asn1::write_single(&h).unwrap();

    let res = asn1::parse_single::<asn1::PrintableString>(&b).unwrap();
    let re = res.as_str().to_string();
    println!("{:?}", res);
}

// pub fn start_generation() {
//     let mut factory = GenerationFactory::new(100, 3);
//     let mut coverage_factory = CoverageFactory::new();

//     let mut queue = VecDeque::new();
//     let mut map = HashMap::new();

//     let am: u16 = 4;

//     let roas = create_example_roas(am.into());

//     for i in 0..am {
//         let mut objects = vec![];
//         let info = ObjectInfo {
//             manipulated_fields: vec![],
//             filename: "tmp.txt".to_string(),
//             ca_index: i,
//         };
//         let v = roas[i as usize].0.to_vec();
//         let batch = vec![(v.clone(), info)];

//         let v = mutate_batch(&batch);

//         for o in v {
//             let info = ObjectInfo {
//                 manipulated_fields: vec![],
//                 filename: "tmp.txt".to_string(),
//                 ca_index: i,
//             };
//             objects.push((o, info));
//         }

//         let genbatch = GenerationBatch {
//             typ: "roa".to_string(),
//             contents: objects,
//             id: random_id(),
//         };

//         queue.push_back(genbatch);
//     }
// }

struct SortedList {
    elements: Vec<FuzzingBatch>,
}

impl SortedList {
    pub fn new() -> SortedList {
        SortedList { elements: vec![] }
    }

    pub fn insert(&mut self, element: FuzzingBatch) {
        let mut index = 0;
        for e in self.elements.iter() {
            if e.batch_score <= element.batch_score {
                break;
            }
            index += 1;
        }

        self.elements.insert(index, element);

        // println!("Start QUEUE");
        // for e in self.elements.iter() {
        //     println!("{}", e.0);
        // }
        // println!("\n END QUEUE \n\n");

        // TODO check what length makes sense here
        if self.elements.len() > 1000 {
            self.elements.remove(self.elements.len() - 1);
        }
    }

    pub fn age(&mut self) {
        for e in self.elements.iter_mut() {
            let mut tmp = e.batch_score;
            tmp -= 1.0;
            if tmp < 1.0 {
                tmp = 1.0;
            }
            e.batch_score = tmp;
        }
    }

    // Select an element with its probability
    pub fn get_element(&mut self) -> FuzzingBatch {
        let mut rng = rand::thread_rng();

        let total_sum: f32 = self.elements.iter().map(|el| el.batch_score).sum();

        let mut random_value = rng.gen_range(0.0..total_sum);

        for el in self.elements.iter() {
            if random_value < el.batch_score {
                return el.clone();
            }
            random_value -= el.batch_score;
        }
        return self.elements.last().unwrap().clone();
    }
}

struct FuzzingQueue {
    elements: SortedList,
}

impl FuzzingQueue {
    pub fn new() -> FuzzingQueue {
        FuzzingQueue {
            elements: SortedList::new(),
        }
    }

    pub fn insert(&mut self, element: FuzzingBatch) {
        self.elements.insert(element);
    }

    pub fn pop(&mut self) -> Option<FuzzingBatch> {
        self.elements.elements.pop()
    }

    pub fn age_elements(&mut self) {}
}

pub fn mutation(batch: &Vec<(Vec<u8>, ObjectInfo)>, size: u32) -> GenerationBatch {
    let v = mutate_batch(batch, size);
    let mut objects = vec![];

    for o in v {
        let info = ObjectInfo {
            manipulated_fields: vec![],
            filename: "tmp.txt".to_string(),
            ca_index: batch.first().unwrap().1.ca_index,
        };
        objects.push((o, info));
    }

    let genbatch = GenerationBatch {
        typ: "roa".to_string(),
        contents: objects,
        id: random_id(),
    };

    genbatch
}

#[derive(Clone)]
pub struct FuzzingBatch {
    batch_id: u64,
    batch_pp: FuzzingPP,
    batch_score: f32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableBatch {
    batch_id: u64,
    batch_content: Vec<(String, Vec<u8>)>,
}

impl FuzzingBatch {
    pub fn serialize(&self) -> String {
        let sb = SerializableBatch {
            batch_id: self.batch_id,
            batch_content: self.batch_pp.serialize(),
        };
        serde_json::to_string(&sb).unwrap()
    }
}

pub fn generate_random_u64() -> u64 {
    let mut rng = rand::thread_rng();
    let id = rng.gen_range(0..u64::MAX);
    id
}

pub fn start_generation() {
    let mut factory = GenerationFactory::new(100, 3);
    let mut coverage_factory = CoverageFactory::new();
    let mut map = HashMap::new();

    let mut fuzzing_queue = SortedList::new();

    // Minimum size of a generation
    let min_generation_size = 10;

    // How many times to divide a generation
    let factor = 10;
    // let mut best_coverage: f64 = 0.0;

    // At the beginning, fille the queue with objects

    // Amount of batches
    let am: u16 = 4;
    let objects_in_batch = 20;

    let roas = create_example_roas((am * 20).into());

    let pp = fuzzing_repo::construct_PP();

    // for i in 0..am {
    //     let mut vals = vec![];
    //     for j in 0..objects_in_batch {
    //         let info = ObjectInfo {
    //             manipulated_fields: vec![],
    //             filename: "tmp.txt".to_string(),
    //             ca_index: i,
    //         };
    //         vals.push((roas[(i * objects_in_batch + j) as usize].0.to_vec(), info));
    //     }
    //     let batch = (1.0, vals);

    let batch = FuzzingBatch {
        batch_id: generate_random_u64(),
        batch_pp: pp,
        batch_score: 1.0,
    };

    fuzzing_queue.insert(batch);
    // }

    let mut know_functions: HashSet<u64> = HashSet::new();
    let mut first_run = true;

    loop {
        fuzzing_queue.age();

        // If nothing is in queue -> Target is still processing all requests
        while fuzzing_queue.elements.is_empty() {
            thread::sleep(Duration::from_millis(50))
        }
        let batch = fuzzing_queue.get_element();

        map.insert(batch.batch_id, batch);

        let serialized = batch.serialize();

        let mut responses = factory.send_batch(serialized.clone());

        while responses.is_none() {
            thread::sleep(Duration::from_millis(1000));
            // If responses is none, the data could not been sent, so we need to re-try
            responses = factory.send_batch(serialized.clone());
            println!("Sleeping while queue is full");
        }

        let responses = coverage_factory.get_coverages();

        for re in responses {
            println!("Coverage {}", re.line_coverage);
            if first_run {
                first_run = false;
                know_functions.extend(re.function_hashes.clone());
            }

            let mut set = HashSet::new();
            // Check how many new functions were found
            for v in re.function_hashes.difference(&know_functions) {
                set.insert(*v);
            }

            // if set.len() > 0 {
            //     println!("Found {} new Functions", set.len());
            // }

            let batch = map.get(&re.batch_id).unwrap();

            // Score Calculation is still up for debate
            let score = set.len() as f32 + 1.0;

            know_functions.extend(set);

            let new_pps = batch.batch_pp.split(factor);
            for pp in new_pps {
                let new_batch = FuzzingBatch {
                    batch_id: generate_random_u64(),
                    batch_pp: pp,
                    batch_score: score,
                };
                fuzzing_queue.insert(new_batch);
            }
            println!("Known Functions: {}", know_functions.len());
        }
    }
}

pub fn send_single_object(uri: &str) {
    thread::sleep(Duration::from_millis(1000));
    let content = fs::read_to_string(uri).unwrap();

    let info = ObjectInfo {
        manipulated_fields: vec![],
        filename: "tmp.txt".to_string(),
        ca_index: 0,
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
