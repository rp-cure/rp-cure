use rand::distributions::WeightedIndex;
use rand::prelude::Distribution;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::process_util::ObjectInfo;

fn generate_number() -> u8 {
    let mut rng = rand::thread_rng();
    let weights = [25, 50, 17, 8, 4, 2, 1]; // 0 appears with a weight of 25, 1 with a weight of 50, etc.
    let dist = WeightedIndex::new(&weights).unwrap();

    // Draws a value from the distribution according to weights. 1 is the most likely value.
    dist.sample(&mut rng) as u8
}

fn mutate(data: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    let num_mutations = generate_number();
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
