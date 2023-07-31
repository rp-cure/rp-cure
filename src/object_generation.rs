use std::{fs, thread, time::Duration};

use crate::{
    fuzzing::processing,
    process_util::{self, GenerationBatch, GenerationFactory, ObjectInfo},
};

pub fn generate_objects(typ: &str, amount: u32) -> Vec<Vec<u8>> {
    let mut objects = vec![];

    let data: Vec<u8> = vec![1, 2, 3, 4, 5];

    for i in 0..amount {
        objects.push(data.clone());
    }

    objects
}

pub fn start_generation() {
    let mut factory = GenerationFactory::new(10, 1);

    loop {
        thread::sleep(Duration::from_millis(1000));
        let objs = generate_objects("roa", 100);
        let mut arr = vec![];

        for obj in objs {
            let info = ObjectInfo {
                manipulated_fields: vec![],
                filename: "tmp.txt".to_string(),
            };
            arr.push((obj, info));
        }

        let batch = GenerationBatch {
            typ: "typ".to_string(),
            contents: arr,
        };

        let serialized = serde_json::to_string(&batch).unwrap();

        factory.send_batch(serialized);
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
    };

    let serialized = serde_json::to_string(&batch).unwrap();

    process_util::send_new_data_s(serialized, "/tmp/gensock0");
}
