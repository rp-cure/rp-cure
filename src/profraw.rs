use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Error, Read, Seek, SeekFrom};
use std::str;
use std::time::Instant;

/*
Using the existing LLVM Tools is not suitable for extracting coverage information as they take > 1s to extract the info.
This profraw file parser brings down this time to ca. 1ms, allowing coverage info extracting after each iteration.
*/

#[derive(Debug)]
struct ProfrawHeader {
    magic: u64,
    version: u64,
    data_size: u64,
    padding_before_counters: u64,
    counters_size: u64,
    padding_after_counters: u64,
    names_size: u64,
    counters_delta: u64,
    names_begin: u64,
    value_kind_last: u64,
    binary_id_offset: u64,
    mem_prof_offset: u64,
    hash_type: u64,
    hash_offset: u64,
    unused: u64,
}

#[derive(Debug)]
struct FunctionRecord {
    name_ref: u64,
    func_hash: u64,
    counter_ref: u64,
    func_ref: u64,
    value_exp: u64,
    num_counters: u32,
    init_arr: u32,
}

#[derive(Debug)]
struct ProfrawFile {
    header: ProfrawHeader,
    function_records: Vec<FunctionRecord>,
    counters: Vec<u64>,
    function_names: Vec<String>,
}

fn read_profraw_header(file: &mut File) -> Result<ProfrawHeader, Error> {
    let magic = file.read_u64::<LittleEndian>()?;
    let version = file.read_u64::<LittleEndian>()?;

    let mut buffer;

    if version < 5 {
        buffer = vec![0; 48];
    } else if version < 6 {
        buffer = vec![0; 64];
    } else {
        buffer = vec![0; 64 + 5 * 8];
    }
    file.read_exact(&mut buffer)?;
    let mut cursor = std::io::Cursor::new(buffer);

    let unused;
    if version < 6 {
        unused = 0;
    } else {
        unused = cursor.read_u64::<LittleEndian>()?;
    }
    let data_size = cursor.read_u64::<LittleEndian>()?;
    let padding_before_counters;
    if version < 5 {
        padding_before_counters = 0;
    } else {
        padding_before_counters = cursor.read_u64::<LittleEndian>()?;
    }
    let counters_size = cursor.read_u64::<LittleEndian>()?;

    let padding_after_counters;
    if version < 5 {
        padding_after_counters = 0;
    } else {
        padding_after_counters = cursor.read_u64::<LittleEndian>()?;
    }

    let names_size = cursor.read_u64::<LittleEndian>()?;
    let counters_delta = cursor.read_u64::<LittleEndian>()?;
    let names_begin = cursor.read_u64::<LittleEndian>()?;
    let value_kind_last = cursor.read_u64::<LittleEndian>()?;

    let hashtype;
    if version >= 6 {
        hashtype = cursor.read_u64::<LittleEndian>()?;
    } else {
        hashtype = 0;
    }

    let hash_offset;
    if version >= 6 {
        hash_offset = cursor.read_u64::<LittleEndian>()?;
    } else {
        hash_offset = 0;
    }

    let binary_id_offset;
    if version >= 6 {
        binary_id_offset = cursor.read_u64::<LittleEndian>()?;
    } else {
        binary_id_offset = 0;
    }

    let mem_prof_offset;
    if version >= 6 {
        mem_prof_offset = cursor.read_u64::<LittleEndian>()?;
    } else {
        mem_prof_offset = 0;
    }

    Ok(ProfrawHeader {
        magic,
        version,
        unused,
        data_size,
        padding_before_counters,
        counters_size,
        padding_after_counters,
        names_size,
        counters_delta,
        names_begin,
        value_kind_last,
        binary_id_offset,
        mem_prof_offset,
        hash_type: hashtype,
        hash_offset,
    })
}

fn read_counters(file: &mut File, num_counters: u64) -> Result<Vec<u64>, Error> {
    let mut buffer = vec![0; 8 * num_counters as usize];
    file.read_exact(&mut buffer)?;

    let counters: Vec<u64> = buffer.chunks_exact(8).map(|chunk| LittleEndian::read_u64(chunk)).collect();

    Ok(counters)
}

fn read_function_records(file: &mut File, num_data: u64) -> Result<Vec<FunctionRecord>, Error> {
    let mut function_records = Vec::new();

    let mut buffer = vec![0; 48 * num_data as usize]; // The total size of the record is 44 bytes.
    file.read_exact(&mut buffer)?;
    let mut cursor = std::io::Cursor::new(buffer);

    for _ in 0..num_data {
        let fr = FunctionRecord {
            name_ref: cursor.read_u64::<LittleEndian>()?,
            func_hash: cursor.read_u64::<LittleEndian>()?,
            counter_ref: cursor.read_u64::<LittleEndian>()?,
            func_ref: cursor.read_u64::<LittleEndian>()?,
            value_exp: cursor.read_u64::<LittleEndian>()?,
            num_counters: cursor.read_u32::<LittleEndian>()?,
            init_arr: cursor.read_u32::<LittleEndian>()?,
        };
        function_records.push(fr);
    }
    Ok(function_records)
}

pub fn read(filename: &str) -> (f64, f64, HashSet<u64>) {
    let mut file = File::open(filename).unwrap();

    let header = read_profraw_header(&mut file).unwrap();

    // Discard not needed Bytes
    for _ in 0..4 {
        file.read_u64::<LittleEndian>().unwrap();
    }
    let function_records = read_function_records(&mut file, header.data_size).unwrap();
    let counters = read_counters(&mut file, header.counters_size).unwrap();

    let larger_zero = counters.iter().filter(|&&x| x > 0).count();

    let mut current_counter_index: usize = 0;

    let mut executed_fs = HashSet::new();

    for r in 0..function_records.len() {
        let counter_amount = function_records[r].func_hash;
        if counter_amount > 0 {
            let function_execution_count = counters[current_counter_index];
            current_counter_index += counter_amount as usize;
            if function_execution_count > 0 {
                executed_fs.insert(r as u64);
            }
        }
    }

    // let executed_functions = function_records.iter().map(|function_record| {
    //     if function_record.func_hash > 0 {
    //         let function_execution_count = counters[current_counter_index];
    //         current_counter_index += function_record.func_hash as usize;
    //         function_execution_count > 0
    //     } else {
    //         false
    //     }
    //     function_ind += 1;
    // });

    // println!("Executed functions: {}/{}", executed_functions.count(), function_records.len());

    // for r in &function_records {
    //     if r.func_hash != 2 {
    //         println!("Function {:?} has {:?} counters", r.name_ref, r.func_hash);
    //     }
    // }

    // println!("Length hashes here {:?}", function_records);

    // let hashes: Vec<u64> = executed_functions.map(|x| x.func_ref).collect();

    let executed_function_count: usize = executed_fs.len();

    let total_function_count = function_records.len();
    let executed_percentage = (executed_function_count as f64 / total_function_count as f64) * 100.0;

    return (executed_percentage, larger_zero as f64 / counters.len() as f64 * 100.0, executed_fs);
}
