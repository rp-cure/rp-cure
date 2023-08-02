use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Error, Read, Seek, SeekFrom};
use std::str;

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
}

#[derive(Debug)]
struct ProfrawHeaderNew {
    magic: u64,
    version: u64,
    binary_id_size: u64,
    data_size: u64,
    padding_before_counters: u64,
    counters_size: u64,
    padding_after_counters: u64,
    names_size: u64,
    counters_delta: u64,
    names_begin: u64,
    value_kind_last: u64,
}

// #[derive(Debug)]
// struct ProfrawHeaderNew {
//     magic: u64,
//     version: u64,
//     binary_id_size: u64,
//     counters_delta: u64,
//     names_delta: u64,
//     num_data: u64,
//     padding_before_counters: u64,
//     counters_size: u64,
//     padding_after_counters: u64,
//     names_size: u64,
//     value_kind_last: u64,
// }

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
    Ok(ProfrawHeader {
        magic: file.read_u64::<LittleEndian>()?,
        version: file.read_u64::<LittleEndian>()?,
        data_size: file.read_u64::<LittleEndian>()?,
        padding_before_counters: file.read_u64::<LittleEndian>()?,
        counters_size: file.read_u64::<LittleEndian>()?,
        padding_after_counters: file.read_u64::<LittleEndian>()?,
        names_size: file.read_u64::<LittleEndian>()?,
        counters_delta: file.read_u64::<LittleEndian>()?,
        names_begin: file.read_u64::<LittleEndian>()?,
        value_kind_last: file.read_u64::<LittleEndian>()?,
    })
}

// fn read_profraw_header_new(file: &mut File) -> Result<ProfrawHeaderNew, Error> {
//     Ok(ProfrawHeaderNew {
//         magic: file.read_u64::<LittleEndian>()?,
//         version: file.read_u64::<LittleEndian>()?,
//         binary_id_size: file.read_u64::<LittleEndian>()?,
//         counters_delta: file.read_u64::<LittleEndian>()?,
//         names_delta: file.read_u64::<LittleEndian>()?,
//         num_data: file.read_u64::<LittleEndian>()?,
//         padding_before_counters: file.read_u64::<LittleEndian>()?,
//         counters_size: file.read_u64::<LittleEndian>()?,
//         padding_after_counters: file.read_u64::<LittleEndian>()?,
//         names_size: file.read_u64::<LittleEndian>()?,
//         value_kind_last: file.read_u64::<LittleEndian>()?,
//     })
// }

fn read_profraw_header_new(file: &mut File) -> Result<ProfrawHeaderNew, Error> {
    Ok(ProfrawHeaderNew {
        magic: file.read_u64::<LittleEndian>()?,
        version: file.read_u64::<LittleEndian>()?,
        binary_id_size: file.read_u64::<LittleEndian>()?,
        data_size: file.read_u64::<LittleEndian>()?,
        padding_before_counters: file.read_u64::<LittleEndian>()?,
        counters_size: file.read_u64::<LittleEndian>()?,
        padding_after_counters: file.read_u64::<LittleEndian>()?,
        names_size: file.read_u64::<LittleEndian>()?,
        counters_delta: file.read_u64::<LittleEndian>()?,
        names_begin: file.read_u64::<LittleEndian>()?,
        value_kind_last: file.read_u64::<LittleEndian>()?,
    })
}

fn read_function_record(file: &mut File) -> Result<FunctionRecord, Error> {
    Ok(FunctionRecord {
        name_ref: file.read_u64::<LittleEndian>()?,
        func_hash: file.read_u64::<LittleEndian>()?,
        counter_ref: file.read_u64::<LittleEndian>()?,
        func_ref: file.read_u64::<LittleEndian>()?,
        value_exp: file.read_u64::<LittleEndian>()?,
        num_counters: file.read_u32::<LittleEndian>()?,
        init_arr: file.read_u32::<LittleEndian>()?,
    })
}

fn read_counters(file: &mut File, num_counters: u64) -> Result<Vec<u64>, Error> {
    let mut counters = Vec::new();
    for _ in 0..num_counters {
        counters.push(file.read_u64::<LittleEndian>()?);
    }
    Ok(counters)
}

fn read_function_names(file: &mut File, names_size: u64) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    let mut name_buffer = vec![0; names_size as usize];
    file.read_exact(&mut name_buffer)?;

    let mut start = 0;
    for i in 0..names_size {
        if name_buffer[i as usize] == 0 {
            let name = str::from_utf8(&name_buffer[start..i as usize]);
            if name.is_err() {
                println!("Error");
                continue;
            }
            let name = name.unwrap();
            names.push(name.to_string());
            start = i as usize + 1;
        }
    }
    Ok(names)
}

pub fn read() -> Result<(), Error> {
    let mut file = File::open("/home/nvogel/Schreibtisch/stuff/profraw_test/default.profraw")?;

    // Read the header
    let header = read_profraw_header_new(&mut file)?;
    println!("{:?}", header);
    // return Ok(());

    // Read the function records
    for i in 0..4 {
        file.read_u64::<LittleEndian>();
    }
    let mut function_records = Vec::new();
    for _ in 0..header.data_size {
        // Each function record is 32 bytes
        function_records.push(read_function_record(&mut file)?);
    }
    println!("Function records {:?}", function_records);

    // Read the counters
    let counters = read_counters(&mut file, header.counters_size)?; // Each counter is 8 bytes
    println!("{:?}", counters);

    // Read the function names
    let function_names = read_function_names(&mut file, header.names_size)?;
    println!("{:?}", function_names);

    let mut executed_function_count: usize = 0;
    let mut current_counter_index: usize = 0;
    for (i, function_record) in function_records.iter().enumerate() {
        if function_record.num_counters > 0 {
            let function_execution_count = counters[current_counter_index];
            current_counter_index += function_record.num_counters as usize;
            if function_execution_count > 0 {
                executed_function_count += 1;
                println!("Function  was executed {} times", function_execution_count);
            }
        }
    }

    // Print the percentage of executed functions
    let total_function_count = function_records.len();
    let executed_percentage = (executed_function_count as f64 / total_function_count as f64) * 100.0;
    println!(
        "{} out of {} functions were executed ({}%)",
        executed_function_count, total_function_count, executed_percentage
    );
    Ok(())
}
