use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Error, Read, Seek, SeekFrom};
use std::str;
use std::time::Instant;

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
    let mut buffer = [0; 48]; // The total size of the record is 44 bytes.
    file.read_exact(&mut buffer)?;
    let mut cursor = std::io::Cursor::new(buffer);

    Ok(FunctionRecord {
        name_ref: cursor.read_u64::<LittleEndian>()?,
        func_hash: cursor.read_u64::<LittleEndian>()?,
        counter_ref: cursor.read_u64::<LittleEndian>()?,
        func_ref: cursor.read_u64::<LittleEndian>()?,
        value_exp: cursor.read_u64::<LittleEndian>()?,
        num_counters: cursor.read_u32::<LittleEndian>()?,
        init_arr: cursor.read_u32::<LittleEndian>()?,
    })
}

fn read_counters(file: &mut File, num_counters: u64) -> Result<Vec<u64>, Error> {
    let mut buffer = vec![0; 8 * num_counters as usize];
    file.read_exact(&mut buffer)?;

    let counters: Vec<u64> = buffer.chunks_exact(8).map(|chunk| LittleEndian::read_u64(chunk)).collect();

    Ok(counters)
}

fn read_function_names(file: &mut File, names_size: u64) -> Result<Vec<String>, Error> {
    // let mut names = Vec::new();
    let v = file.read_u64::<LittleEndian>().unwrap();
    for i in 0..10 {
        let v = file.read_u8().unwrap();
        println!("v is {}", v);
        // let mut buf = [0; 2];
        // file.read_exact(&mut buf).unwrap();
        // println!("buf is {:?}", hex::encode(buf));
        // println!("Next char is {}", str::from_utf8(&buf).unwrap_or_default());
    }
    Ok(vec![])
    // file.read_buf(buf)
    // println!("names_size: {}", names_size);
    // let mut name_buffer = vec![0; names_size as usize];
    // file.read_exact(&mut name_buffer)?;

    // let mut start = 0;
    // for i in 0..names_size {
    //     if name_buffer[i as usize] == 0 {
    //         let name = str::from_utf8(&name_buffer[start..i as usize]);
    //         if name.is_err() {
    //             println!("Error");
    //             continue;
    //         }
    //         let name = name.unwrap();
    //         names.push(name.to_string());
    //         start = i as usize + 1;
    //     }
    // }
    // Ok(names)
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

pub fn read() -> (f64, f64) {
    let start = Instant::now();

    // let mut file = File::open("/home/nvogel/Schreibtisch/stuff/profraw_test/default.profraw")?;
    let mut file = File::open("routinator.profraw").unwrap();

    let header = read_profraw_header_new(&mut file).unwrap();

    // Discard not needed Byts
    for i in 0..4 {
        file.read_u64::<LittleEndian>();
    }
    let function_records = read_function_records(&mut file, header.data_size)?;
    let counters = read_counters(&mut file, header.counters_size).unwrap();

    let larger_zero = counters.iter().filter(|&&x| x > 0).count();

    let mut executed_function_count: usize = 0;
    let mut current_counter_index: usize = 0;
    let executed_function_count: usize = function_records
        .iter()
        .filter(|function_record| {
            if function_record.num_counters > 0 {
                let function_execution_count = counters[current_counter_index];
                current_counter_index += function_record.num_counters as usize;
                function_execution_count > 0
            } else {
                false
            }
        })
        .count();

    let total_function_count = function_records.len();
    let executed_percentage = (executed_function_count as f64 / total_function_count as f64) * 100.0;

    return (executed_percentage, larger_zero as f64 / counters.len() as f64 * 100.0);
}
