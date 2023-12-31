use std::{fs, process::Command};

use serde_json::Value;

use crate::util;

fn ex_cmd(bin: &str, args: Vec<&str>, env: (&str, &str)) -> String {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    cmd.env(env.0, env.1);
    let output = cmd.output().expect("failed to execute process");
    let res = String::from_utf8_lossy(&output.stdout);
    res.to_string()
}

fn get_rate(binary: &str, name: &str) -> (f64, f64) {
    let profdata_file = name.to_string() + ".profraw";
    // Command to generate the coverage report
    println!("Name is {}", name);

    if name == "routinator" {
        let start = std::time::Instant::now();
        ex_cmd(
            "llvm-profdata-16",
            vec!["merge", &profdata_file, "--o", &("out_".to_string() + name + ".profdata")],
            ("", ""),
        );
        let duration = start.elapsed();

        let start = std::time::Instant::now();
        // Command to make report readable
        let res = ex_cmd(
            "llvm-cov-16",
            vec!["export", "--instr-profile", &("out_".to_string() + name + ".profdata"), binary],
            ("", ""),
        );

        let end = start.elapsed();

        if res.is_empty() {
            println!("Result was empty");

            return (0.0, 0.0);
        }

        let start = std::time::Instant::now();
        let js: Value = serde_json::from_str(&res).unwrap();
        let end = start.elapsed();
        println!("{}", &js["data"][0]["totals"]);
        let pc = &js["data"][0]["totals"]["lines"]["percent"];
        let pc: f64 = pc.as_f64().unwrap();
        let pc2 = &js["data"][0]["totals"]["functions"]["percent"];
        let pc2: f64 = pc2.as_f64().unwrap();
        (pc, pc2)
    } else {
        let start = std::time::Instant::now();
        ex_cmd(
            "llvm-profdata",
            vec![
                "merge",
                &profdata_file,
                "--sparse",
                "--o",
                &("out_".to_string() + name + ".profdata"),
            ],
            ("", ""),
        );
        let duration = start.elapsed();

        let start = std::time::Instant::now();
        // Command to make report readable
        let res = ex_cmd(
            "llvm-cov",
            vec!["export", "--instr-profile", &("out_".to_string() + name + ".profdata"), binary],
            ("", ""),
        );

        let end = start.elapsed();

        if res.is_empty() {
            return (0.0, 0.0);
        }

        let start = std::time::Instant::now();
        let js: Value = serde_json::from_str(&res).unwrap();
        let end = start.elapsed();
        let pc = &js["data"][0]["totals"]["lines"]["percent"];
        let pc: f64 = pc.as_f64().unwrap();
        let pc2 = &js["data"][0]["totals"]["functions"]["percent"];
        let pc2: f64 = pc2.as_f64().unwrap();
        (pc, pc2)
    }
}

pub fn testing() {
    let start = std::time::Instant::now();
    util::run_rp_processes("info");
    let duration = start.elapsed();
    println!("Time elapsed in expensive_function() is: {:?}", duration);
    let binary = "/home/nvogel/git/rp-cure/rp/bin/routinator";
    let name = "routinator";

    let start = std::time::Instant::now();
    let rate = get_rate(binary, name);
    let duration = start.elapsed();
    println!("Rate: {:?}", rate);
}

pub fn testing_2() {
    util::remove_folder_content("coverinfo");
    util::run_rp_processes("info");
    let (com_cov, fun_cov) = go_coverage();
    println!("Go coverage: {}, {}", com_cov, fun_cov);

    let binary = "/home/nvogel/git/rp-cure/rp/bin/routinator";
    let name = "routinator";

    let rate = get_rate(binary, name);
    println!("Rust Coverage: {}, {}", rate.0, rate.1);
}

pub fn read_go_file() {
    let file = "/home/nvogel/Schreibtisch/stuff/hello/lala.txt";
    let contents = std::fs::read_to_string(file).expect("Something went wrong reading the file");
    let lines = contents.split("\n").collect::<Vec<&str>>();
    let mut ret = vec![];
    for i in 1..lines.len() - 1 {
        let line = lines[i];
        let line = line.split(" ").collect::<Vec<&str>>();

        let statements = line[line.len() - 2];
        let count = line[line.len() - 1];

        let beg = line[0].split(":").collect::<Vec<&str>>()[1];
        let beg = beg.split(",").collect::<Vec<&str>>();

        let line_start = beg[0]; //.split(".").collect::<Vec<&str>>()[0];
        let line_end = beg[1]; //.split(".").collect::<Vec<&str>>()[0];

        ret.push([line_start, line_end, statements, count]);
    }
    println!("{:?}", lines);
    println!("{:?}", ret);
}

pub fn get_coverage(rp_name: &str) -> (f64, f64) {
    if rp_name == "octo" {
        return go_coverage();
    } else {
        let binary = "rp/bin/".to_string() + rp_name;
        return get_rate(&binary, rp_name);
    }
}

pub fn go_coverage() -> (f64, f64) {
    let report = convert_go_report();
    println!("Report {:?}", report);
    let raw = read_go_func(report);

    let mut executed = 0;

    println!("Statement coverage {:?}", raw.last().unwrap());

    for v in &raw[..raw.len() - 1] {
        println!("{:?}", v);
        let fcov_s = v.last().unwrap();
        let fcov = fcov_s.parse::<f64>().unwrap();
        if fcov > 0.0 {
            executed += 1;
        }
    }

    println!(
        "Covered functions {}/{}, {}%",
        executed,
        raw.len(),
        executed as f64 / raw.len() as f64 * 100.0
    );

    let function_coverage = executed as f64 / raw.len() as f64;
    let statement_coverage = raw.last().unwrap().last().unwrap().parse::<f64>().unwrap();
    (statement_coverage, function_coverage)
}

pub fn convert_go_report() -> String {
    //go tool covdata textfmt -i=coverinfo -o=lala.txt
    //go tool cover -func=lala.txt -o o.txt

    println!(
        "Return {}",
        ex_cmd("go", vec!["tool", "covdata", "textfmt", "-i=coverinfo", "-o=gocov.txt"], ("", ""))
    );
    let ret = ex_cmd("go", vec!["tool", "cover", "-func=gocov.txt", "-o=goreport.txt"], ("", ""));
    let ret = fs::read_to_string("goreport.txt").unwrap();
    ret
}

pub fn read_go_func(contents: String) -> Vec<Vec<String>> {
    // let file = "/home/nvogel/Schreibtisch/stuff/hello/o.txt";
    // let contents = std::fs::read_to_string(file).expect("Something went wrong reading the file");
    let lines = contents.split("\n").collect::<Vec<&str>>();

    let mut ret = vec![];
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let line = line.replace("\t", " ");
        let mut line = line.split(" ").clone().collect::<Vec<&str>>();
        line.retain(|&x| !x.is_empty());

        let val = line.iter().map(|&x| x.to_string().replace("%", "")).collect::<Vec<String>>();

        ret.push(val.clone());
    }
    ret
}
