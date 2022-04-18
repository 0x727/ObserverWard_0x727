#![feature(once_cell)]

use crate::cli::ObserverWardConfig;
use error::Error;
use futures::channel::mpsc::unbounded;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use observer_ward_what_server::{NmapFingerPrint, WhatServer};
use observer_ward_what_web::fingerprint::WebFingerPrint;
use observer_ward_what_web::{RequestOption, TemplateResult, WhatWeb, WhatWebResult};
use prettytable::csv::Reader;
use prettytable::{color, Attr, Cell, Row, Table};
use reqwest::redirect::Policy;
use reqwest::{header, Proxy};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::io::Cursor;
use std::io::{BufRead, Read};
use std::iter::FromIterator;
use std::lazy::SyncLazy;
use std::path::{Path, PathBuf};
use std::time::Duration;
use term::color::Color;
use tokio::process::Command;

pub mod api;
pub mod cli;
pub mod error;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyWebFingerPrint {
    name: String,
    priority: u32,
    fingerprint: Vec<WebFingerPrint>,
}

pub fn print_color(mut string: String, color: Color, nl: bool) {
    if nl {
        string.push('\n')
    }
    if let Some(mut t) = term::stdout() {
        t.fg(color).ok();
        write!(t, "{}", string).expect("print_color err");
        t.reset().ok();
    } else {
        print!("{}", string);
    };
}

pub fn print_what_web(what_web_result: &WhatWebResult) {
    let color_web_name: Vec<String> = what_web_result.name.iter().map(String::from).collect();
    let status_code =
        reqwest::StatusCode::from_u16(what_web_result.status_code).unwrap_or_default();
    if !what_web_result.name.is_empty() {
        print!("[ {} |", what_web_result.url);
        print_color(format!("{:?}", color_web_name), term::color::GREEN, false);
        print!(" | {} | ", what_web_result.length);
        if status_code.is_success() {
            print_color(format!("{:?}", status_code), term::color::GREEN, false);
        } else {
            print_color(format!("{:?}", status_code), term::color::RED, false);
        }
        println!(" | {} ]", what_web_result.title);
    } else {
        println!(
            "[ {} | {:?} | {} | {} | {} ]",
            what_web_result.url,
            color_web_name,
            what_web_result.length,
            what_web_result.status_code,
            what_web_result.title,
        );
    }
}

pub fn print_nuclei(what_web_result: &WhatWebResult) {
    for template in what_web_result.template_result.iter() {
        print_color(
            format!("[{}]", template.template_id),
            term::color::RED,
            false,
        );
        println!(" | [{}] ", template.matched_at);
    }
}

pub async fn webhook_results(what_web_result: WhatWebResult, webhook_url: &str) -> WhatWebResult {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0";
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .pool_max_idle_per_host(0)
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .timeout(Duration::new(10, 0));
    let what_web_result_json = json!(what_web_result)
        .as_object()
        .unwrap_or(&serde_json::Map::new())
        .clone();
    let _: Result<_, _> = client
        .build()
        .unwrap_or_default()
        .post(webhook_url)
        .json(&what_web_result_json)
        .send()
        .await;
    what_web_result.clone()
}

pub fn print_opening() {
    let s = r#" __     __     ______     ______     _____
/\ \  _ \ \   /\  __ \   /\  == \   /\  __-.
\ \ \/ ".\ \  \ \  __ \  \ \  __<   \ \ \/\ \
 \ \__/".~\_\  \ \_\ \_\  \ \_\ \_\  \ \____-
  \/_/   \/_/   \/_/\/_/   \/_/ /_/   \/____/
Community based web fingerprint analysis tool."#;
    print_color(s.to_string(), term::color::GREEN, true);
    let info = r#"_____________________________________________
:  https://github.com/0x727/FingerprintHub  :
:  https://github.com/0x727/ObserverWard    :
 --------------------------------------------"#;
    print_color(info.to_string(), term::color::YELLOW, true);
}

pub struct Helper {
    request_option: RequestOption,
    config_path: PathBuf,
    config: ObserverWardConfig,
    msg: HashMap<String, String>,
}

static OBSERVER_WARD_PATH: SyncLazy<PathBuf> = SyncLazy::new(|| -> PathBuf {
    let mut config_path = PathBuf::new();
    if let Some(cp) = dirs::config_dir() {
        config_path = cp;
    } else {
        println!("Cannot create config directory{:?}", config_path);
        std::process::exit(0);
    }
    let observer_ward = config_path.join("observer_ward");
    if !observer_ward.is_dir() || !observer_ward.exists() {
        std::fs::create_dir_all(&observer_ward).unwrap_or_default();
    }
    observer_ward
});

impl Helper {
    pub fn new(config: &ObserverWardConfig) -> Self {
        let ro = RequestOption::new(&config.timeout, &config.proxy);
        Self {
            request_option: ro,
            config_path: OBSERVER_WARD_PATH.clone(),
            config: config.clone(),
            msg: Default::default(),
        }
    }
    async fn update_fingerprint(&mut self) {
        let fingerprint_path = self.config_path.join("web_fingerprint_v3.json");
        self.download_file_from_github(
            "https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json",
            fingerprint_path
                .to_str()
                .unwrap_or("web_fingerprint_v3.json"),
        )
        .await;
        // self.download_file_from_github(
        //     "https://0x727.github.io/FingerprintHub/nmap_service_probes.json",
        //     "nmap_service_probes.json",
        // )
        // .await;
    }
    async fn update_plugins(&mut self) {
        let plugins_zip_path = self.config_path.join("plugins.zip");
        let extract_target_path = self.config_path.clone();
        self.download_file_from_github(
            "https://github.com/0x727/FingerprintHub/releases/download/default/plugins.zip",
            plugins_zip_path.to_str().unwrap_or("plugins.zip"),
        )
        .await;
        match extract_plugins_zip(&plugins_zip_path, &extract_target_path) {
            Ok(_) => {
                println!("It has been extracted to the {:?}", extract_target_path);
            }
            Err(err) => {
                println!("{:?}", err);
                println!("Please manually unzip the plugins to the directory");
            }
        }
    }
    pub async fn run(&mut self) -> HashMap<String, String> {
        if self.config.update_fingerprint {
            self.update_fingerprint().await;
        }
        if self.config.update_self {
            self.update_self().await;
        }
        if self.config.update_plugins {
            self.update_plugins().await;
        }
        if !self.msg.is_empty() {
            for (k, v) in &self.msg {
                print!("{}:{}", k, v);
            }
        }
        self.msg.clone()
    }
}

impl Helper {
    pub async fn update_self(&mut self) {
        // https://doc.rust-lang.org/reference/conditional-compilation.html
        let mut base_url =
            String::from("https://github.com/0x727/ObserverWard/releases/download/default/");
        let mut download_name = "observer_ward_amd64";
        if cfg!(target_os = "windows") {
            download_name = "observer_ward.exe";
        } else if cfg!(target_os = "linux") {
            download_name = "observer_ward_amd64";
        } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
            download_name = "observer_ward_darwin";
        } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            download_name = "observer_ward_aarch64_darwin";
        };
        base_url.push_str(download_name);
        let save_filename = "update_".to_owned() + download_name;
        self.download_file_from_github(&base_url, &save_filename)
            .await;
        println!(
            "Please rename the file {} => {}",
            save_filename, download_name
        );
    }

    pub fn read_nmap_fingerprint(&mut self) -> Vec<NmapFingerPrint> {
        let nmap_fingerprint_path = self.config_path.join("nmap_service_probes.json");
        if let Ok(mut file) = File::open(nmap_fingerprint_path) {
            let mut data = String::new();
            file.read_to_string(&mut data).ok();
            let nmap_fingerprint: Vec<NmapFingerPrint> =
                serde_json::from_str(&data).expect("BAD JSON");
            return nmap_fingerprint;
        } else {
            println!("The nmap fingerprint library cannot be found in the current directory!");
        }
        Vec::new()
    }

    pub fn read_web_fingerprint(&mut self, verify: &str) -> Vec<WebFingerPrint> {
        if !verify.is_empty() {
            if let Ok(mut file) = File::open(verify) {
                let mut data = String::new();
                file.read_to_string(&mut data).ok();
                let mut web_fingerprint: Vec<WebFingerPrint> = vec![];
                let verify_fingerprints: VerifyWebFingerPrint =
                    serde_yaml::from_str(&data).expect("BAD YAML");
                for mut verify_fingerprint in verify_fingerprints.fingerprint {
                    verify_fingerprint.name = verify_fingerprints.name.clone();
                    verify_fingerprint.priority = verify_fingerprints.priority;
                    web_fingerprint.push(verify_fingerprint);
                }
                return web_fingerprint;
            } else {
                println!("The verification file cannot be found in the current directory!");
            }
        }
        let mut web_fingerprint_path = PathBuf::from("web_fingerprint_v3.json");
        if !web_fingerprint_path.exists() {
            web_fingerprint_path = self.config_path.join("web_fingerprint_v3.json");
        }
        if let Ok(mut file) = File::open(web_fingerprint_path) {
            let mut data = String::new();
            file.read_to_string(&mut data).ok();
            let web_fingerprint: Vec<WebFingerPrint> =
                serde_json::from_str(&data).expect("BAD JSON");
            return web_fingerprint;
        } else {
            println!("The fingerprint library cannot be found in the current directory!");
            println!("Update fingerprint library with `-u` parameter!");
        }
        Vec::new()
    }

    pub fn read_results_file(&self) -> Vec<WhatWebResult> {
        let mut results: Vec<WhatWebResult> = Vec::new();
        let read_file_data = |path: &str| {
            let mut file = match File::open(path) {
                Err(err) => {
                    println!("{}", err);
                    std::process::exit(0);
                }
                Ok(file) => file,
            };
            let mut data = String::new();
            file.read_to_string(&mut data).ok();
            data
        };
        if !self.config.json.is_empty() {
            let data = read_file_data(&self.config.json);
            let wwr: Vec<WhatWebResult> = serde_json::from_str(&data).expect("BAD JSON");
            results.extend(wwr);
        }
        if !self.config.csv.is_empty() {
            let rdr = Reader::from_path(&self.config.csv).expect("BAD CSV");
            let iter: csv::DeserializeRecordsIntoIter<File, WhatWebResult> = rdr.into_deserialize();
            let wwr: Vec<WhatWebResult> = iter.filter_map(Result::ok).collect();
            results.extend(wwr);
        }
        results
    }
    async fn download_file_from_github(&mut self, update_url: &str, filename: &str) {
        let proxy = self.request_option.proxy.clone();
        let proxy_obj = Proxy::custom(move |_url| proxy.clone());
        let client = reqwest::Client::builder().proxy(proxy_obj);
        if let Ok(downloading_client) = client.build() {
            if let Ok(response) = downloading_client.get(update_url).send().await {
                let mut file = std::fs::File::create(filename).unwrap();
                let mut content = Cursor::new(response.bytes().await.unwrap_or_default());
                std::io::copy(&mut content, &mut file).unwrap_or_default();
                self.msg.insert(
                    String::from("info"),
                    format!(
                        "Update: '{}' file size => {:?}",
                        filename,
                        file.metadata().unwrap().len()
                    ),
                );
                return;
            }
        }
        self.msg.insert(
            String::from("err"),
            format!(
                "Update failed, please download {} to local directory manually.",
                update_url
            ),
        );
    }
}

pub fn read_file_to_target(file_path: &str) -> HashSet<String> {
    if let Ok(lines) = read_lines(file_path) {
        let target_list: Vec<String> = lines.filter_map(Result::ok).collect();
        return HashSet::from_iter(target_list);
    }
    HashSet::from_iter([])
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn print_results_and_save(
    json: &str,
    csv: &str,
    results: Vec<WhatWebResult>,
    has_plugins: bool,
) {
    if !json.is_empty() {
        let out = File::create(&json).expect("Failed to create file");
        serde_json::to_writer(out, &results).expect("Failed to save file")
    }
    let mut table = Table::new();
    let mut headers = vec![
        Cell::new("url"),
        Cell::new("name"),
        Cell::new("length"),
        Cell::new("status_code"),
        Cell::new("title"),
        Cell::new("priority"),
    ];
    if has_plugins {
        headers.push(Cell::new("plugins"))
    }
    table.set_titles(Row::new(headers.clone()));
    for res in &results {
        let wwn: Vec<String> = res.name.iter().map(String::from).collect();
        let status_code = reqwest::StatusCode::from_u16(res.status_code).unwrap_or_default();
        let mut status_code_color = Attr::ForegroundColor(color::RED);
        if status_code.is_success() {
            status_code_color = Attr::ForegroundColor(color::GREEN);
        }
        let mut rows = vec![
            Cell::new(res.url.as_str()),
            Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new(&res.length.to_string()),
            Cell::new(&res.status_code.to_string()).with_style(status_code_color),
            Cell::new(&textwrap::fill(res.title.as_str(), 40)),
            Cell::new(&res.priority.to_string()),
        ];
        if has_plugins {
            let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
            rows.push(Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::RED)))
        }
        table.add_row(Row::new(rows));
    }
    if !csv.is_empty() {
        let out = File::create(&csv).expect("Failed to create file");
        table.to_csv(out).expect("Failed to save file");
    }
    let mut table = Table::new();
    table.set_titles(Row::new(headers.clone()));
    for res in &results {
        let wwn: Vec<String> = res.name.iter().map(String::from).collect();
        let status_code = reqwest::StatusCode::from_u16(res.status_code).unwrap_or_default();
        let mut status_code_color = Attr::ForegroundColor(color::RED);
        if status_code.is_success() {
            status_code_color = Attr::ForegroundColor(color::GREEN);
        }
        let mut rows = vec![
            Cell::new(res.url.as_str()),
            Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new(&res.length.to_string()),
            Cell::new(&res.status_code.to_string()).with_style(status_code_color),
            Cell::new(&textwrap::fill(res.title.as_str(), 40)),
            Cell::new(&res.priority.to_string()),
        ];
        if has_plugins {
            let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
            rows.push(Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::RED)))
        }
        table.add_row(Row::new(rows));
    }
    if !table.is_empty() {
        print_color(
            String::from("Important technology:\n"),
            term::color::YELLOW,
            true,
        );
        table.printstd();
    }
}

fn extract_plugins_zip(f_name: &Path, extract_target_path: &Path) -> Result<(), Error> {
    let plugins_path = extract_target_path.join("plugins");
    if plugins_path.exists() {
        std::fs::remove_dir_all(plugins_path)?;
    }
    let zipfile = std::fs::File::open(f_name)?;
    let mut archive = zip::ZipArchive::new(zipfile)?;
    archive.extract(extract_target_path)?;
    Ok(())
}

pub async fn get_plugins_by_nuclei(w: WhatWebResult, config: &ObserverWardConfig) -> WhatWebResult {
    let mut wwr = w.clone();
    let mut plugins_set: HashSet<String> = HashSet::new();
    let mut exist_plugins: Vec<String> = Vec::new();
    for name in wwr.name.iter() {
        let plugins_name_path = Path::new(&config.plugins).join(name);
        if plugins_name_path.exists() {
            if let Some(p_path) = plugins_name_path.to_str() {
                exist_plugins.push(p_path.to_string())
            }
        }
    }
    if exist_plugins.is_empty() {
        return wwr;
    }
    let mut command_line = Command::new("nuclei");
    command_line.args([
        "-u",
        &wwr.url,
        "-no-color",
        "-timeout",
        &(config.timeout + 5).to_string(),
    ]);
    command_line.args([
        "-H",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
    ]);
    for p in exist_plugins.iter() {
        command_line.args(["-t", p]);
    }
    command_line.args(["-silent", "-json"]);
    let output = command_line.output().await.expect("command_line_output");
    if let Ok(template_output) = String::from_utf8(output.stdout) {
        let templates_output: Vec<String> = template_output
            .split_terminator('\n')
            .map(String::from)
            .collect();
        for line in templates_output.iter() {
            let template: TemplateResult = serde_json::from_str(line).unwrap_or_default();
            wwr.template_result.push(template.clone());
            plugins_set.insert(template.template_id);
        }
    }
    wwr.plugins = plugins_set;
    if !wwr.plugins.is_empty() {
        wwr.priority += 1;
    }
    wwr
}

#[derive(Clone)]
pub struct ObserverWard {
    what_server_ins: WhatServer,
    what_web_ins: WhatWeb,
    config: ObserverWardConfig,
}

impl Default for ObserverWard {
    fn default() -> Self {
        let config = ObserverWardConfig::new();
        let mut helper = Helper::new(&config);
        let web_fingerprint = helper.read_web_fingerprint(&config.verify);
        let mut nmap_fingerprint = vec![];
        if config.service {
            nmap_fingerprint = helper.read_nmap_fingerprint();
        }
        ObserverWard::new(config.clone(), web_fingerprint, nmap_fingerprint)
    }
}

impl ObserverWard {
    pub fn new(
        config: ObserverWardConfig,
        web_fingerprint: Vec<WebFingerPrint>,
        nmap_fingerprint: Vec<NmapFingerPrint>,
    ) -> Self {
        let request_option = RequestOption::new(&config.timeout, &config.proxy);
        let what_server_ins = WhatServer::new(300, nmap_fingerprint);
        let what_web_ins = WhatWeb::new(request_option, web_fingerprint);
        Self {
            what_server_ins,
            what_web_ins,
            config,
        }
    }
    pub async fn scan(&self, targets: HashSet<String>) -> Vec<WhatWebResult> {
        let config = self.config.clone();
        let what_web_ins = self.what_web_ins.clone();
        let what_server_ins = self.what_server_ins.clone();
        let (what_web_sender, mut what_web_receiver) = unbounded();
        let (mut what_server_sender, mut what_server_receiver) = unbounded();
        let (mut verify_sender, mut verify_receiver) = unbounded();
        let (mut results_sender, mut results_receiver) = unbounded();
        let mut vec_results: Vec<WhatWebResult> = vec![];
        let config_thread = config.thread;
        let is_debug = !config.verify.is_empty();
        let webhook = config.webhook.clone();
        let what_web_handle = tokio::task::spawn(async move {
            let mut worker = FuturesUnordered::new();
            let mut targets_iter = targets.iter();
            for _ in 0..config_thread {
                match targets_iter.next() {
                    Some(target) => worker.push(what_web_ins.scan(target.to_string(), is_debug)),
                    None => {
                        break;
                    }
                }
            }
            while let Some(result) = worker.next().await {
                if let Some(target) = targets_iter.next() {
                    worker.push(what_web_ins.scan(target.to_string(), is_debug));
                }
                what_web_sender.unbounded_send(result).unwrap_or_default();
            }
            true
        });
        let what_server_handle = tokio::task::spawn(async move {
            let mut worker = FuturesUnordered::new();
            for _ in 0..3 {
                match what_web_receiver.next().await {
                    Some(w) => worker.push(what_server_ins.scan(w)),
                    None => {
                        break;
                    }
                }
            }
            while let Some(wwr) = worker.next().await {
                if let Some(v_wwr) = what_web_receiver.next().await {
                    worker.push(what_server_ins.scan(v_wwr));
                }
                print_what_web(&wwr);
                what_server_sender.start_send(wwr).unwrap_or_default();
            }
            true
        });
        let plugins_path = config.plugins.clone();
        let verify_handle = tokio::task::spawn(async move {
            if !plugins_path.is_empty() {
                let mut worker = FuturesUnordered::new();
                for _ in 0..3 {
                    match what_server_receiver.next().await {
                        Some(w) => {
                            worker.push(get_plugins_by_nuclei(w, &config));
                        }
                        None => {
                            break;
                        }
                    }
                }
                while let Some(wwr) = worker.next().await {
                    if let Some(v_wwr) = what_server_receiver.next().await {
                        worker.push(get_plugins_by_nuclei(v_wwr, &config));
                    }
                    print_nuclei(&wwr);
                    verify_sender.start_send(wwr).unwrap_or_default();
                }
            } else {
                while let Some(wwr) = what_server_receiver.next().await {
                    verify_sender.start_send(wwr).unwrap_or_default();
                }
            }
            true
        });

        let results_handle = tokio::task::spawn(async move {
            let mut worker = FuturesUnordered::new();
            if !webhook.is_empty() {
                for _ in 0..3 {
                    match verify_receiver.next().await {
                        Some(w) => {
                            worker.push(webhook_results(w, &webhook));
                        }
                        None => {
                            break;
                        }
                    }
                }
                while let Some(wwr) = worker.next().await {
                    if let Some(w) = verify_receiver.next().await {
                        worker.push(webhook_results(w, &webhook));
                    }
                    results_sender.start_send(wwr).unwrap_or_default();
                }
            } else {
                while let Some(wwr) = verify_receiver.next().await {
                    results_sender.start_send(wwr).unwrap_or_default();
                }
            }
            true
        });
        let (_r1, _r2, _r3, _r4) = tokio::join!(
            what_web_handle,
            what_server_handle,
            verify_handle,
            results_handle
        );
        while let Some(wwr) = results_receiver.next().await {
            vec_results.push(wwr);
        }
        if vec_results.len() < 2000 {
            vec_results.sort_by(|a, b| b.priority.cmp(&a.priority));
        }
        vec_results
    }
    pub fn reload(&mut self, config: &ObserverWardConfig) {
        let mut helper = Helper::new(config);
        let web_fingerprint = helper.read_web_fingerprint(&config.verify);
        let mut nmap_fingerprint = vec![];
        if config.service {
            nmap_fingerprint = helper.read_nmap_fingerprint();
        }
        let request_option = RequestOption::new(&config.timeout, &config.proxy);
        let what_server_ins = WhatServer::new(300, nmap_fingerprint);
        let what_web_ins = WhatWeb::new(request_option, web_fingerprint);
        self.config = config.clone();
        self.what_web_ins = what_web_ins;
        self.what_server_ins = what_server_ins;
    }
}

// 去重
pub fn strings_to_urls(domains: String) -> HashSet<String> {
    let target_list = domains
        .split_terminator('\n')
        .map(String::from)
        .collect::<Vec<_>>();
    HashSet::from_iter(target_list)
}
