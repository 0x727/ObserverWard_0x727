#![feature(once_cell)]

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, Write};
use std::lazy::SyncLazy;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::{io, net::SocketAddr, time::Duration};

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use observer_ward_what_web::WhatWebResult;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use unescape_lib::unescape_func;

mod unescape_lib;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Matches {
    service: String,
    #[serde(deserialize_with = "unescape_func")]
    pattern: Vec<u8>,
    version_info: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NmapFingerPrint {
    matches: Vec<Matches>,
    directive_name: String,
    protocol: String,
    #[serde(deserialize_with = "unescape_func")]
    directive_str: Vec<u8>,
    total_wait_ms: Option<u8>,
    tcp_wrapped_ms: Option<u8>,
    #[serde(default)]
    rarity: u8,
    #[serde(default)]
    ports: Vec<u16>,
    ssl_ports: Option<String>,
    fallback: Option<String>,
}

impl NmapFingerPrint {
    pub async fn match_rules(&self, response: &[u8]) -> HashSet<String> {
        let mut server_name: HashSet<String> = HashSet::new();
        let mut futures = FuturesUnordered::new();
        let mut matches_iter = self.matches.iter();
        for _ in 0..matches_iter.len() {
            if let Some(rule) = matches_iter.next() {
                futures.push(self.what_server(rule, response));
            }
        }
        while let Some(result) = futures.next().await {
            if let Some(rule) = matches_iter.next() {
                futures.push(self.what_server(rule, response));
            }
            if !result.is_empty() {
                server_name.insert(result);
                return server_name;
            }
        }
        server_name
    }
    async fn what_server(&self, rule: &Matches, text: &[u8]) -> String {
        let regex_str = std::str::from_utf8(&rule.pattern);
        if let Ok(ok_regex_str) = regex_str {
            return match Regex::new(ok_regex_str) {
                Ok(re) => {
                    if re.captures(text).is_some() {
                        rule.service.clone()
                    } else {
                        String::new()
                    }
                }
                Err(_) => String::new(),
            };
        }
        String::new()
    }
}

#[derive(Clone)]
pub struct WhatServer {
    timeout: u64,
    fingerprint: Arc<Vec<NmapFingerPrint>>,
}

impl WhatServer {
    pub fn new(timeout: u64, nmap_fingerprint: Vec<NmapFingerPrint>) -> Self {
        let fingerprint: Arc<Vec<NmapFingerPrint>> = Arc::new(nmap_fingerprint);
        Self {
            timeout,
            fingerprint,
        }
    }
    fn filter_probes_by_port(&self, port: u16) -> (Vec<&NmapFingerPrint>, Vec<&NmapFingerPrint>) {
        let (mut in_probes, mut ex_probes): (Vec<&NmapFingerPrint>, Vec<&NmapFingerPrint>) =
            (vec![], vec![]);
        for nmap_fingerprint in self.fingerprint.iter() {
            if nmap_fingerprint.ports.contains(&port) {
                in_probes.push(nmap_fingerprint);
            } else {
                ex_probes.push(nmap_fingerprint);
            }
        }
        (in_probes, ex_probes)
    }
    fn send_directive_str_request(&self, socket: SocketAddr, payload: Vec<u8>) -> Vec<u8> {
        let received: Vec<u8> = Vec::new();
        if let Ok(mut stream) = self.connect(socket) {
            stream
                .set_write_timeout(Some(Duration::from_millis(self.timeout)))
                .unwrap_or_default();
            stream
                .set_read_timeout(Some(Duration::from_millis(self.timeout)))
                .unwrap_or_default();
            stream.write_all(&payload).unwrap();
            stream.flush().unwrap();
            let mut reader = io::BufReader::new(&mut stream);
            let received: Vec<u8> = reader.fill_buf().unwrap_or_default().to_vec();
            reader.consume(received.len());
            return received;
        };
        received
    }

    fn connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(socket)?;
        stream.set_nodelay(true).unwrap();
        stream.set_ttl(100).unwrap();
        Ok(stream)
    }
    async fn exec_run(&self, probe: &NmapFingerPrint, host_port: SocketAddr) -> HashSet<String> {
        let response = self.send_directive_str_request(host_port, probe.directive_str.clone());
        let server = probe.match_rules(&response).await;
        server
    }
    pub async fn scan(&self, what_web_result: WhatWebResult) -> WhatWebResult {
        if self.fingerprint.is_empty() {
            return what_web_result;
        }
        let mut what_web_result = what_web_result.clone();
        match SocketAddr::from_str(&what_web_result.url) {
            Ok(socket) => {
                let (in_probes, ex_probes) = self.filter_probes_by_port(socket.port());
                let mut in_probes_iter = in_probes.into_iter();
                let mut ex_probes_iter = ex_probes.into_iter();
                let mut futures = FuturesUnordered::new();
                for _ in 0..32 {
                    if let Some(probes) = in_probes_iter.next() {
                        futures.push(self.exec_run(probes, socket));
                    }
                }
                while let Some(result) = futures.next().await {
                    if let Some(probes) = in_probes_iter.next() {
                        futures.push(self.exec_run(probes, socket));
                    }
                    if !result.is_empty() {
                        what_web_result.name = result;
                        return what_web_result;
                    }
                }
                let mut futures = FuturesUnordered::new();
                for _ in 0..32 {
                    if let Some(probes) = ex_probes_iter.next() {
                        futures.push(self.exec_run(probes, socket));
                    }
                }
                while let Some(result) = futures.next().await {
                    if let Some(probes) = ex_probes_iter.next() {
                        futures.push(self.exec_run(probes, socket));
                    }
                    if !result.is_empty() {
                        what_web_result.name = result;
                        return what_web_result;
                    }
                }
            }
            Err(_) => return what_web_result,
        }
        what_web_result
    }
}

#[allow(dead_code)]
static NMAP_FINGERPRINT_LIB_DATA: SyncLazy<Vec<NmapFingerPrint>> =
    SyncLazy::new(|| -> Vec<NmapFingerPrint> {
        let self_path: PathBuf = env::current_exe().unwrap_or_default();
        let path = Path::new(&self_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let mut file = match File::open(path.join("nmap_service_probes.json")) {
            Err(_) => {
                println!("The nmap fingerprint library cannot be found in the current directory!");
                std::process::exit(0);
            }
            Ok(file) => file,
        };
        let mut data = String::new();
        file.read_to_string(&mut data).ok();
        let nmap_fingerprint: Vec<NmapFingerPrint> = serde_json::from_str(&data).expect("BAD JSON");
        nmap_fingerprint
    });
