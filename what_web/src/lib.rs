#![feature(once_cell)]

use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::str;
use std::sync::Arc;
use std::{fmt, process};
use url::Url;

use fingerprint::{WebFingerPrintLib, WebFingerPrintRequest};
use request::{get_title, index_fetch};
use serde::{de, Deserialize, Deserializer, Serialize};
use ward::check;

use crate::fingerprint::WebFingerPrint;

pub mod fingerprint;
mod request;
mod ward;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhatWebResult {
    pub url: String,
    #[serde(deserialize_with = "string_to_hashset")]
    pub name: HashSet<String>,
    pub priority: u32,
    pub length: usize,
    pub title: String,
    pub status_code: u16,
    #[serde(default)]
    pub is_web: bool,
    #[serde(default)]
    pub plugins: HashSet<String>,
    #[serde(skip)]
    pub template_result: Vec<TemplateResult>,
}

impl WhatWebResult {
    pub fn new(url: String) -> Self {
        Self {
            url,
            name: HashSet::new(),
            priority: 0,
            length: 0,
            status_code: 0,
            title: String::new(),
            plugins: HashSet::new(),
            template_result: vec![],
            is_web: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestOption {
    timeout: u64,
    pub proxy: Option<Url>,
}

impl RequestOption {
    pub fn new(timeout: &u64, proxy: &str) -> Self {
        if !proxy.is_empty() {
            match Url::parse(proxy) {
                Ok(u) => {
                    let proxy_url = Some(u);
                    Self {
                        timeout: *timeout,
                        proxy: proxy_url,
                    }
                }
                Err(err) => {
                    println!("Invalid Proxy Uri {}", err);
                    process::exit(0);
                }
            }
        } else {
            Self {
                timeout: *timeout,
                proxy: None,
            }
        }
    }
}

#[derive(Clone)]
pub struct WhatWeb {
    fingerprint: Arc<WebFingerPrintLib>,
    config: RequestOption,
}

impl WhatWeb {
    pub fn new(config: RequestOption, web_fingerprint: Vec<WebFingerPrint>) -> Self {
        let fingerprint: Arc<WebFingerPrintLib> = Arc::new(WebFingerPrintLib::new(web_fingerprint));
        Self {
            fingerprint,
            config,
        }
    }
    pub async fn scan(&self, url: String, debug: bool) -> WhatWebResult {
        let mut name: HashSet<String> = HashSet::new();
        let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
        let default_request = WebFingerPrintRequest {
            path: String::from("/"),
            request_method: String::from("get"),
            request_headers: Default::default(),
            request_data: String::new(),
        };
        if let Ok(raw_data_list) =
            index_fetch(&url, &default_request, true, false, self.config.clone()).await
        {
            if raw_data_list.is_empty() {
                what_web_result.is_web = false;
            }
            //首页请求允许跳转
            for raw_data in raw_data_list {
                let web_name_set =
                    check(&raw_data, &self.fingerprint.to_owned(), false, debug).await;
                for (k, v) in web_name_set {
                    name.insert(k);
                    what_web_result.priority = v;
                }
                if url.starts_with("http://") || url.starts_with("https://") {
                    what_web_result.url = url.clone();
                } else {
                    what_web_result.url = String::from(raw_data.url.clone());
                }
                if raw_data.next_url.is_none() {
                    what_web_result.title = get_title(&raw_data);
                    what_web_result.priority += 1;
                }
                what_web_result.length = raw_data.text.len();
                what_web_result.status_code = raw_data.status_code.as_u16();
                if raw_data.status_code.is_success() {
                    what_web_result.priority += 1;
                }
            }
        };
        // 在首页请求时不是Web也没必要跑特殊请求了
        if !what_web_result.is_web {
            return what_web_result;
        }
        for special_wfp in self.fingerprint.to_owned().special.iter() {
            if let Ok(raw_data_list) =
                index_fetch(&url, &special_wfp.request, false, true, self.config.clone()).await
            {
                for raw_data in raw_data_list {
                    let web_name_set =
                        check(&raw_data, &self.fingerprint.to_owned(), true, debug).await;
                    for (k, v) in web_name_set {
                        name.insert(k);
                        what_web_result.priority = v;
                    }
                }
            }
        }
        if name.len() > 10 {
            let count = name.len();
            name.clear();
            name.insert(format!("Honeypot 蜜罐{}", count));
        }
        what_web_result.name = name.clone();
        what_web_result
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateResult {
    #[serde(rename = "template-id")]
    pub template_id: String,
    #[serde(rename = "matched-at")]
    pub matched_at: String,
    #[serde(default)]
    pub meta: HashMap<String, String>,
}

fn string_to_hashset<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringToHashSet(PhantomData<HashSet<String>>);
    impl<'de> de::Visitor<'de> for StringToHashSet {
        type Value = HashSet<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let name: Vec<String> = value.split_terminator('\n').map(String::from).collect();
            Ok(HashSet::from_iter(name))
        }
        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }
    deserializer.deserialize_any(StringToHashSet(PhantomData))
}
