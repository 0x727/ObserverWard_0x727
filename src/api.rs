#[cfg(not(target_os = "windows"))]
extern crate daemonize;

use crate::error::Error;
use crate::{print_color, Helper, ObserverWard, ObserverWardConfig, OBSERVER_WARD_PATH};
use actix_web::web::Data;
use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
#[cfg(not(target_os = "windows"))]
use daemonize::Daemonize;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use std::collections::{HashMap, HashSet};
#[cfg(not(target_os = "windows"))]
use std::fs::File;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use tokio::sync::RwLock;

fn get_ssl_config() -> Result<SslAcceptorBuilder, Error> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    let key_path = OBSERVER_WARD_PATH.join("key.pem");
    let cert_path = OBSERVER_WARD_PATH.join("cert.pem");
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(cert_path)?;
    Ok(builder)
}

#[derive(Clone, Debug)]
struct TokenAuth {
    token: String,
}

fn validator(token_auth: Data<TokenAuth>, credentials: BearerAuth) -> bool {
    return token_auth.token.is_empty() || token_auth.token == credentials.token();
}

#[post("/v1/observer_ward")]
async fn what_web_api(
    token: web::Data<TokenAuth>,
    auth: BearerAuth,
    config: web::Json<ObserverWardConfig>,
    observer_ward_ins: web::Data<RwLock<ObserverWard>>,
) -> impl Responder {
    if !validator(token, auth) {
        return HttpResponse::Unauthorized().finish();
    }
    let vec_results = observer_ward_ins
        .read()
        .await
        .scan(config.targets.clone())
        .await;
    HttpResponse::Ok().json(vec_results)
}

#[post("/v1/config")]
async fn set_config_api(
    token: web::Data<TokenAuth>,
    auth: BearerAuth,
    mut config: web::Json<ObserverWardConfig>,
    observer_ward_ins: web::Data<RwLock<ObserverWard>>,
) -> impl Responder {
    if !validator(token, auth) {
        return HttpResponse::Unauthorized().finish();
    }
    let mut helper = Helper::new(&config);
    helper.run().await;
    helper.msg = HashMap::new();
    config.targets = HashSet::new();
    observer_ward_ins.write().await.reload(&config);
    let config = observer_ward_ins.read().await.config.clone();
    HttpResponse::Ok().json(config)
}

#[get("/v1/config")]
async fn get_config_api(
    token: web::Data<TokenAuth>,
    auth: BearerAuth,
    observer_ward_ins: web::Data<RwLock<ObserverWard>>,
) -> impl Responder {
    if !validator(token, auth) {
        return HttpResponse::Unauthorized().finish();
    }
    let config = observer_ward_ins.read().await.config.clone();
    HttpResponse::Ok().json(config)
}

#[actix_web::main]
async fn api_server(listening_address: SocketAddr, token: String) {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let observer_ward_ins = web::Data::new(RwLock::new(ObserverWard::default()));
    let token_auth = web::Data::new(TokenAuth {
        token: token.clone(),
    });
    let http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(token_auth.clone())
            .app_data(Config::default())
            .app_data(web::JsonConfig::default().limit(40960))
            .app_data(observer_ward_ins.clone())
            .service(what_web_api)
            .service(get_config_api)
            .service(set_config_api)
    });
    let mut s = format!("http://{}/v1/observer_ward", listening_address);
    if let Ok(ssl_config) = get_ssl_config() {
        let https_server = http_server.bind_openssl(listening_address, ssl_config);
        s = s.replace("http://", "https://");
        if let Ok(server) = https_server {
            print_help(&s, &token);
            server.run().await.unwrap_or_default();
        }
    } else {
        let http_server = http_server.bind(listening_address);
        if let Ok(server) = http_server {
            print_help(&s, &token);
            server.run().await.unwrap_or_default();
        }
    }
}

fn print_help(s: &str, t: &str) {
    println!("API service has been started:{}", s);
    let api_doc = format!(
        r#"curl --request POST \
  --url {} \
  --header 'Authorization: Bearer {}' \
  --header 'Content-Type: application/json' \
  --data '{{"targets":["https://httpbin.org/"]}}'"#,
        s, t
    );
    let result = r#"[{"url":"http://httpbin.org/","name":["swagger"],"priority":5,"length":9593,"title":"httpbin.org","status_code":200,"is_web":true,"plugins":[]}]"#;
    println!("Request:");
    print_color(api_doc, term::color::BRIGHT_GREEN, true);
    println!("Response:");
    print_color(result.to_string(), term::color::GREEN, true);
}

pub fn run_server() {
    let config = ObserverWardConfig::new();
    if config.daemon {
        background();
    }
    if let Ok(address) = std::net::SocketAddr::from_str(&config.api_server) {
        thread::spawn(move || {
            api_server(address, config.token);
        })
        .join()
        .expect("API service startup failed")
    } else {
        println!("Invalid listening address");
    }
}

#[cfg(not(target_os = "windows"))]
fn background() {
    let stdout = File::create("/tmp/observer_ward.out").unwrap();
    let stderr = File::create("/tmp/observer_ward.err").unwrap();

    let daemonize = Daemonize::new()
        .pid_file("/tmp/observer_ward.pid") // Every method except `new` and `start`
        .chown_pid_file(false) // is optional, see `Daemonize` documentation
        .working_directory("/tmp") // for default behaviour.
        .user("nobody")
        .group("daemon") // Group name
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/observer_ward.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/observer_ward.err`.
        .exit_action(|| println!("Executed before master process exits"))
        .privileged_action(|| "Executed before drop privileges");
    match daemonize.start() {
        Ok(_) => println!("Success, daemonized"),
        Err(e) => eprintln!("Error, {}", e),
    }
}

#[cfg(target_os = "windows")]
fn background() {
    print_color(
        "Windows does not support background services".to_string(),
        term::color::GREEN,
        true,
    );
}
