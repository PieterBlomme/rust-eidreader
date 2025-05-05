#[macro_use]
extern crate rocket;
extern crate os_type;

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service_dispatcher,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::ServiceControlHandlerFn,
};

use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::Session;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::response::content;
use rocket::response::status::NotFound;
use rocket::{Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::str;

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    address: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Person {
    national_number: String,
    card_number: String,
    surname: String,
    firstnames: String,
    date_of_birth: String,
    gender: String,
    address_street_and_number: String,
    address_zip: String,
    address_municipality: String,
    photo: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct InputToSign {
    data: String,
}

fn get_pkcs11() -> Pkcs11 {
    let pkcs11 = match os_type::current_platform().os_type {
        os_type::OSType::Ubuntu => Pkcs11::new(
            env::var("PKCS11_SOFTHSM2_MODULE")
                .unwrap_or_else(|_| r"/usr/lib/x86_64-linux-gnu/libbeidpkcs11.so.0".to_string()),
        )
        .unwrap(),
        os_type::OSType::OSX => {
            Pkcs11::new(env::var("PKCS11_SOFTHSM2_MODULE").unwrap_or_else(|_| {
                r"/Library/Belgium Identity Card/Pkcs11/libbeidpkcs11.dylib".to_string()
            }))
            .unwrap()
        }
        _ => Pkcs11::new(
            env::var("PKCS11_SOFTHSM2_MODULE")
                .unwrap_or_else(|_| r"C:\\Windows\System32\beidpkcs11.dll".to_string()),
        )
        .unwrap(),
    };

    // initialize the library
    if !pkcs11.is_initialized() {
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
    }
    pkcs11
}

fn get_session() -> Result<Session, NotFound<String>> {
    let pkcs11 = get_pkcs11();
    // find a slot, get the first one
    let mut slots = pkcs11.get_slots_with_token().unwrap();

    if slots.is_empty() {
        return Err(NotFound(String::from("Geen eID ingevoerd.")));
    };
    let slot = slots.remove(0);

    match pkcs11.open_ro_session(slot) {
        Ok(session) => return Ok(session),
        Err(_session) => {
            return Err(NotFound(String::from(
                "Ongeldige eID of eID niet correct ingevoerd.",
            )))
        }
    };
}

fn eid() -> Result<content::RawJson<String>, NotFound<String>> {
    let attrs_to_fetch = [
        "address_municipality",
        "address_street_and_number",
        "address_zip",
        "gender",
        "date_of_birth",
        "firstnames",
        "surname",
        "national_number",
        "card_number",
        "PHOTO_FILE",
    ];

    let session = match get_session() {
        Ok(session) => session,
        Err(_session) => {
            return Err(NotFound(String::from(
                "Ongeldige eID of eID niet correct ingevoerd.",
            )))
        }
    };

    // pub key template
    let pub_key_template = vec![Attribute::Class(ObjectClass::DATA)];

    let pub_attribs = vec![AttributeType::Label, AttributeType::Value];

    let obj_handles = session.find_objects(&pub_key_template).unwrap();

    let mut person_hash = HashMap::new();

    for obj_handle in obj_handles {
        let attributes = session
            .get_attributes(obj_handle, &pub_attribs.clone())
            .unwrap();
        let mut label = String::new();
        let mut content: Vec<u8> = Vec::new();
        for attr in attributes {
            if let Attribute::Label(value) = attr {
                label = match str::from_utf8(&value) {
                    Ok(v) => v.to_string(),
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
            } else if let Attribute::Value(value) = attr {
                content = value
            }
        }
        if attrs_to_fetch.iter().any(|e| label.contains(e)) {
            if label.contains("PHOTO_FILE") {
                person_hash.insert(label, general_purpose::STANDARD.encode(content));
            } else {
                match str::from_utf8(&content) {
                    Ok(v) => person_hash.insert(label, v.to_string()),
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
            }
        }
    }

    let person = Person {
        national_number: person_hash
            .entry(String::from("national_number"))
            .or_default()
            .to_string(),
        card_number: person_hash
            .entry(String::from("card_number"))
            .or_default()
            .to_string(),
        surname: person_hash
            .entry(String::from("surname"))
            .or_default()
            .to_string(),
        firstnames: person_hash
            .entry(String::from("firstnames"))
            .or_default()
            .to_string(),
        gender: person_hash
            .entry(String::from("gender"))
            .or_default()
            .to_string(),
        date_of_birth: person_hash
            .entry(String::from("date_of_birth"))
            .or_default()
            .to_string(),
        address_street_and_number: person_hash
            .entry(String::from("address_street_and_number"))
            .or_default()
            .to_string(),
        address_municipality: person_hash
            .entry(String::from("address_municipality"))
            .or_default()
            .to_string(),
        address_zip: person_hash
            .entry(String::from("address_zip"))
            .or_default()
            .to_string(),
        photo: person_hash
            .entry(String::from("PHOTO_FILE"))
            .or_default()
            .to_string(),
    };
    Ok(content::RawJson(serde_json::to_string(&person).unwrap()))
}

#[get("/eid")]
fn get_eid() -> Result<content::RawJson<String>, NotFound<String>> {
    eid()
}

#[get("/healthz")]
fn get_healthz() -> content::RawJson<&'static str> {
    content::RawJson("{\"online\":true}")
}

#[cfg(windows)]
fn run_as_background_process() {
    use std::ffi::OsString;
    
    define_windows_service!(ffi_service_main, service_main);
    
    fn service_main(_arguments: Vec<OsString>) {
        let event_handler = move |control_event| -> ServiceControlHandlerFn {
            match control_event {
                ServiceControl::Stop => {
                    // Cleanup and shutdown logic here
                    ServiceControlHandlerFn::NoError
                }
                _ => ServiceControlHandlerFn::NoError,
            }
        };
        
        let status_handle = service_control_handler::register("eIDReader", event_handler)
            .unwrap_or_else(|e| panic!("Failed to register service control handler: {}", e));
        
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: std::time::Duration::default(),
                process_id: None,
            })
            .unwrap();

        // Launch your Rocket server here
        let _ = rocket();
    }

    service_dispatcher::start("eIDReader", ffi_service_main)
        .unwrap_or_else(|e| panic!("Failed to start service: {}", e));
}

#[launch]
fn rocket() -> _ {
    let args = Args::parse();
    
    let figment = rocket::Config::figment()
        .merge(("port", 8099))
        .merge(("address", args.address))
        .merge(("log_level", "debug"));

    rocket::custom(figment)
        .mount("/", routes![get_eid, get_healthz])
        .attach(CORS)
}
