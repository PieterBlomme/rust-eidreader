#[macro_use]
extern crate rocket;

use base64;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::response::content;
use rocket::{Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::str;
use rocket::response::status::NotFound;

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

#[derive(Serialize, Deserialize, Debug)]
struct Person {
    national_number: String,
    surname: String,
    firstnames: String,
    date_of_birth: String,
    gender: String,
    address_street_and_number: String,
    address_zip: String,
    address_municipality: String,
    photo: String,
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
        "PHOTO_FILE",
    ];
    let mut pkcs11 = Pkcs11::new(
        env::var("PKCS11_SOFTHSM2_MODULE")
            .unwrap_or_else(|_| r"C:\\Windows\System32\beidpkcs11.dll".to_string()),
    )
    .unwrap();
    // initialize the library
    if !pkcs11.is_initialized() {
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
    }

    // find a slot, get the first one
    let mut slots = pkcs11.get_slots_with_token().unwrap();

    if slots.is_empty()
    {
        return Err(NotFound(String::from("Geen eID ingevoerd.")))
    };
    let slot = slots.remove(0);
    let session = match pkcs11.open_ro_session(slot){
        Ok(session) => session,
        Err(_session) => return Err(NotFound(String::from("Ongeldige eID of eID niet correct ingevoerd.")))
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
                person_hash.insert(label, base64::encode(content));
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

#[launch]
fn rocket() -> _ {
    let figment = rocket::Config::figment()
    .merge(("port", 8099))
    .merge(("address", "0.0.0.0"))
    .merge(("log_level", "debug"));

    rocket::custom(figment)
        .mount("/", routes![get_eid, get_healthz])
        .attach(CORS)
}
