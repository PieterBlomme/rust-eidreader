Rust program that runs a small webserver for reading Belgian eID non-protected information.  
The program will run a small webserver on http://localhost:8099/eid, exposing a json with the following fields:
    - national_number
    - surname
    - firstnames
    - date_of_birth
    - gender
    - address_street_and_number
    - address_zip
    - address_municipality
    - photo (base64 encoded)

This endpoint can be used by a Javascript application to integrate eID reading in a web app.