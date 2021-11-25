pub use route_recognizer::{Router, Params};
use itp_sgx_io as io;
use sgx_tstd as std;

const STATUS_LINE_OK: &str = "HTTP/1.1 200 OK";
const STATUS_LINE_NOT_FOUND: &str = "HTTP/1.1 404 NOT FOUND";

//use codec::{alloc::string::String};
use std::{
	string::{
        /*ToString,*/ 
        String,
    },
    //vec::Vec,
    io::{Result as IOResult}
}; 
pub fn load_all_routes() -> Router<IOResult<String>> {
    let mut router = Router::new();
    router.add("/", index());
    /*
    router.add("/tom", "Tom".to_string());
    router.add("/wycats", "Yehuda".to_string());
    */
    router
}

pub fn index()->IOResult<String>{
    let contents = get_file_contents("index").unwrap();
    prepare_response(STATUS_LINE_OK, contents)
}

pub fn not_found()->IOResult<String>{
    let contents = get_file_contents("404").unwrap();
    prepare_response(STATUS_LINE_NOT_FOUND, contents)
}

pub fn get_file_contents(filename: &str) -> IOResult<String> {
    let html_base_dir = "html";
    let path = format!("{}/{}.html", html_base_dir, filename);
    let contents = io::read_to_string(&path).unwrap();
    //Vec::from(contents.as_bytes())
    Ok(contents)
}

pub fn prepare_response(status_line: &str, contents: String) -> IOResult<String> {
    let response = format!(
        "{}\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        contents.len(),
        contents
    );
    Ok(response)
}