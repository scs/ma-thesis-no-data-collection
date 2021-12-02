pub use route_recognizer::{Router, Params};
use itp_sgx_io as io;
use sgx_tstd as std;
use crate::mixnet::proxy; 
//use crate::mixnet::HTTPS_BASE_URL;
//use regex::Regex;

const STATUS_LINE_OK: &str = "HTTP/1.1 200 OK";
//const STATUS_LINE_REDIRECT: &str = "HTTP/1.1 301 OK";
const STATUS_LINE_NOT_FOUND: &str = "HTTP/1.1 404 NOT FOUND";
//const STATUS_LINE_SERVER_ERROR: &str = "HTTP/1.1 500 OK";


//use http_req::uri::Uri;
use crate::mixnet::tls_server::Request as ParsedRequest;
//use codec::{alloc::string::String};
use std::{
	string::{
        ToString, 
        String,
    },
    vec::Vec,
    io::{Result as IOResult}
};

#[derive(Debug)]
pub struct RouterRequest<'a> {
    pub map: &'a Params,
}

pub fn load_all_routes() -> Router<String> {
    let mut router = Router::new();
    router.add("/", "index".to_string());
    router
}

pub fn handle_routes(path: &str, parsed_req: ParsedRequest)->IOResult<Vec<u8>>{
    //println!("path: {:?}", path);
    let router = load_all_routes();
    match &parsed_req.target {
        None => {
            match router.recognize(path) {
                Ok(route_match) => {       
                    match route_match.handler().as_str() {
                        "index" => index(),
                        //"proxy" => proxy(req, true),
                        //"proxy_wo_route" => proxy(req, false),
                        _ => not_found(),
                    }
                },
                Err(e) => {
                    /*
                    if parsed_req.headers.contains_key("Referer") {
                        let referer = parsed_req.headers.remove("Referer").unwrap_or(HTTPS_BASE_URL.to_string()); 
                        println!("Coming from: {}", referer);
                        let addr: Uri = referer.parse().unwrap();
                        let mut base_path = addr.path().unwrap().to_string();
                        base_path += path;
                        //handle_routes(base_path.as_str(), parsed_req)
                        not_found()
                    } else {*/
                        println!("Error, No Cookie was set and : {}", e);
                        not_found()
                }
            }
        },
        Some(_target) => {
            if parsed_req.auth {
                println!("Need to check authentication here and change method for proxy");
                proxy(parsed_req)
            } else {
                proxy(parsed_req)

            }
        }
    }


}  

pub fn index()->IOResult<Vec<u8>>{
    let contents = get_file_contents("index").unwrap();
    prepare_response(STATUS_LINE_OK, contents)
}

pub fn proxy(request: ParsedRequest)->IOResult<Vec<u8>>{
    proxy::forward_request_and_return_response(&request)
}


pub fn not_found()->IOResult<Vec<u8>>{
    let contents = get_file_contents("404").unwrap();
    prepare_response(STATUS_LINE_NOT_FOUND, contents)
}

pub fn get_file_contents(filename: &str) -> IOResult<Vec<u8>> {
    let html_base_dir = "html";
    let path = format!("{}/{}.html", html_base_dir, filename);
    let contents = io::read_to_string(&path).unwrap();
    //Vec::from(contents.as_bytes())
    Ok(contents.as_bytes().to_vec())
}

pub fn prepare_response(status_line: &str, mut contents: Vec<u8>) -> IOResult<Vec<u8>> {
    let response_string = format!(
        "{}\r\nContent-Length: {}\r\n\r\n",
        status_line,
        contents.len(),
    );
    let mut response = response_string.as_bytes().to_vec();
    response.append(&mut contents);
    Ok(response)
}