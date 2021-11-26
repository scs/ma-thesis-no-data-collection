pub use route_recognizer::{Router, Params};
use itp_sgx_io as io;
use sgx_tstd as std;
use crate::mixnet::proxy; 
const STATUS_LINE_OK: &str = "HTTP/1.1 200 OK";
const STATUS_LINE_NOT_FOUND: &str = "HTTP/1.1 404 NOT FOUND";

use crate::mixnet::tls_server::Request as ParsedRequest;
//use codec::{alloc::string::String};
use std::{
	string::{
        ToString, 
        String,
    },
    //vec::Vec,
    io::{Result as IOResult}
};

#[derive(Debug)]
pub struct RouterRequest<'a> {
    pub map: &'a Params,
    pub data: ParsedRequest<'a>,
}

pub fn load_all_routes() -> Router<String> {
    let mut router = Router::new();
    router.add("/", "index".to_string());
    router.add("/proxy/:service/", "proxy_wo_route".to_string());
    router.add("/proxy/:service/*route", "proxy".to_string());
    //router.add("/proxy/:service", "proxy".to_string());
    //router.add("/proxy/:service/*route", "proxy".to_string());
    /*
    router.add("/tom", "Tom".to_string());
    router.add("/wycats", "Yehuda".to_string());
    */
    router
}

pub fn handle_routes(path: &str, parsed_req: ParsedRequest)->IOResult<String>{
    let router = load_all_routes();
    match router.recognize(path) {
        Ok(route_match) => {
            //println!("DEBUG: {:?}", route_match);
            let req = RouterRequest {
                map: route_match.params(),
                data: parsed_req,
            };

            match route_match.handler().as_str() {
                "index" => index(),
                "proxy" => proxy(req, true),
                "proxy_wo_route" => proxy(req, false),
                _ => not_found(),
            }
        },
        Err(e) => {
            println!("Error: {}", e);
            not_found()
        }
    }

}  

pub fn index()->IOResult<String>{
    let contents = get_file_contents("index").unwrap();
    prepare_response(STATUS_LINE_OK, contents)
}

pub fn proxy(request: RouterRequest, has_route: bool)->IOResult<String>{
    let contents = proxy::forward_and_return_request(&request, has_route).unwrap();
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