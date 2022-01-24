pub use route_recognizer::{Router, Params};
use itp_sgx_io as io;
use sgx_tstd as std;
use crate::mixnet::proxy; 
//use proxy::PROXY_URLS;
//use crate::mixnet::HTTPS_BASE_URL;
//use regex::Regex;

const STATUS_LINE_OK: &str = "HTTP/1.1 200 OK";
//const STATUS_LINE_REDIRECT: &str = "HTTP/1.1 301 OK";
const STATUS_LINE_NOT_FOUND: &str = "HTTP/1.1 404 NOT FOUND";
const STATUS_LINE_UNAUTHORIZED: &str = "HTTP/1.1 401 UNAUTHORIZED";
const STATUS_LINE_INTERNAL_SERVER_ERROR: &str = "HTTP/1.1 500 INTERNAL SERVER ERROR";
//use crate::mixnet::{HTTPS_BASE_URL};
use std::time::{Duration};
use time::OffsetDateTime;
//const STATUS_LINE_SERVER_ERROR: &str = "HTTP/1.1 500 OK";
use http_req::response::{Headers};

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
    router.add("/favicon.ico", "favicon".to_string());
    router.add("/favicon/:name", "favicon_special".to_string());
    router.add("/unauthorized", "unauthorized".to_string());
    router
}

pub fn handle_routes(path: &str, mut parsed_req: ParsedRequest)->IOResult<Vec<u8>>{
    //println!("path: {:?}", path);
    
    let router = load_all_routes();
    match &parsed_req.target {
        None => {
            match router.recognize(path) {
                Ok(route_match) => {       
                    //println!("route_match: {:?}", route_match.params().find("name"));
                    match route_match.handler().as_str() {
                        "index" => index(),
                        "favicon" => get_favicon("favicon.ico"),
                        "favicon_special" => get_favicon(route_match.params().find("name").unwrap()),
                        //"proxy" => proxy(req, true),
                        //"proxy_wo_route" => proxy(req, false),
                        "unauthorized" => not_authorized(),
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
                        
                        /*
                        Not needed anymore
                        if parsed_req.path.unwrap().contains("zahs.tv") {
                            println!("forwareded zattoo");
                            parsed_req.target = Some(String::from("zattoo.com"));
                            proxy(parsed_req) 
                        } else */
                        if parsed_req.path.unwrap().contains("prod.tda.link") {
                            parsed_req.target = Some(String::from("www.tagesanzeiger.ch"));
                            proxy(parsed_req)
                        }
                        else if parsed_req.method.unwrap().contains("OPTIONS") {
                            if parsed_req.path.unwrap().contains("disco")||parsed_req.path.unwrap().contains("prod.tda.link"){
                                parsed_req.target = Some(String::from("www.tagesanzeiger.ch"));
                                proxy(parsed_req)
                            } else {
                                println!("Error-Options request: {}", e);

                                not_found()
                            }
                        } else {
                            println!("Error, No Cookie was set and : {}", e);

                            //println!("Debug: sw js {:?}", parsed_req);
                            not_found()
                        }

                }
            }
        },
        Some(_target) => {
            let auth_for_target = proxy::check_auth_for_request(&parsed_req);
            //println!("Auth: {}", auth_for_target);
            if parsed_req.inital_auth_req { // request from main page containing a cookie!
                // new cookie is coming in, get it
                let cookie = parsed_req.body.remove("cookie").unwrap();
                //println!("Validating Cookie");
                if proxy::cookie_is_valid(&parsed_req, cookie.to_string()) {
                    proxy(parsed_req)
                } else if auth_for_target {
                    proxy(parsed_req)
                } else { not_authorized() }
            } else if auth_for_target { // proxy traffic which is authenticated
                proxy(parsed_req)
            } else { // not authorized traffic
                //not_authorized() 
                cookie_validation_failed()
                //proxy(parsed_req) // only for testing reason, the line above should be used
            }
        }
    }


}

pub fn index()->IOResult<Vec<u8>>{
    let contents = get_file_contents("index").unwrap();
    prepare_response(STATUS_LINE_OK, Headers::new(), contents)
}

pub fn proxy(request: ParsedRequest)->IOResult<Vec<u8>>{
    proxy::forward_request_and_return_response(&request)
}

pub fn not_authorized()->IOResult<Vec<u8>>{
    let contents = get_file_contents("not_authorized").unwrap();
    let mut headers = Headers::new();
    headers.insert("Set-Cookie", "proxy-target=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;");
    prepare_response(STATUS_LINE_UNAUTHORIZED, headers, contents)
}

pub fn cookie_validation_failed()->IOResult<Vec<u8>>{
    let mut headers = Headers::new();
    headers.insert("Set-Cookie", "proxy-target=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;");
    let dt = OffsetDateTime::now_utc()+Duration::from_secs(3600);
    let inv_session = format!("proxy-invalid-session=true; expires={}; path=/;", dt);
    headers.insert("Set-Cookie", &inv_session);
    headers.insert("Content-type", "text/html");
    let contents = get_file_contents("not_authorized").unwrap();
    prepare_response(STATUS_LINE_UNAUTHORIZED, headers, contents)
}


pub fn not_found()->IOResult<Vec<u8>>{
    let contents = get_file_contents("404").unwrap();
    prepare_response(STATUS_LINE_NOT_FOUND, Headers::new(), contents)
}

pub fn internal_server_error()->IOResult<Vec<u8>>{
    let contents = get_file_contents("500").unwrap();
    prepare_response(STATUS_LINE_INTERNAL_SERVER_ERROR, Headers::new(), contents)
}

pub fn get_file_contents(filename: &str) -> IOResult<Vec<u8>> {
    let html_base_dir = "ma-thesis/html";
    let path = format!("{}/{}.html", html_base_dir, filename);
    let contents = io::read_to_string(&path).unwrap();
    //Vec::from(contents.as_bytes())
    Ok(contents.as_bytes().to_vec())
}

pub fn prepare_response(status_line: &str, headers: Headers, mut contents: Vec<u8>) -> IOResult<Vec<u8>> {
    let mut addional_headers = String::from(""); 
    for (key, value) in headers.iter() {
        addional_headers += format!("{}:{} \r\n", key, value).as_str();
    };
    let response_string = format!(
        "{}\r\n{}Content-Length: {}\r\n\r\n",
        status_line,
        addional_headers,
        contents.len(),
    );
    let mut response = response_string.as_bytes().to_vec();
    response.append(&mut contents);
    Ok(response)
}

pub fn get_favicon(filename: &str)->IOResult<Vec<u8>>{
    let fav_base_dir = "ma-thesis/favicon/";
    let path = format!("{}/{}", fav_base_dir, filename);
    let contents = io::read(&path).unwrap();
    prepare_response(STATUS_LINE_OK, Headers::new(), contents)
}