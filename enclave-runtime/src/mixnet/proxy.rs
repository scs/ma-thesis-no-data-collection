//use itp_sgx_io as io;
use sgx_tstd as std;
//use crate::mixnet::router;
use crate::mixnet::tls_server::Request;
use http_req::{request::{RequestBuilder, Method}, tls, uri::Uri, response::{Response, Headers}};
//use http_req::response::Headers;
use std::net::TcpStream;
use std::{
	string::{
        ToString, 
        String,
    },
    vec::Vec,
    io::{Result as IOResult, Error, ErrorKind, BufReader, prelude::*,},
    borrow::ToOwned,
    path::Path,
    fs::File,

};
//use std::io::prelude::*;
use regex::Regex;
use crate::mixnet::{HTTPS_BASE_URL, BASE_LOCALHOST_URL};
use std::collections::HashMap;
use std::sync::SgxMutex as Mutex;
use sgx_rand as rand;
use rand::{Rng};

#[derive(Clone,Debug)]
pub struct Domain{
    pub uri: Uri, 
    pub login_check_uri: Uri,
    pub login_check_answer: String,
    pub cookies: Vec<String>,
    pub regex_uri: Regex,
    pub regex_uri_extended: Regex, 
    pub regex_subdomains: Option<Regex>, 
}
 

/*
------------------------
Helper Funcs and Var
------------------------
*/
lazy_static! {
    static ref PROXY_URLS: Mutex<HashMap<String, Domain>> = {
        let mut m = HashMap::new();
        let services = lines_from_file("ma-thesis/services.txt", 1);
        for service in services {
            let mut split = service.split(" || ");
            //Attention: this must be adapted for each new column
            let line =(split.next().unwrap(), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""));
            let https_url = format!("https://{}", line.0);
            let base_regex = Regex::new(line.0).unwrap();
            let exended_base_regex = Regex::new(format!("(?:(?:ht|f)tp(?:s?)://|~/|/)?{}", line.0).as_str()).unwrap();
            let subdomains_regex = if line.3.eq("") {None} else { Some(Regex::new(format!("((?:(?:ht|f)tp(?:s?)://|~/|/)?{})", line.3).as_str()).unwrap())};
            m.insert(String::from(line.0), Domain{
                uri: https_url.parse().unwrap(),
                login_check_uri: line.1.parse().unwrap_or(https_url.parse().unwrap()),
                login_check_answer: String::from(line.2),
                cookies: Vec::new(),
                regex_uri: base_regex,
                regex_uri_extended: exended_base_regex,
                regex_subdomains: subdomains_regex,
            });
        };
        Mutex::new(m)
    };
    static ref HEAD_REGEX: Regex = Regex::new("(?i)<head?[^>]>").unwrap();
    
    static ref REPLACE_HEAD_WITH: String = {
        let head_base = "<head> \n <base href=\"";
        let base_char = "/\"/>  \n <meta charset=\"utf-8\">";
        let style = "<style> .proxy_target_logout {margin-top:3px; padding:10px; width: 100%; border:1px solid #CCC; max-width: 100%; background-color: red; color: white; position:fixed; bottom: 0px; left:0px; z-index: 2147483647;} </style>";
        let script = "<script type=\"text/javascript\"> 
        window.onload = function () {
            let btn = document.createElement(\"button\");
            btn.className += \"proxy_target_logout\";
            btn.innerHTML = \"Cancel this session\";
            btn.addEventListener(\"click\", function () {
                document.cookie = \"proxy-target=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;\";
                window.location.href = '/';
            });
            document.body.prepend(btn);
        }
        </script>";
        format!("{}{}{}\n{}\n{}\n", head_base, HTTPS_BASE_URL, base_char, style, script)
    };
}

pub fn get_target_domain<'a>(req: &'a  Request)-> Domain {
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    target_domain.clone()
}

pub fn parse_method(input: &str) -> IOResult<Method>{
    match input {
        "GET"  => Ok(Method::GET),
        "HEAD"  => Ok(Method::HEAD),
        "POST"  => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "DELETE" => Ok(Method::DELETE),
        "OPTIONS" => Ok(Method::OPTIONS),
        "PATCH" => Ok(Method::PATCH),
        _ => Err(Error::new(ErrorKind::Other, "Method could not be parsed!"))
    }
}

fn lines_from_file(filename: impl AsRef<Path>, offset: usize) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .skip(offset)
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn hashmap_to_string(hashmap: & HashMap<String,String>) -> String {
   hashmap.iter().map(|(k,v)| format!("{}={}", k,v)).collect::<Vec<String>>().join("&")
}
lazy_static! {
    static ref HEADERS: Vec<String> = {vec![
        String::from("Accept"),
        String::from("Accept-Charset"),
        //String::from("Accept-Encoding"),
        String::from("Connection"),
        String::from("Access-Control-Allow-Origin"),
        //String::from("Content-Length") // Will be calculated later
    ]};
}

fn create_headers_to_forward<'a>(req: &'a  Request) -> Vec::<(String, String)>{
    let mut forwarded_headers: Vec::<(String, String)> = Vec::new();
    for header in HEADERS.iter() {
        match req.headers.get(header) {
            Some(val) => {forwarded_headers.push((header.to_string(), val.to_string()));},
            _ => {}
        }
    };
    let cookie = get_random_cookie(&req);
    if !cookie.eq(&String::from("")){
        forwarded_headers.push((String::from("Cookie"),cookie));
    }
    forwarded_headers
}

/*
------------------------
Proxy Part 
------------------------
*/

pub fn forward_request_and_return_response(req: & Request) -> IOResult<Vec<u8>> {
    let target_uri = parse_target_uri(&req);
    let headers = create_headers_to_forward(&req);
    //let (res, body) = send_https_request(https_url, &req).unwrap();
    let body = if req.auth {
        String::new()
    } else {
        hashmap_to_string(&req.body)
    };
    let (res, body) = send_https_request_all_paraemeter(
        &target_uri,
        443, 
        parse_method(req.method.unwrap()).unwrap(),
        &body,
        //&vec![("Connection".to_string(), "Keep-Alive".to_string()), ("Cookie".to_string(), get_random_cookie(&req))]
        &headers
    ).unwrap();

    let (status_line, headers, body) = handle_response(res, &body, req).unwrap();
    prepare_response(status_line, headers, body)
}

pub fn parse_target_uri(req: & Request) -> Uri {
    let regex = Regex::new("proxy_sub=(.*)").unwrap();
    let path = req.path.unwrap();
    let https_url = match regex.captures(path) {
        Some(res) => {res.get(1).unwrap().as_str().to_string()},
        _ => {create_https_url_from_target_and_route(req)}
    };
    https_url.parse().unwrap()
}

pub fn create_https_url_from_target_and_route(req: & Request) -> String {
    let target = req.target.as_ref().unwrap(); //Both unwraps are Safe, otherwise we wouldn't be here
    let path = req.path.as_ref().unwrap();
    let mut https_url = String::from("https://");
    https_url += &target;
    https_url += path;
    https_url
}


pub fn handle_response(res: Response, body_original: & Vec<u8>, req: & Request)->IOResult<(String, Headers, Vec<u8>)>{
    let mut headers = Headers::new();
    let status_code = res.status_code();
    let version = res.version();
    let reason = res.reason();
    let default_content_type = String::from("text/plain");
    let content_type = res.headers().get("Content-Type").unwrap_or(&default_content_type);
    headers.insert("Content-Type", content_type);
    //println!("Response: {:?}", res);
    let body = if status_code.is_success() { // StatusCode 200 - 299
        if content_type.contains("text") || content_type.contains("application") {
            match String::from_utf8(body_original.to_vec()) {
                Ok(body_string) => {
                    let mut clean = clean_urls(&body_string, &req, &BASE_LOCALHOST_URL.to_string()).unwrap(); // URL changement to LOCALHOST
                    
                    clean = if content_type.contains("html"){
                        add_base_tag(&clean).unwrap()
                    } else {
                        clean
                    };
                    clean.as_bytes().to_vec()
                },
                Err(e) => {
                    println!("Content Type: {} - No Conversion possible: {}", content_type, e);
                    body_original.to_vec()
                }
            }
            //println!("{:?}", String::from_utf8(body_original.to_vec()));
        } else {
            body_original.to_vec()
        }
    } else if status_code.is_redirect() { // 300 - 399 Redirect // Intercept it and reset Cookie
        let location = res.headers().get("Location").unwrap();
        //println!("Retrying at {:?}", location);
        println!("ERROR: 300-399 Status: {} Requested Path: {} New Location: {}", status_code, req.path.unwrap(), location);
        //headers.insert("Location", HTTPS_BASE_URL);
        /*
        let (res_redirect, body_redirect) = send_https_request_all_paraemeter(&(location.to_string().parse().unwrap()), 443, parse_method(req.method.unwrap()).unwrap(),  &String::new(), &Vec::new()).unwrap();
        let (_status_line, _header, body) = handle_response(res_redirect, &body_redirect, req).unwrap();
        body*/
        String::from("Redirect").as_bytes().to_vec()
    } else if status_code.is_client_err() { // 400-499 Client Error
        println!("ERROR: Status: {} Requested Path: {}", status_code, req.path.unwrap());
        //println!("DEBUG INFOS: {:?}", req);

        String::from("400").as_bytes().to_vec()
    } else { // 500-599 Server Error
        println!("ERROR: Status: {} Requested Path: {}", status_code, req.path.unwrap());
        String::from("500").as_bytes().to_vec()
    };
    let status_line = format!("{} {} {}", version, status_code, reason);
    Ok((status_line, headers, body))
    //prepare_response(status_line, headers, body)
    //Ok(body)
}

/*
------------------------
HTTP Requests
------------------------
*/

pub fn send_https_request_all_paraemeter(addr: &Uri, port: u16, method: Method, body: &String, headers: &Vec<(String, String)>) -> IOResult<(Response, Vec<u8>)>{
    //Construct a domain:ip string for tcp connection
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));
    //Connect to remote host
    let stream = TcpStream::connect(conn_addr).unwrap();
    //Open secure connection over TlsStream, because of `addr` (https)
    let mut stream = tls::Config::default()
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap();
    //Container for response's body
    let mut writer = Vec::new();
    let mut request = RequestBuilder::new(&addr)
        .method(method).to_owned();
        
        
    // Fill in Headers
    for header in headers {
        request.header(&header.0, &header.1);
    };
    //println!("{:?}", request);
    let response = request.header("Content-Length", &body.as_bytes().len())
        .body(body.as_bytes())
        .send(&mut stream, &mut writer)
        .unwrap();
    Ok((response, writer)) // return response & body
}

/*
------------------------
Cookie Magic
------------------------
*/

pub fn get_random_cookie(req: & Request) -> String {
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    //target_domain.cookies.push(String::from("hello"));
    let cookies = &target_domain.cookies;
    if cookies.len()>0 {
        let index = rand::thread_rng().gen_range(0, cookies.len());
        String::from(&cookies[index])
    } else {String::from("")}

    //String::from("s: &str")
    //target_domain.cookies.choose(& mut thread_rng())
}

pub fn cookie_is_valid(req: & Request, cookie: String) -> bool {
    if try_out_cookie_at_target(req, &cookie) {
        println!("[+] Cookie Validated, it will now be inserted!");
        insert_cookie_to_target(&req, cookie);
        true
    } else {
        println!("[xxx] Cookie Validation failed");
        false
    }
}

pub fn try_out_cookie_at_target(req: & Request, cookie: &String) -> bool {
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    let (response, _body) = send_https_request_all_paraemeter(&target_domain.login_check_uri, 443, Method::GET, &String::new(), &vec![(String::from("Connection"), String::from("Close")), (String::from("Cookie"), cookie.to_string())]).unwrap();
    let status_code = response.status_code();
    match target_domain.login_check_answer.as_str() {
        "302" if status_code.is_redirect() => {
            false
        },
        _ => true
    }
}


pub fn insert_cookie_to_target(req: & Request, cookie: String){
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    //target_domain.cookies.push(String::from("hello"));
    //println!("{} will be inserted to {:?}", cookie, target_domain);
    target_domain.cookies.push(cookie);
    //println!("Vector now {:?}",  target_domain);
}


/*
------------------------
Mutating Response Part 
------------------------
*/
pub fn clean_urls(content: & String, req: & Request, replace_with: &String) -> IOResult<String> {
    let target_domain = get_target_domain(req);
    let modified_content = regex_replace_all_wrapper(&target_domain.regex_uri, &content, &replace_with);
    let extended_modified_content = regex_replace_all_wrapper(&target_domain.regex_uri_extended, &modified_content, &HTTPS_BASE_URL.to_string());
    let sub_domain_cleand = if let Some(sub_regex) = target_domain.regex_subdomains {
        regex_replace_all_wrapper(&sub_regex, &extended_modified_content, &format!("{}/?proxy_sub=$0", HTTPS_BASE_URL))
    } else {extended_modified_content};
    
    Ok(sub_domain_cleand)
}

pub fn regex_replace_all_wrapper(regex: &Regex, text: &String, replace_with: &String)-> String {
    String::from(regex.replace_all(&text, replace_with.as_str()))
}

pub fn add_base_tag(content: & String) -> IOResult<String> {
    let content = HEAD_REGEX.replace_all(&content, REPLACE_HEAD_WITH.as_str());
    Ok(String::from(content))
}

/*
------------------------
HTTP Response 
------------------------
*/
pub fn prepare_response(status_line: String, headers: Headers, mut contents: Vec<u8>) ->  IOResult<Vec<u8>>{
    //println!("{:?}", status_line);
    //let status_line = format!("{} {} {}", status.version(), status.code.as_u16(), status.reason());
    //let status_line = "HTTP/1.1 200 OK";
    let mut addional_headers = "".to_owned();
    for (key, value) in headers.iter() {
        addional_headers += format!("{}:{} \r\n", key, value).as_str();
    };
    let response_string = format!(
        "{}\r\n{}Content-Length: {}\r\n\r\n",
        status_line,
        addional_headers,
        contents.len(),
    );
    //println!("Sending response: {:?}", response_string);
    //response_string = format!("{}\r\nLocation: https://localhost:8443 \r\n\r\n", response_string);
    let mut response = response_string.as_bytes().to_vec();
    response.append(&mut contents);
    Ok(response)
}