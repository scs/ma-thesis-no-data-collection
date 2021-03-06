//use itp_sgx_io as io;
use sgx_tstd as std;
//use crate::mixnet::router;
use crate::mixnet::tls_server::Request;
use http_req::{request::{RequestBuilder, Method}, tls, tls::Conn, uri::Uri, response::{Response, Headers, StatusCode}, error::Error as ReqError};
//use http_req::response::Headers;
use std::net::TcpStream;
use std::{
	string::{
        ToString, 
        String,
    },
    vec::Vec,
    io::{Result as IOResult, Error, ErrorKind, BufReader, prelude::*},// BufWriter, Write},
    borrow::ToOwned,
    path::Path,
    fs::{File} //, //OpenOptions}

};
//use std::io::prelude::*;
use regex::Regex;
use crate::mixnet::{HTTPS_BASE_URL, BASE_LOCALHOST_URL, TCS_NUM};
use std::collections::{HashMap, HashSet};
use std::sync::SgxMutex as Mutex;
use sgx_rand as rand;
use rand::{Rng};
//use cookie::Cookie;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use itp_sgx_io as io;
use serde_json::{Value};
use route_recognizer::Router;
//use chrono::prelude::*;
//use std::sync::atomic::{AtomicU8, Ordering*/};
//use urlencoding::decode;
//use core::borrow::{BorrowMut, Borrow};
//use std::sync::Arc;
const HEAD_503: &[u8; 120] = b"HTTP/1.1 503 Service Unavailable \r\n\
                            Date: Sat, 16 Jan 2022 12:44:04 GMT\r\n\
                            Content-Type: text/html\r\n\
                            Content-Length: 100\r\n\r\n";

const _DUR_HALF_SEC: Option<Duration> = Some(Duration::from_millis(500));
const _DUR_ONE_SEC: Option<Duration> = Some(Duration::from_millis(1000));
const _DUR_ONE_AND_HALF_SEC: Option<Duration> = Some(Duration::from_millis(1500));
const _DUR_TWO_SEC: Option<Duration> = Some(Duration::from_millis(2000));
const DUR_FIVE_SEC: Option<Duration> = Some(Duration::from_millis(5000));

#[derive(Clone,Debug)]
pub struct Domain {
//    pub struct Domain <'a> {
    pub name: String,
    pub uri: Uri, 
    pub login_check_uri: Uri,
    pub login_check_answer: String,
    //pub cookies: Vec<Cookie<'a>>,
    pub cookies: Vec<String>,
    pub regex_uri: Regex,
    pub regex_uri_extended: Regex, 
    pub regex_subdomains: Option<Regex>,
    pub regex_subdomains_relative: Option<Regex>,
    pub regex_general_subdomains: Option<Regex>, 
    pub auth_user: HashSet<String>,
    pub cookie_origin: HashMap<String, (String, Vec<Regex>)>,
    pub whitelist: Router<String>
 
}

// Debug counter
//static COUNTER: AtomicU8 = AtomicU8::new(0);
/*
------------------------
Helper Funcs and Var
------------------------
*/
lazy_static! {
    static ref PROXY_TLS_CONN: Vec<Mutex<HashMap<String, Conn<std::net::TcpStream>>>> = {
        let mut vec = Vec::new();
        for i in 0..*TCS_NUM {
            let m = HashMap::new();
            vec.push(Mutex::new(m));
        };
        vec
    };
    static ref PROXY_URLS: Mutex<HashMap<String, Domain>> = {
//        static ref PROXY_URLS: Mutex<HashMap<String, Domain<'static>>> = {
        let mut m = HashMap::new();
        let services = lines_from_file("ma-thesis/services.txt", 1);
        for service in services {
            let mut split = service.split(" || ");
            //Attention: this must be adapted for each new column
            let line =(split.next().unwrap(), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""));
            let https_url = format!("https://{}", line.0);
            let base_regex = Regex::new(line.0).unwrap();
            let exended_base_regex = Regex::new(format!("(?:(?:ht|f)tp(?:s?)://|~/|/|//)?{}", line.0).as_str()).unwrap();
            let subdomains_regex = if line.3.eq("") {None} else { Some(Regex::new(format!("((?:(?:ht|f)tp(?:s?)://|~/)({}))", line.3).as_str()).unwrap())};
            let subdomains_regex_relative = if line.3.eq("") {None} else { Some(Regex::new(format!("(\"|\'|\\()//({})", line.3).as_str()).unwrap())};
            let all_subdomains_regex =  if line.4.eq("") {None} else {Some(Regex::new(format!("((?:(?:ht|f)tp(?:s?)://|~/|/|//)?([^.]+[.])*({}))", line.4).as_str()).unwrap())};

           // println!(" ---------------Router Creation for {}-----------------", line.0.to_string());
            //router creation
            let mut r = Router::new();
            if !line.5.eq("") {
                let whitelist =  line.5.split("|");
                for dom in whitelist {
                    //println!("Allow: {:?}", dom);
                    r.add(dom, "Proxy".to_string());
                }


            }
            if !line.6.eq("") {
                let blacklist =  line.6.split("|");
                for dom in blacklist {
                    //println!("Block: {:?}", dom);
                    r.add(dom, "Block".to_string());

                }


            }
            let mut dom = Domain{
                name: String::from(line.0),
                uri: https_url.parse().unwrap(),
                login_check_uri: line.1.parse().unwrap_or(https_url.parse().unwrap()),
                login_check_answer: String::from(line.2),
                cookies: Vec::new(),
                regex_uri: base_regex,
                regex_uri_extended: exended_base_regex,
                regex_subdomains: subdomains_regex,
                regex_subdomains_relative: subdomains_regex_relative,
                regex_general_subdomains: all_subdomains_regex,
                auth_user: HashSet::new(),
                cookie_origin: HashMap::new(),
                whitelist: r,
            };
            dom.auth_user.insert("perf_test".to_string());

            m.insert(String::from(line.0), dom );
        };
        Mutex::new(m)
    };
    

    static ref HEAD_REGEX: Regex = Regex::new("(?i)<head?[^>]>").unwrap();
    
    static ref PROTOCOL_RELATVE_REGEX: Regex  =Regex::new("\\?proxy_sub=//").unwrap();
    static ref REPLACE_HEAD_WITH: String = {
        let head_base = "<head> \n <base href=\"";
        let base_char = "/\"/>  \n <meta charset=\"utf-8\">";
        let script = io::read_to_string("ma-thesis/js/basescript.html").unwrap();
        format!("{}{}{}\n{}\n", head_base, HTTPS_BASE_URL, base_char,  script)
    };
}

pub fn get_target_domain<'a>(req: &'a  Request)-> Domain {
    //pub fn get_target_domain<'a>(req: &'a  Request)-> Domain<'a> {
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
        //String::from("Authorization"),
        //String::from("Accept-Encoding"),
        //String::from("Connection"),
        //String::from("Access-Control-Allow-Origin"),
        //String::from("Cookie"), // Will be calculated later

        String::from("Content-type"),
        String::from("content-type"),
        //String::from("Cookie")
        //String::from("Sec-Fetch-Dest"),
        /*
        String::from("Sec-Fetch-Dest"),
        String::from("Sec-Fetch-Mode"),
        String::from("Sec-Fetch-Site"),
        */


    ]};

    static ref DEFAULT_HEADERS: Vec<(String,String)> = {vec![
        (String::from("User-Agent"), String::from("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")),
        (String::from("DNT"), String::from("1")),
        (String::from("Cache-Control"), String::from("no-cache")),
        (String::from("Connection"), String::from("keep-alive")),
       // (String::from("Origin"), String::from("https://www.tagesanzeiger.ch/")),
        //(String::from("Referer"), String::from("https://www.tagesanzeiger.ch/"))
        //(String::from("Cookie"), String::from("pzuid=e8d084518706744c0d45d166e020266d5e5ec489f8429ad4bb454844c86c3b7561c8999c; beaker.session.id=525f092dfd55682e2f90a6faaf4fe47d8d881713gAJ9cQEoVQdfZG9tYWlucQJOVQ5fY3JlYXRpb25fdGltZXEDR0HYcidZTrS3VQNfaWRxBFVAODU2NTRhY2RmZDRiMGIzODk1Mzk4NTI3ZWNiYzZmMmUyZWU5ZTA5NTJkMjI5ZjkyZTMxY2I2YzBkNjA0OWU0ZHEFVQ5fYWNjZXNzZWRfdGltZXEGR0HYcl00hXVYWA8AAABzZXNzaW9uX3ZlcnNpb25xB0sCVQVfcGF0aHEIVQEvdS4="))
    ]};
}

fn create_headers_to_forward_and_regexes<'a>(req: &'a Request) -> (Vec::<(String, String)>, Vec<Regex>){
    let mut forwarded_headers: Vec::<(String, String)> = DEFAULT_HEADERS.clone();
    for header in HEADERS.iter() {
        match req.headers.get(header) {
            Some(val) => {forwarded_headers.push((header.to_string(), val.to_string()));},
            _ => {}
        }
    };
    /*
    for header in DEFAULT_HEADERS.iter() {
        forwarded_headers.push()
        match req.headers.get(header) {
            Some(val) => {forwarded_headers.push((key.to_string(), header..to_string()));},
            _ => {}
        }
    };*/
    let (cookie, regexes) = get_random_cookie_and_regexes(req);
    //println!("using cookie: {}", cookie);
    if !cookie.eq(&String::from("")){ // if valid cookie is found add it to header
        forwarded_headers.push((String::from("Cookie"),cookie));
    }
    (forwarded_headers, regexes)
}

/*
------------------------
Proxy Part 
------------------------
*/
pub fn forward_request_and_return_response(mut req: Request) -> IOResult<Vec<u8>> {
    let target_uri = req.target_uri.as_ref().unwrap();
    /*
    // Get paths for Whitlist
    let path = "debug/paths.txt";
    let f = OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)
        .expect("unable to open file");
    let mut f = BufWriter::new(f);
    writeln!(f, "{}", target_uri.path().unwrap_or("/"));
    */
    let (headers, regexes) = create_headers_to_forward_and_regexes(& req);
    req.regexes = regexes;
    //let (res, body) = send_https_request(https_url, &req).unwrap();
    let body = if req.inital_auth_req {
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

    let (status_line, headers, body) = handle_response(res, &body, &req).unwrap();
    prepare_response(status_line, headers, body)
}

pub fn check_auth_for_request(req: & Request) -> bool {
    if let Some(uuid) = &req.uuid {
        let domain = get_target_domain(req);
        return domain.auth_user.contains(uuid)
    } else {return false};
    
}
/*
pub fn parse_target_uri(req: & Request) -> Uri {
    let regex = Regex::new("proxy_sub=(.*)").unwrap();
    let path = req.path.unwrap();
    //println!("Targeting: {}", path);
    let https_url = if path.contains("track_audio") | path.contains("track_video") {
        //println!("zattoo track path: {:?}", path);
        let backup = format!("{}/", HTTPS_BASE_URL);
        let cdn = req.zattoo_cdn.as_ref().unwrap_or(&backup);
        //let cdn_build = &cdn[0..cdn.len()-1];
        let reconstructed_path = format!("{}{}", cdn,path );
        reconstructed_path
    } else {
        match regex.captures(path) {
        Some(res) => { 
            let url = res.get(1).unwrap().as_str().to_string();
            if url.starts_with("https") {
                decode(&url).unwrap().to_string()
            } else {
                let mut prep_https = String::from("https://");
                prep_https+= &url;
                prep_https
            }
        },
        _ => {create_https_url_from_target_and_route(req)}
    }};

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
*/

pub fn handle_response(res: Response, body_original: & Vec<u8>, req: & Request)->IOResult<(String, Headers, Vec<u8>)>{
    let mut headers = Headers::new();
    let status_code = res.status_code();
    let version = res.version();
    let reason = res.reason();
    let default_content_type = String::from("text/plain");
    let content_type = res.headers().get("Content-Type").unwrap_or(&default_content_type);
    let mut body = String::new().as_bytes().to_vec();
    let path = req.path.unwrap();
    let target = req.target.as_ref().unwrap();

    if status_code.eq(&StatusCode::new(204)) && req.method.unwrap().eq("OPTIONS"){
        headers.insert("Access-Control-Allow-Origin", "https://localhost:8443/");
        //headers.insert("Date", "Mon, 16 Jan 2022 11:23:04 GMT");
        //headers.insert("Access-Control-Allow-Origin", );
        headers.insert("Access-Control-Allow-Credentials", "true");
        headers.insert("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        headers.insert("Access-Control-Allow-Headers", "X-PINGOTHER, Content-Type, authorization");
        headers.insert("Access-Control-Allow-Max-Age", "86400");
        headers.insert("Vary", "Origin");
        let status_line = format!("{} {} {}", version, status_code, reason);
        return Ok((status_line, headers, body))

    }
    headers.insert("Content-Type", content_type);
    headers.insert("Vary", "Origin");
    if target.contains("zattoo") {
        headers.insert("Access-Control-Allow-Origin", HTTPS_BASE_URL); // before was set to *, think we can let this
    } else {
        headers.insert("Access-Control-Allow-Origin", HTTPS_BASE_URL);
    }
    

    
    headers.insert("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    headers.insert("Access-Control-Allow-Headers", "X-PINGOTHER, Content-Type, Origin, Authorization, Accept-Encoding");
    headers.insert("Access-Control-Allow-Max-Age", "86400");
    headers.insert("Cache-Control", "no-cache");
    //*/
    //headers.insert("Access-Control-Allow-Origin", "*");
    headers.insert("Access-Control-Allow-Credentials", "true");

    body = if status_code.is_success() { // StatusCode 200 - 299
        try_zatto_res(&res, & mut headers);

        if content_type.contains("text") || content_type.contains("application") && !content_type.contains("octet-stream") {
            match String::from_utf8(body_original.to_vec()) {
                Ok(body_string) => {
                    
                    let mut clean = clean_urls(&body_string, &req, &BASE_LOCALHOST_URL.to_string()).unwrap(); // URL changement to LOCALHOST
                    for regex in req.regexes.iter(){
                        //println!("trying regex: {}", regex);
                        if target.contains("nzz"){
                            clean = regex_replace_all_wrapper(regex, &clean, &"\"---SANITIZED---\"".to_string());

                        } else {
                            clean = regex_replace_all_wrapper(regex, &clean, &"---SANITIZED---".to_string());
                        }
                    }
                    
                    clean = if content_type.contains("script") && target.contains("tagesanzeiger"){
                        let int_re = Regex::new("http(?:s?)://(?:www.)?").unwrap();

                        regex_replace_all_wrapper(&int_re, &clean, &format!("{}/?proxy_sub=$0", HTTPS_BASE_URL))
                    } else if path.contains("zapi/watch/") && body_string.contains("zahs.tv"){
                        // get ressource path
                        let cookie_re = Regex::new("(http(?:s?)://[^.]*.zahs.tv/[^/.]*)/m.mpd").unwrap();
                        let zattoo_cookie = cookie_re.captures(&clean).unwrap().get(1).unwrap().as_str();
                        //println!("before: {}", zattoo_cookie);
                        //create Cookie HEader as return
                        let dt = OffsetDateTime::now_utc()+Duration::from_secs(3600);
                        let val = format!("proxy-zattoo-cdn={}; Expires={}; Max-Age=3600; Path=/; SameSite=None; Secure", zattoo_cookie, dt);
                        headers.insert("Set-cookie", &val);

                        //regex paths
                        let int_re = Regex::new("(http(?:s?)://[^.]*.zahs.tv)").unwrap();
                        regex_replace_all_wrapper(&int_re, &clean, &format!("{}/?proxy_sub=$0", HTTPS_BASE_URL))

                    } else if content_type.contains("html"){
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
        let cleaned_loc = clean_urls(location, &req, &BASE_LOCALHOST_URL.to_string()).unwrap();

        println!("ERROR-{}: Requested Path: {} New Location: {} cleaned location: {}", status_code, req.path.unwrap(), location, cleaned_loc);
        headers.insert("Location", &cleaned_loc);
        headers.insert("Cache-Control", "no-cache");
        /*
        let (res_redirect, body_redirect) = send_https_request_all_paraemeter(&(location.to_string().parse().unwrap()), 443, parse_method(req.method.unwrap()).unwrap(),  &String::new(), &Vec::new()).unwrap();
        let (_status_line, _header, body) = handle_response(res_redirect, &body_redirect, req).unwrap();
        body*/
        String::from("Redirect").as_bytes().to_vec()
    } else if status_code.is_client_err() { // 400-499 Client Error
        println!("ERROR-{}: Requested Path: {}", status_code, req.path.unwrap());
        //println!("DEBUG INFOS MEthod: {:?}", req.method);
        //println!("Response: {:?}", String::from_utf8(body_original.to_vec()));
        body_original.to_vec()
        //String::from("400").as_bytes().to_vec()
    } else { // 500-599 Server Error
        println!("ERROR-{}: Requested Path: {}", status_code, req.path.unwrap());
        println!("Debug body of 500 {}",  String::from_utf8(body_original.to_vec()).unwrap_or("error".to_string()));
        String::from("500").as_bytes().to_vec()
    };
    let status_line = format!("{} {} {}", version, status_code, reason);
    Ok((status_line, headers, body))
    //prepare_response(status_line, headers, body)
    //Ok(body)
}

pub fn try_zatto_res(res: & Response, headers: & mut Headers){
    try_to_insert_to_header(&String::from("Date"), res, headers);
    try_to_insert_to_header(&String::from("Server"), res, headers);
    try_to_insert_to_header(&String::from("Cache-Control"), res, headers);
    try_to_insert_to_header(&String::from("Connection"), res, headers);
}

pub fn try_to_insert_to_header(key: &String, res: & Response, headers: & mut Headers){
    //let def = String::new();
    match res.headers().get(key) {
        Some(val) => {headers.insert(key, val);},
        _ => {}
    }
    
}

/*
------------------------
HTTP Requests
------------------------
*/

pub fn send_https_request_all_paraemeter(addr: &Uri, port: u16, method: Method, body: &String, headers: &Vec<(String, String)>) -> IOResult<(Response, Vec<u8>)>{
    //Construct a domain:ip string for tcp connection
    //Container for re??ponse's body
    let mut writer = Vec::new();
    let mut request = RequestBuilder::new(&addr)
        .method(method).to_owned();

    // Fill in Headers??
    
    for header in headers {
        request.header(&header.0, &header.1);
    };
    //println!("{:?}, \n addr:2 {:?} \n",addr.host(), addr2.host() );
    //early exiting Options request from tagi
    //let path = String::from(addr.path())
    if method.eq(&Method::OPTIONS) && (addr.path().unwrap().contains("disco")||addr.host().unwrap().contains("prod.tda.link")){
        println!("Early exiting tagi disco preflights");
        const HEAD: &[u8; 26] = b"HTTP/1.1 204 No Content \r\n";

        let response = Response::from_head(HEAD).unwrap();
        Ok((response, writer))

    } else if addr.host().unwrap().contains("localhost") && addr.port().unwrap() !=8444 {
        println!("Early returning call to localhost");
        //println!("Debug addr: {:?}", addr);
        Ok((return_503(), writer))
    }
    else {
            let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));
            // get TLS Session
            let t_id = std::thread::current().id().as_u64().get() as usize;
            let mut map = PROXY_TLS_CONN[t_id].lock().unwrap();
            let host = String::from(addr.host().unwrap());
            let mut stream = if map.contains_key(&host as &str){
                //println!("Reusing TLS Connection");
                map.get_mut(&host as &str).unwrap()
            } else {
                drop(map); // release lock, to add new tls stream
                //println!("Adding new Connection");
               
                let stream = create_tcp_stream(&conn_addr, &addr);
                insert_tls_stream(&host, stream);
                //println!("Added");
                map = PROXY_TLS_CONN[t_id].lock().unwrap();
                map.get_mut(&addr.host().unwrap() as &str).unwrap()

            };
            //drop(map);
            //let mut stream = create_tcp_stream(&conn_addr, &addr);
        //request.timeout(Some(Duration::from_millis(1500)));
        request.header("Content-Length", &body.as_bytes().len())
        .body(body.as_bytes());
        //let path = addr.path().unwrap_or("");
    //   if addr.host().unwrap().contains("localhost"){println!("Debug request {:?}", request);}
        let request_backup = request.clone();
        let temp = request.send(&mut stream, &mut writer);
        drop(map);
        error_handling_request_builder(temp, request_backup, &conn_addr, &addr, writer)

    }
}

pub fn error_handling_request_builder(handle: Result<Response, ReqError>, request_backup: RequestBuilder,  conn_addr: &String, addr: &Uri, mut writer: Vec<u8>)-> IOResult<(Response, Vec<u8>)> {
    match handle {
        Ok(response) => {
            Ok((response, writer)) // return response & body
        },
        Err(e) => {
            let default_503 = return_503();
            match e {
                ReqError::IO(error) => {
                    match error.kind() {
                        ErrorKind::BrokenPipe => {
                            println!("Broken Pipe, reopen TLS Connection");
                            let stream = create_tcp_stream(&conn_addr, &addr);
                            
                            insert_tls_stream(&addr.host().unwrap().to_string(), stream);
                            writer = Vec::new();
                            let t_id = std::thread::current().id().as_u64().get() as usize;
                            let mut map = PROXY_TLS_CONN[t_id].lock().unwrap();
                            let mut stream = map.get_mut(&addr.host().unwrap() as &str).unwrap();
                            let request = request_backup.clone();
                            let temp = request.send(&mut stream, &mut writer);
                            drop(map);
                            error_handling_request_builder(temp, request_backup, conn_addr, addr, writer)
                        },
                        ErrorKind::WouldBlock => {
                            println!("Wouldblock on conn_addr: {}", conn_addr);
                            //let response = return_503();
                            Ok((default_503, writer))
                        }
                        _ => {
                            println!("Request IOError (default 503), Kind: {:?}, ", error.kind());
                            //let response = return_503();
                            println!("Debug body: {:?}", writer);
                            Ok((default_503, writer))
                        }
                    }
                }
                ReqError::Parse(ref error) => {
                    println!("Request Parse Error (default 503): {:?}", error);
                    //println!("request send: {:?}", request_backup);
                    Ok((default_503, writer))
                }
                _ => {
                    println!("Request TLS  Error (default 503): {:?}", e);
                    //let response = return_503();
                    Ok((default_503, writer))
                }
            }
        }
    }
}

pub fn return_503()-> Response {
    Response::from_head(HEAD_503).unwrap()
}
/*
pub fn get_tcp_stream<'a>(addr: & 'static Uri, port: u16) -> & 'static Conn<std::net::TcpStream> {
    let conn_addr: & 'static String = &format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));
    //create timeout time
    let conn_addr_copy = conn_addr.clone();
    let mut map = PROXY_TLS_CONN.lock().unwrap();
    if !map.contains_key(&conn_addr as &str){
        const READ_TO: Option<Duration> = Some(Duration::from_secs(2));
        const WRITE_TO: Option<Duration> = Some(Duration::from_secs(2));
    
        //Connect to remote host
        let stream = TcpStream::connect(conn_addr).unwrap();
        stream.set_read_timeout(READ_TO).expect("set_read_timeout call failed");
        stream.set_write_timeout(WRITE_TO).expect("set_write_timeout call failed");
        //Open secure connection over TlsStream, because of `addr` (https)
        let mut stream = tls::Config::default()
            .connect(addr.host().unwrap_or(""), stream)
            .unwrap();
        map.insert(conn_addr_copy, &stream);
    } 
    let stream: &Conn<std::net::TcpStream> = *map.get_mut(&conn_addr as &str).unwrap();
    stream
}
*/
pub fn insert_tls_stream(host: & String, stream: Conn<std::net::TcpStream>){
    let key = String::from(host);
    let t_id = std::thread::current().id().as_u64().get() as usize;

    let mut map = PROXY_TLS_CONN[t_id].lock().unwrap();
    map.insert(key, stream);

    drop(map);
}

pub fn create_tcp_stream(conn_addr: &String, addr: &Uri) -> Conn<std::net::TcpStream> {    

    //Connect to remote host
    let stream = TcpStream::connect(conn_addr).unwrap();/*
    if conn_addr.contains("zahs.tv"){
        stream.set_read_timeout(DUR_HALF_SEC).expect("set_read_timeout call failed");
        stream.set_write_timeout(DUR_HALF_SEC).expect("set_write_timeout call failed");
    } else {
        stream.set_read_timeout(DUR_TWO_SEC).expect("set_read_timeout call failed");
        stream.set_write_timeout(DUR_TWO_SEC).expect("set_write_timeout call failed");
    }
    */
    stream.set_read_timeout(DUR_FIVE_SEC).expect("set_read_timeout call failed");
    stream.set_write_timeout(DUR_FIVE_SEC).expect("set_write_timeout call failed");
    //Open secure connection over TlsStream, because of `addr` (https)
    if conn_addr.contains("localhost:8444"){
        let path = Path::new("ma-thesis/end.fullchain");
        tls::Config::default()
        .add_root_cert_file_pem(path).unwrap() 
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap()
    } else {
        tls::Config::default()
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap()
    }
}

/*
------------------------
Cookie Magic
------------------------
*/

pub fn get_random_cookie_and_regexes(req: & Request) -> (String, Vec<Regex>) {
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    //target_domain.cookies.push(String::from("hello"));
   // println!("Domain Debug: \n Cookie : {:?} \n origin:  {:?} \n authusers: {:?}", target_domain.cookies, target_domain.cookie_origin, target_domain.auth_user);
    let cookies = &target_domain.cookies;
    if cookies.len()>0 {
        let index = rand::thread_rng().gen_range(0, cookies.len());
        let cookie = cookies[index].to_string();
        // add logic to attach regexes
        let regexes_vec = &target_domain.cookie_origin.get(&cookie).unwrap().1;
        (cookie, regexes_vec.to_vec())
    } else {(String::from(""), Vec::new())}

    //String::from("s: &str")
    //target_domain.cookies.choose(& mut thread_rng())
}

pub fn cookie_validator(){
   // println!("[->] Entering Cookie Validation");
    let map_ref = PROXY_URLS.lock().unwrap();
    let mut map = map_ref.clone();
    drop(map_ref);
    //let mut remove: HashMap<String, Vec<u16>> = HashMap::new();
    for (k,v) in map.iter_mut(){
        if v.cookies.len() > 0 {
            //println!("checking: {}", k);
            let mut remove_indexes = Vec::new();
            for (i, cookie) in v.cookies.iter().enumerate() {
                //println!("Cookie {} = {}", i, cookie);
                let valid = try_out_cookie_at_target(&v, &cookie, & mut Vec::new(), false);
                if !valid {
                    remove_indexes.push(i);
                }
                
            }
            remove_indexes.sort_by(|a,b| b.cmp(a)); // Reverse Order to remove them from vector safely...
            //println!("Removing: {:?}", remove_indexes);
            remove_invalid_cookies(k, &remove_indexes);
        }
    }
    //drop(map);
    //println!("[<-] Exiting Cookie Validation");

}

pub fn remove_invalid_cookies(domain: & String, indexes: & Vec<usize>) {
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(domain).unwrap();
    for i in indexes{
        let cookie = target_domain.cookies.remove(*i); // remove from cookie
        let res = target_domain.cookie_origin.remove(&cookie);
        match res {
            Some(tuple) => {
                // tuple = (uuid, Regexes)
                target_domain.auth_user.remove(&tuple.0);
            },
            _ => {/* Acces already removed */}
        }

    }
    drop(map);
}

pub fn cookie_is_valid(req: & Request, cookie: String) -> bool {
    let target_domain = get_target_domain(&req);
    let mut regexes: Vec<Regex> = Vec::new(); // need to be filled up
    if try_out_cookie_at_target(&target_domain, &cookie, & mut regexes, true) {
        println!("[+] Cookie Validated, it will now be inserted!");
        insert_cookie_to_target(&req, cookie, regexes);
        true
    } else {
        println!("[xxx] Cookie Validation failed");
        false
    }
}

pub fn try_out_cookie_at_target(target_domain: & Domain, cookie: &String,  regexes: & mut Vec<Regex>, sanitizer: bool) -> bool {
    /*let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();*/

    let login_check_answer = target_domain.login_check_answer.as_str();
    let (response, _body) = if login_check_answer == "tagi" {
       send_https_request_all_paraemeter(&target_domain.login_check_uri, 443, Method::POST, &String::new(), &vec![(String::from("Connection"), String::from("Keep-alive")), (String::from("Cookie"), cookie.to_string())]).unwrap()
    } else {
        send_https_request_all_paraemeter(&target_domain.login_check_uri, 443, Method::GET, &String::new(), &vec![(String::from("Connection"), String::from("Keep-alive")), (String::from("Cookie"), cookie.to_string())]).unwrap()
    };
    let status_code = response.status_code();
    match login_check_answer {
        "302" => {
            if status_code.is_redirect() {
                false
            } else {
                if sanitizer {
                    create_sanitizer_regex(target_domain, cookie, regexes);
                }
                true
            }

        },
        "tagi" => {
            let body = String::from_utf8(_body).unwrap(); // personal data
            let json: Value = serde_json::from_str(body.as_str()).unwrap();
            let identity = &json["identityToken"].as_str();
            let bearer = format!("Bearer {}", &identity.unwrap_or(""));

            //println!("Debug: {}", bearer);
            let sec: Uri = "https://www.tagesanzeiger.ch/disco-api/v1/paywall/get-entitlements".parse().unwrap();
            let (_res, answer) = send_https_request_all_paraemeter(
                &sec, 443, Method::POST,
                &String::new(), 
                &vec![
                    (String::from("Connection"), String::from("Keep-alive")),
                    (String::from("Authorization"), bearer.to_string())
                    ]
                ).unwrap();
            let bo = String::from_utf8(answer).unwrap();
            let abo_json: Value = serde_json::from_str(bo.as_str()).unwrap();
            /*
            if body.contains("abo-button") {
                println!("Login successfull");
            } else {
                println!("not good");
            }
            true
           */
          match abo_json["hasAbo"] {
              Value::Bool(bo) => {
                if sanitizer{
                    regexes.push(Regex::new(&String::from((json["email"]).as_str().unwrap_or(""))).unwrap());
                    let firstname = (json["firstname"]).as_str().unwrap_or("");
                    let lastname = (json["lastname"]).as_str().unwrap_or("");
                    //println!("Firstname: {}, lastname: {}", firstname, lastname);
                    
                    if firstname != "" {
                        regexes.push(Regex::new(&String::from(firstname)).unwrap());
                    }
                    if lastname != "" {
                        regexes.push(Regex::new(&String::from(lastname)).unwrap());
                    }
    
                }
                  bo},
              _ => false
          }

        },
        "403" => {
            if status_code.is_client_err() {
                false
            } else {
                if sanitizer {
                    create_sanitizer_regex(target_domain, cookie, regexes);
                }
                true}
        },
        _ => {
            true}
    }
}

pub fn create_sanitizer_regex(target_domain: & Domain, cookie: &String, regexes: & mut Vec<Regex>){
    match target_domain.name.as_str() {
        "test.benelli.dev" => {},
        "www.nzz.ch" => {
            let addr: Uri = "https://www.nzz.ch".parse().unwrap();
            let (_response,body) = send_https_request_all_paraemeter(&addr, 443, Method::GET, &String::new(), &vec![(String::from("Connection"), String::from("Keep-alive")), (String::from("Cookie"), cookie.to_string())]).unwrap();
            let body = String::from_utf8(body).unwrap();
            let userinforegex = Regex::new("window.nzzUserInfo = ([^;]*)").unwrap();
            let data = userinforegex.captures(&body).unwrap();
            let json: Value = serde_json::from_str(data.get(1).unwrap().as_str()).unwrap();
            let firstname = (json["first_name"]).as_str().unwrap();
            let lastname = (json["last_name"]).as_str().unwrap();
            let _user_id = (json["user_id"]).as_str().unwrap();
            let _session_id = (json["session_id"]).as_str().unwrap();
            let escapedfirstname = format!("\"{}\"", firstname);      
            let escapedlastname = format!("\"{}\"", lastname);            
      
            if escapedfirstname != "" {
                regexes.push(Regex::new(&String::from(escapedfirstname)).unwrap());
            }
            if escapedlastname != "" {
                regexes.push(Regex::new(&String::from(escapedlastname)).unwrap());
            }
            //println!("regex: {}", &data[1]);
        },
        "zattoo.com" => {
            let addr: Uri = "https://zattoo.com/zapi/v3/session".parse().unwrap();
            let (_response,body) = send_https_request_all_paraemeter(&addr, 443, Method::GET, &String::new(), &vec![(String::from("Connection"), String::from("Keep-alive")), (String::from("Cookie"), cookie.to_string())]).unwrap();
            let body = String::from_utf8(body).unwrap(); // personal data
            let json: Value = serde_json::from_str(body.as_str()).unwrap();
            //let identity = &json["account"].as_str();
            //let bearer = format!("Bearer {}", &identity.unwrap_or(""));
            let login = String::from((json["account"]["name"]).as_str().unwrap());
            let regex = Regex::new(&login).unwrap();
            regexes.push(regex);
            //println!("Response zattoo {}", login);
        },
        _ => {}
    };
}

pub fn insert_cookie_to_target(req: & Request, cookie: String, regexes: Vec<Regex>){
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    //target_domain.cookies.push(String::from("hello"));
    //println!("{} will be inserted to {:?}", cookie, target_domain);  
    let cookie_decoded = cookie.clone().replace("+", " ");
    /*
    let parsed_cookie = Cookie::parse(cookie_decoded).unwrap();
    */
    let parsed_cookie = cookie_decoded.clone();
    let uuid = req.uuid.as_ref().unwrap().to_string();
    target_domain.auth_user.insert(uuid.clone());
    target_domain.cookie_origin.insert(cookie_decoded, (uuid, regexes));

    target_domain.cookies.push(parsed_cookie);

    //println!("Vector now {:?}",  target_domain);
}


/*
------------------------
Mutating Response Part 
------------------------
*/
pub fn clean_urls(content: & String, req: & Request, replace_with: &String) -> IOResult<String> {
    /*/* Debug to file */
    let cnt = COUNTER.fetch_add(1, Ordering::SeqCst);
    
    let path = format!("debug/{}_0.txt", cnt);
    let mut file_0 = File::create(path)?;
    let path = format!("debug/{}_1.txt", cnt);
    let mut file_1 = File::create(path)?; 
    let path = format!("debug/{}_2.txt", cnt);
    let mut file_2 = File::create(path)?;
    let path = format!("debug/{}_3.txt", cnt);
    let mut file_3 = File::create(path)?;
    
    let path = format!("debug/{}_4.txt", cnt);
    let mut file_4 = File::create(path)?;*/
 
    
    let target_domain = get_target_domain(req);
    //file_0.write_all(content.as_bytes())?;
    let modified_content = regex_replace_all_wrapper(&target_domain.regex_uri, &content, &replace_with);
    //file_1.write_all(modified_content.as_bytes())?;
    let extended_modified_content = regex_replace_all_wrapper(&target_domain.regex_uri_extended, &modified_content, &HTTPS_BASE_URL.to_string());
    //file_0.write_all(extended_modified_content.as_bytes())?;
    let sub_domain_cleand = if let Some(sub_regex) = target_domain.regex_subdomains {
        let intermediate = regex_replace_all_wrapper(&sub_regex, &extended_modified_content, &format!("{}/?proxy_sub=$0", HTTPS_BASE_URL ));
        //let fixed_protocol_relative = regex_replace_all_wrapper(&PROTOCOL_RELATVE_REGEX, &sub_domain_cleand, &"?proxy_sub=https://".to_string());
        //file_1.write_all(intermediate.as_bytes())?;
        //Regex::new("(\"|\')//(assets.static-nzz.ch|ens.nzz.ch|img.nzz.ch|tms.nzz.ch|track.nzz.ch|oxifwsabgd.nzz.ch)").unwrap();
        let sb_relative = regex_replace_all_wrapper(&target_domain.regex_subdomains_relative.unwrap(), &intermediate,  &format!("$1//{}/?proxy_sub=https://$2", BASE_LOCALHOST_URL));
        //file_3.write_all(fixed_protocol_relative2.as_bytes())?;
        sb_relative
           /* 
        let domains = "assets.static-nzz.ch|ens.nzz.ch|img.nzz.ch|tms.nzz.ch|track.nzz.ch|oxifwsabgd.nzz.ch";
        try out zatoo */
        /*
        if let Some(general_sub) = target_domain.regex_general_subdomains {
            regex_replace_all_wrapper(&general_sub, &sb_relative, &format!("{}/?proxy_sub=$0", HTTPS_BASE_URL))
        } else {sb_relative} */
        /*
        let re2 = Regex::new(format!(r"(\\u002F\\u002F)({})", domains).as_str()).unwrap();
        regex_replace_all_wrapper(&re2, &int,   &format!(r"\u002F\u002F{}\u002F\u003Fproxy_sub=https:$0", BASE_LOCALHOST_URL))
        */
    } else {
        extended_modified_content
        /*
        if let Some(general_sub) = target_domain.regex_general_subdomains {
            regex_replace_all_wrapper(&general_sub, &extended_modified_content, &format!("{}/?proxy_sub=$0", HTTPS_BASE_URL))
        } else {extended_modified_content}
        */
    };
    //file_1.write_all(sub_domain_cleand.as_bytes())?;
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