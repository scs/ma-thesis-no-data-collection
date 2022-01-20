//use itp_sgx_io as io;
use sgx_tstd as std;
//use crate::mixnet::router;
use crate::mixnet::tls_server::Request;
use http_req::{request::{RequestBuilder, Method}, tls, tls::Conn, uri::Uri, response::{Response, Headers, StatusCode}};
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
//use cookie::Cookie;
use std::time::{Duration};
use time::OffsetDateTime;
//use chrono::prelude::*;
//use std::sync::atomic::{AtomicU8, Ordering*/};
use urlencoding::decode;
//use core::borrow::{BorrowMut, Borrow};
//use std::sync::Arc;

#[derive(Clone,Debug)]
pub struct Domain {
//    pub struct Domain <'a> {
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
    pub auth_user: HashMap<String,String>
 
}

// Debug counter
//static COUNTER: AtomicU8 = AtomicU8::new(0);
/*
------------------------
Helper Funcs and Var
------------------------
*/
lazy_static! {
    static ref PROXY_TLS_CONN: Mutex<HashMap<String, Conn<std::net::TcpStream>>> = {
        let mut m = HashMap::new();/*
        //let tls_session = lines_from_file("ma-thesis/tls_sessions.txt", 1);
        let a = String::from("https://test.benelli.dev");
        let addr: Uri = a.parse().unwrap();
        let port: u16 = 443;
        let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));

        let stream = create_tcp_stream(&conn_addr, &addr);
        let host = String::from(addr.host().unwrap());
        m.insert(host, stream);*/

        Mutex::new(m)
    };
    static ref PROXY_URLS: Mutex<HashMap<String, Domain>> = {
//        static ref PROXY_URLS: Mutex<HashMap<String, Domain<'static>>> = {
        let mut m = HashMap::new();
        let services = lines_from_file("ma-thesis/services.txt", 1);
        for service in services {
            let mut split = service.split(" || ");
            //Attention: this must be adapted for each new column
            let line =(split.next().unwrap(), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""), split.next().unwrap_or(""));
            let https_url = format!("https://{}", line.0);
            let base_regex = Regex::new(line.0).unwrap();
            let exended_base_regex = Regex::new(format!("(?:(?:ht|f)tp(?:s?)://|~/|/|//)?{}", line.0).as_str()).unwrap();
            let subdomains_regex = if line.3.eq("") {None} else { Some(Regex::new(format!("((?:(?:ht|f)tp(?:s?)://|~/)({}))", line.3).as_str()).unwrap())};
            let subdomains_regex_relative = if line.3.eq("") {None} else { Some(Regex::new(format!("(\"|\'|\\()//({})", line.3).as_str()).unwrap())};
            let all_subdomains_regex =  if line.4.eq("") {None} else {Some(Regex::new(format!("((?:(?:ht|f)tp(?:s?)://|~/|/|//)?([^.]+[.])*({}))", line.4).as_str()).unwrap())};
            m.insert(String::from(line.0), Domain{
                uri: https_url.parse().unwrap(),
                login_check_uri: line.1.parse().unwrap_or(https_url.parse().unwrap()),
                login_check_answer: String::from(line.2),
                cookies: Vec::new(),
                regex_uri: base_regex,
                regex_uri_extended: exended_base_regex,
                regex_subdomains: subdomains_regex,
                regex_subdomains_relative: subdomains_regex_relative,
                regex_general_subdomains: all_subdomains_regex,
                auth_user: HashMap::new(),
            });
        };
        Mutex::new(m)
    };
    

    static ref HEAD_REGEX: Regex = Regex::new("(?i)<head?[^>]>").unwrap();
    
    static ref PROTOCOL_RELATVE_REGEX: Regex  =Regex::new("\\?proxy_sub=//").unwrap();

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
                if (\"serviceWorker\" in navigator) {
                navigator.serviceWorker.getRegistrations().then( function(registrations) { for(let registration of registrations) { registration.unregister(); } }); 
                }
                document.cookie = \"proxy-target=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;\";
                document.cookie = \"proxy-zattoo-cdn=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;\";
                window.location.href = '/';
            });
            document.body.prepend(btn);

            document.cookie = \"uuid=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;\";
            document.cookie = \"FAVORITES_ONBOARDING=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;\";
        
            if(document.head.innerHTML.includes(\"tagesanzeiger.ch\")){
                //tagesanzeiger reload
                const observer = new MutationObserver(function(mutations_list) {
                    mutations_list.forEach(function(mutation) {
                        mutation.addedNodes.forEach(function(added_node) {
                            if(added_node.innerHTML.includes(\"(CSR)\")){
                                location.reload();
                            }
                            console.log(added_node);
                        });
                    });
                });
                observer.observe(document.querySelector(\"#__next\"), { subtree: false, childList: true });
        
            }
        }



        </script>";
        format!("{}{}{}\n{}\n{}\n", head_base, HTTPS_BASE_URL, base_char, style, script)
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
        String::from("Authorization"),
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

fn create_headers_to_forward<'a>(req: &'a  Request) -> Vec::<(String, String)>{
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
    let cookie = get_random_cookie(&req);
    //println!("using cookie: {}", cookie);
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

    let (status_line, headers, body) = handle_response(res, &body, req).unwrap();
    prepare_response(status_line, headers, body)
}

pub fn check_auth_for_request(req: & Request) -> bool {
    if let Some(uuid) = &req.uuid {
        let domain = get_target_domain(req);
        return domain.auth_user.contains_key(uuid)
    } else {return false};
    
}

pub fn parse_target_uri(req: & Request) -> Uri {
    let regex = Regex::new("proxy_sub=(.*)").unwrap();
    let path = req.path.unwrap();
    //println!("Targeting: {}", path);
    let https_url = if path.contains("track_audio") | path.contains("track_video") {
        let backup = format!("{}/", HTTPS_BASE_URL);
        let cdn = req.zattoo_cdn.as_ref().unwrap_or(&backup);
        let cdn_build = &cdn[0..cdn.len()-1];
        let test = format!("{}{}", cdn_build,path );
        test
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
        headers.insert("Access-Control-Allow-Origin", "*");
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

/*
    if req.path.unwrap().contains("validate-session") {
        println!("Debug: Tagesanzeiger response: {:?}", res);
    } */
    //let default_cookies = String::from("");
    //let cookies = res.headers().get("set-cookie").unwrap_or(&default_cookies);
    //headers.insert("Set-Cookie", cookies);
    //println!("Response: {:?}", res);

    //Zattoo extra logic
    let regex = Regex::new("set-proxy-zattoo=([^&]*)").unwrap();
    match regex.captures(path) {
        Some(res) => {
            let url = res.get(1).unwrap().as_str();
            //let datetime= Instant::now() + Duration::from_secs(7200);
            let dt = OffsetDateTime::now_utc()+Duration::from_secs(3);
            //println!("{:?}", datetime.toUTCString());
            let val = format!("proxy-zattoo-cdn={}; Expires={}; Max-Age=3600; Path=/; SameSite=None; Secure", url, dt);
            headers.insert("Set-cookie", &val);
            //println!("Inserted: {}", val);
        },
        _ => {}
    }

    body = if status_code.is_success() { // StatusCode 200 - 299
        try_zatto_res(&res, & mut headers);

        if content_type.contains("text") || content_type.contains("application") && !content_type.contains("octet-stream") {
            match String::from_utf8(body_original.to_vec()) {
                Ok(body_string) => {
                    let mut clean = clean_urls(&body_string, &req, &BASE_LOCALHOST_URL.to_string()).unwrap(); // URL changement to LOCALHOST
                    clean = if content_type.contains("script") && target.contains("tagesanzeiger"){
                        let int_re = Regex::new("http(?:s?)://(?:www.)?").unwrap();

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
    //Container for re§ponse's body
    let mut writer = Vec::new();
    let mut request = RequestBuilder::new(&addr)
        .method(method).to_owned();
    // get TLS Session
    let mut map = PROXY_TLS_CONN.lock().unwrap();
    let host = String::from(addr.host().unwrap());
    let mut stream = if map.contains_key(&host as &str){
        //println!("Reusing TLS Connection");
        map.get_mut(&host as &str).unwrap()
    } else {
        drop(map); // release lock, to add new tls stream
        //println!("Adding new Connection");
        let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));
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
        insert_tls_stream(host, stream);
        //println!("Added");
        map = PROXY_TLS_CONN.lock().unwrap();
        map.get_mut(&addr.host().unwrap() as &str).unwrap()

    };

    // Fill in Headers
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

    } else {
        request.header("Content-Length", &body.as_bytes().len())
        .body(body.as_bytes());
        let path = addr.path().unwrap_or("");
       // if path.contains("content") {println!("Debug request {:?}", request);}
        let temp = request.send(&mut stream, &mut writer);
        match temp {
            Ok(response) => {
                Ok((response, writer)) // return response & body
            },
            Err(e) => {
                println!("Couldn't handle request: {:?}", e);
                //println!("Debug: Addr: {:?} \n\n", addr);
                //println!("Request send: {:?}", request);
                const HEAD: &[u8; 120] = b"HTTP/1.1 503 Service Unavailable \r\n\
                            Date: Sat, 11 Jan 2003 02:44:04 GMT\r\n\
                            Content-Type: text/html\r\n\
                            Content-Length: 100\r\n\r\n";

                let response = Response::from_head(HEAD).unwrap();
                Ok((response, writer))
            }
        }
    }
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
pub fn insert_tls_stream(host: String, stream: Conn<std::net::TcpStream>){
    let mut map = PROXY_TLS_CONN.lock().unwrap();
    map.insert(host, stream);
    drop(map);
}

pub fn create_tcp_stream(conn_addr: &String, addr: &Uri) -> Conn<std::net::TcpStream> {    
    const READ_TO: Option<Duration> = Some(Duration::from_secs(2));
    const WRITE_TO: Option<Duration> = Some(Duration::from_secs(2));

    //Connect to remote host
    let stream = TcpStream::connect(conn_addr).unwrap();
    stream.set_read_timeout(READ_TO).expect("set_read_timeout call failed");
    stream.set_write_timeout(WRITE_TO).expect("set_write_timeout call failed");
    //Open secure connection over TlsStream, because of `addr` (https)
    tls::Config::default()
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap()
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
        cookies[index].to_string()
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
    let (response, _body) = send_https_request_all_paraemeter(&target_domain.login_check_uri, 443, Method::GET, &String::new(), &vec![(String::from("Connection"), String::from("Keep-alive")), (String::from("Cookie"), cookie.to_string())]).unwrap();
    let status_code = response.status_code();
    match target_domain.login_check_answer.as_str() {
        "302" => {
            if status_code.is_redirect() {
                false
            } else {true}
        },
        "tagi" => {
            let body = String::from_utf8_lossy(&_body);
            println!("Cookie used: {}", cookie);
            if body.contains("abo-button") {
                println!("Login successfull");
            } else {
                println!("not good");
            }
            true
        },
        "403" => {
            if status_code.is_client_err() {
                false
            } else {true}
        },
        _ => {
            true}
    }
}


pub fn insert_cookie_to_target(req: & Request, cookie: String){
    let mut map = PROXY_URLS.lock().unwrap();
    let target_domain: & mut Domain = map.get_mut(req.target.as_ref().unwrap()).unwrap();
    //target_domain.cookies.push(String::from("hello"));
    //println!("{} will be inserted to {:?}", cookie, target_domain);  
    let cookie_decoded = cookie.clone().replace("+", " ");
    /*
    let parsed_cookie = Cookie::parse(cookie_decoded).unwrap();
    target_domain.auth_user.insert(req.uuid.as_ref().unwrap().to_string(), parsed_cookie.value().to_string());
    */
    let parsed_cookie = cookie_decoded;
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