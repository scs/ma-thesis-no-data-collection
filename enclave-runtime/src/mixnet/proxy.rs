//use itp_sgx_io as io;

use sgx_tstd as std;

//use crate::mixnet::router;
use crate::mixnet::tls_server::Request;

use http_req::{request::RequestBuilder, tls, uri::Uri, response::{Response, Headers}};
//use http_req::response::Headers;
use std::net::TcpStream;
use std::{
	string::{
        ToString, 
        String,
    },
    vec::Vec,
    io::{Result as IOResult},
    borrow::ToOwned,
    
};
//use std::io::prelude::*;
use regex::Regex;

use crate::mixnet::{HTTPS_BASE_URL};

pub fn forward_request_and_return_response(req: & Request) -> IOResult<Vec<u8>> {
    let https_url = create_https_url_from_target_and_route(req);
    let (res, body) = send_https_request(https_url, &req).unwrap();
    let (status_line, headers, body) = handle_response(res, &body, req).unwrap();
    prepare_response(status_line, headers, body)
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
    let content_type = res.headers().get("Content-Type").unwrap();
    headers.insert("Content-Type", content_type);
    //println!("Response: {:?}", res);
    let body = if status_code.is_success() { // StatusCode 200 - 299
        if content_type.contains("html") {
            let res_str = String::from_utf8(body_original.to_vec()).expect("Invalid Response from host");
            // handle response code
            let mut clean = clean_urls(&res_str, &req).unwrap();
            clean = add_base_tag(&clean).unwrap();
            clean.as_bytes().to_vec()
        } else if content_type.contains("javascript") {
            let res_str = String::from_utf8(body_original.to_vec()).expect("Invalid Response from host");
            let clean = clean_urls(&res_str, &req).unwrap();
            clean.as_bytes().to_vec()
        } else {
            body_original.to_vec()
        }
    } else if status_code.is_redirect() { // 300 - 399 Redirect // Intercept it and reset Cookie
        let location = res.headers().get("Location").unwrap();
        //println!("Retrying at {:?}", location);
        println!("ERROR: 300-399 Status: {} Requested Path: {} New Location: {}", status_code, req.path.unwrap(), location);
        //headers.insert("Location", HTTPS_BASE_URL);
        let (res_redirect, body_redirect) = send_https_request(location.to_string(), req).unwrap();
        let (_status_line, _header, body) = handle_response(res_redirect, &body_redirect, req).unwrap();
        body
        //String::from("Redirect").as_bytes().to_vec()
    } else if status_code.is_client_err() { // 400-499 Client Error
        println!("ERROR: Status: {} Requested Path: {}", status_code, req.path.unwrap());

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

pub fn prepare_response(status_line: String, headers: Headers, mut contents: Vec<u8>) ->  IOResult<Vec<u8>>{
    //println!("{:?}", status_line);
    //let status_line = format!("{} {} {}", status.version(), status.code.as_u16(), status.reason());
    //let status_line = "HTTP/1.1 200 OK";
    let mut addional_headers = "".to_owned(); //"Location: https://www.blick.ch/ \r\n";
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

pub fn send_https_request(hostname: String, req: &Request) -> IOResult<(Response, Vec<u8>)>{
    let addr: Uri = hostname.parse().unwrap();
    let port: u16 = 443;
    //Construct a domain:ip string for tcp connection
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));
    //println!("Addr: {:?}", conn_addr);
    //Connect to remote host
    let stream = TcpStream::connect(conn_addr).unwrap();
    //Open secure connection over TlsStream, because of `addr` (https)
    let mut stream = tls::Config::default()
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap();
    //Container for response's body
    let mut writer = Vec::new();
    //Add header `Connection: Close`
    println!("DEBUG Method: {:?} \n Body: {:?}", req.method, req.body);
    let response = RequestBuilder::new(&addr)
        .header("Connection", "Keep-Alive")
        .header("Cookie", "connect.sid=s:IZCMqmHa17cQr6JySQDwCv5U8cyH32d_.Jl3L3UhZQ9dbkju51eeDsOCDo8AfCbAUsl1S2eASTjs; Domain=republik.ch; Path=/; Expires=Wed, 30 Nov 2022 15:38:19 GMT; HttpOnly; Secure; SameSite=None")
        .send(&mut stream, &mut writer)
        .unwrap();
    Ok((response, writer))
}

pub fn clean_urls(content: & String, req: & Request) -> IOResult<String> {
    let target_url =  req.target.as_ref().unwrap();    
    let mut regex_string = String::from("(?:(?:ht|f)tp(?:s?)://|~/|/)?");
    regex_string += target_url;
    let re = Regex::new(regex_string.as_str()).unwrap(); 
    let replace_with = String::from(HTTPS_BASE_URL);
    let content = re.replace_all(&content, replace_with.as_str());
    Ok(String::from(content))
}

pub fn add_base_tag(content: & String) -> IOResult<String> {
    let regex = Regex::new("(?i)<head>").unwrap();
    let mut replace_with = String::from("<head> \n <base href=\"");
    replace_with += HTTPS_BASE_URL;
    replace_with += &String::from("\"/> <meta charset=\"utf-8\">");
    replace_with += &get_logout_script();
    //println!("Regexstring: {} and replace it with: {}", regex, replace_with);

    let content = regex.replace_all(&content, replace_with.as_str());
    Ok(String::from(content))
}

pub fn get_logout_script() -> String {
    let style = "<style> .proxy_target_logout {margin-bottom:3px; padding:10px; width: 100%; border:1px solid #CCC; max-width: 100%; background-color: red; color: white; } </style>";
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
    format!("{}{}", style, script)
}