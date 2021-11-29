//use itp_sgx_io as io;

use sgx_tstd as std;

//use crate::mixnet::router;
use crate::mixnet::tls_server::Request;

use http_req::{request::RequestBuilder, tls, uri::Uri, response::{Response}};
//use http_req::response::Headers;
use std::net::TcpStream;
use std::{
	string::{
        //ToString, 
        String,
    },
    vec::Vec,
    io::{Result as IOResult},
    
};
//use std::io::prelude::*;
use regex::Regex;

use crate::mixnet::{HTTPS_BASE_URL};

pub fn forward_and_return_request_new(req: & Request) -> IOResult<String> {
    let https_url = create_https_url_from_target_and_route(req);
    let (res, body) = send_http_request(https_url).unwrap();
    let clean_response = handle_response(res, &body, req).unwrap();
    Ok(clean_response)
}

pub fn create_https_url_from_target_and_route(req: & Request) -> String {
    let target = req.target.as_ref().unwrap(); //Both unwraps are Safe, otherwise we wouldn't be here
    let path = req.path.as_ref().unwrap();
    let mut https_url = String::from("https://");
    https_url += &target;
    https_url += path;
    https_url
}


pub fn handle_response(res: Response, body: & Vec<u8>, req: & Request)->IOResult<String>{
    let status_code = res.status_code();
    if status_code.is_success() { // StatusCode 200 - 299
        println!("{:?}", res.headers().get("Content-Type").unwrap());
        let res_str = String::from_utf8(body.to_vec()).expect("Invalid Response from host");
        // handle response code
        let target =  req.target.as_ref().unwrap();
        let clean = clean_urls(&res_str, &target).unwrap();
        add_base_tag(&clean)
    } else if status_code.is_redirect() { // 300 - 399 Redirect
        println!("{:?}", res.headers());
        Ok(String::from("Redirect"))
    } else if status_code.is_client_err() { // 400-499 Client Error
        Ok(String::from("400"))
    } else { // 500-599 Server Error
        Ok(String::from("500"))
    }
}

pub fn send_http_request(hostname: String) -> IOResult<(Response, Vec<u8>)>{
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
    let response = RequestBuilder::new(&addr)
        .header("Connection", "Close")
        .send(&mut stream, &mut writer)
        .unwrap();

    Ok((response, writer))

}

pub fn clean_urls(content: & String, target_url: & String) -> IOResult<String> {
    let mut regex_string = String::from("(?:(?:ht|f)tp(?:s?)://|~/|/)?");
    regex_string += target_url;
    let re = Regex::new(regex_string.as_str()).unwrap(); 
    let replace_with = String::from(HTTPS_BASE_URL);
    //replace_with += &String::from("/proxy/");
    //replace_with += target_url;

    //println!("Regexstring: {} and replace it with: {}", regex_string, replace_with);
    //println!("{:?}",content);
    let content = re.replace_all(&content, replace_with.as_str());
    //println!("{:?}",content);
    //println!("{}", String::from_utf8_lossy(&writer));
    //println!("[<-] replacement done");
    //text
    Ok(String::from(content))
}

pub fn add_base_tag(content: & String) -> IOResult<String> {
    let regex = Regex::new("(?i)<head>").unwrap();
    let mut replace_with = String::from("<head> \n <base href=\"");
    replace_with += HTTPS_BASE_URL;
    replace_with += &String::from("\"/> <meta charset=\"utf-8\">");
    //println!("Regexstring: {} and replace it with: {}", regex, replace_with);

    let content = regex.replace_all(&content, replace_with.as_str());
    Ok(String::from(content))
}