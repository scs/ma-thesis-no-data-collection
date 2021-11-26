use itp_sgx_io as io;

use sgx_tstd as std;

use crate::mixnet::router;
use router::RouterRequest;

use http_req::{request::RequestBuilder, tls, uri::Uri};
use std::net::TcpStream;
use std::{
	string::{
        //ToString, 
        String,
    },
    vec::Vec,
    io::{Result as IOResult}
};
//use std::io::prelude::*;

use regex::Regex;

use crate::mixnet::{HTTPS_BASE_URL};



pub fn forward_and_return_request(req: & RouterRequest, has_route: bool) -> IOResult<String> {
    let target = &req.map["service"];
    let route = if has_route {
        &req.map["route"]
    } else { "" };
    println!("Targeting: {} and route {}", target, route);
    // get session token
    let addr: Uri = target.parse().unwrap();
    //println!("parsed address: {:?}", addr);
    let mut https_url = String::from("https://");
    https_url += target;
    https_url += &String::from("/");
    https_url += route;
    let addr: Uri = https_url.parse().unwrap();
    println!("parsed address: {:?}", addr);

    let res = send_http_request(https_url).unwrap();
    // handle response code
    let clean = clean_urls(&res, &target).unwrap();
    Ok(clean)
}

pub fn send_http_request(hostname: String) -> IOResult<String>{
    let addr: Uri = hostname.parse().unwrap();
    let port: u16 = 443;
    //Construct a domain:ip string for tcp connection
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap_or(port));
    println!("Addr: {:?}", conn_addr);
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

    let res_str = String::from_utf8(writer).expect("Invalid Response from host");
    //println!("Response: {:?}", response);
    //println!("DEBUG res_str: {}", res_str);
    Ok(res_str)
}

pub fn clean_urls(content: & String, target_url: & String) -> IOResult<String> {
    let mut regex_string = String::from("(?:(?:ht|f)tp(?:s?)://|~/|/)?");
    regex_string += target_url;
    let re = Regex::new(regex_string.as_str()).unwrap(); 
    let mut replace_with = String::from(HTTPS_BASE_URL);
    replace_with += &String::from("/proxy/");
    replace_with += target_url;

    println!("Regexstring: {} and replace it with: {}", regex_string, replace_with);
    //println!("{:?}",content);
    let content = re.replace_all(&content, replace_with.as_str());
    //println!("{:?}",content);
    //println!("{}", String::from_utf8_lossy(&writer));
    //println!("[<-] replacement done");
    //text
    Ok(String::from(content))
}