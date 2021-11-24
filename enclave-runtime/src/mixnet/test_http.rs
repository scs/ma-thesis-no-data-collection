use itp_sgx_io as io;
use sgx_tstd as std;
use std::{
	string::ToString,
	vec::Vec,
};
use codec::{alloc::string::String};

//from tutorial (doc.rust.lang.org/book)

use http_req::{request::{RequestBuilder,Method}, tls, uri::Uri, response::StatusCode};
//use std::ffi::CStr;
//use std::ffi::CString;
use std::net::TcpStream;
use std::net::TcpListener;
//use std::os::raw::c_char;
//use std::prelude::v1::*;
use regex::Regex;
//from tutorial (doc.rust.lang.org/book)
use std::io::prelude::*;
#[allow(dead_code)]
pub fn start_tcp_listener(){
    	/*
	
	let base_url = Url::parse("https://google.com").unwrap();
	let http_client = HttpClient::new(true, Some(Duration::from_secs(3u64)), None, None);
	let builder = RestClient::new(http_client, base_url);
	let res = builder.get::<String>("/".to_string()).unwrap();
	*/

	/*
	RestGet::get("https://www.CheckTLS.com/TestReceiver
	?CUSTOMERCODE=me@mydomain.com
	&CUSTOMERPASS=IllNeverTell
	&EMAIL=test@CheckTLS.com
	&LEVEL=XML_DETAIL");
	*/
    println!("[+] Starting TcpListener");
	// 	let (mut key, mut cert) = get_key_and_cert();
	let listener = TcpListener::bind(super::BASE_URL).unwrap();
	for stream in listener.incoming() {
		let stream = stream.unwrap();
		println!("handling connection:");
		//        let _ = serve(stream, &mut key, &mut cert).unwrap();
		handle_connection(stream);
		println!("Connection closed!");

	}

}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 2048];
    stream.read(&mut buffer).unwrap();

	let get = b"GET / HTTP/1.1\r\n";
	let post_login = b"POST /login HTTP/1.1\r\n";

	let (status_line, contents) = if buffer.starts_with(post_login) {
		let request = String::from_utf8_lossy(&buffer[..]);
		//println!("Request: {}", String::from_utf8_lossy(&buffer[..]));
		println!("Received login request");
		println!("-----------------");
		println!("generating user_credentials");
		let cre_re = Regex::new("username=([^&]*).*&password=([^&]*)").unwrap(); // benelli.dev
        println!("{:?}", request);
		let cre_caps = cre_re.captures(&request).unwrap();
		let username = cre_caps.get(1).unwrap().as_str();
		let pw = cre_caps.get(2).unwrap().as_str();
		//println!("username: {}, pw: {} ", username, pw);
		
		//let my_str = "&email=userb@user.com&password=User1234";
		let my_str = format!("&email={}&password={}", username, pw);
		println!("Try login");
		let wr = login_to_target_service(my_str.as_str());
        let contents = String::from_utf8_lossy(&wr).to_string();
		println!("[+] Successfull login, returning page but ...");
		/*
		println!("[->] ... replacing urls");

		let re = Regex::new("(?:(?:ht|f)tp(?:s?)://|~/|/)?test.benelli.dev").unwrap(); 
		//let replaced_body = re.captures(&body_new).unwrap();
		let contents = re.replace_all(&contents, "localhost:8000/targetservice").to_string();
		//println!("{:?}",replaced_body);
		//println!("{}", String::from_utf8_lossy(&writer));
		println!("[<-] replacement done");
		*/
		("HTTP/1.1 200 OK", contents)
    } else {
		let (other_status_line, filename) = if buffer.starts_with(get) {
			("HTTP/1.1 200 OK", "hello.html")
		} else {
			("HTTP/1.1 404 NOT FOUND", "404.html")
		};
		let html_base_dir = "html";
		let path = format!("{}/{}", html_base_dir, filename);
		let contents = io::read_to_string(&path).unwrap();
		(other_status_line, contents)
    };
	let response = format!(
        "{}\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        contents.len(),
        contents
    );

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}

pub fn login_to_target_service(cre: &str) -> Vec<u8> {
	//println!("{}" ,cre);
	/*
	let hostname = "test.benelli.dev";
    let port = 443;
    let hostname = format!("https://{}:{}", hostname, port);
    let c_hostname = CString::new(hostname.to_string()).unwrap();
	let c_hostname = c_hostname.as_ptr();
	
	if c_hostname.is_null() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let hostname = CStr::from_ptr(c_hostname).to_str();
    let hostname = hostname.expect("Failed to recover hostname");

    //Parse uri and assign it to variable `addr`
    let addr: Uri = hostname.parse().unwrap();
	*/

	let addr: Uri = "https://test.benelli.dev:443/login".parse().unwrap();

    //Construct a domain:ip string for tcp connection
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.port().unwrap());

    //Connect to remote host
    let stream = TcpStream::connect(conn_addr).unwrap();
	/*
	let addr: Uri = "https://abo-digital.tagesanzeiger.ch/identity-service/auth/authorize?source_client=web&response_type=token&redirect_uri=https://www.tagesanzeiger.ch/".parse().unwrap();
	let stream = TcpStream::connect((addr.host().unwrap(), addr.corr_port())).unwrap();
	
	*/
    //Open secure connection over TlsStream, because of `addr` (https)
    let mut stream = tls::Config::default()
        .connect(addr.host().unwrap_or(""), stream)
        .unwrap();

    //Container for response's body
    let mut writer = Vec::new();

    //Add header `Connection: Close`
    let response = RequestBuilder::new(&addr)
        .header("Connection", "Keep-Alive")
        .send(&mut stream, &mut writer)
        .unwrap();

	let body_res = String::from_utf8_lossy(&writer);
	let re = Regex::new("<meta.*name=\"csrf-token\".*content=\"(.*)\".*>").unwrap(); // benelli.dev
	//let re = Regex::new("name=\"csrf_token\".*value=\"(.*)\".*>").unwrap(); // tagesanzeiger.ch

    //println!("Status: {} {}", response.status_code(), response.reason());
	let caps = re.captures(&body_res).unwrap();
	let token = caps.get(1).unwrap().as_str();
	//println!("csrf-token: {:?}", token);
	let mut body_str = String::from("_token=");
	body_str += token;
	//let credentials = "&email=userb@user.com&password=User1234";
	//body_str+=credentials;
	body_str+=cre;
	//println!("{}", body_str);
	//println!("headers: {}", response.headers());
	//let cookie_re = Regex::new("Set-Cookie: (.*?)").unwrap();
	let set_cookies = response.headers().get("Set-Cookie").unwrap();
	//println!("{:?}", set_cookies);
	//let headers = String::from(response.headers().unwrap());
	/*
	for cookie_cap in cookie_re.captures_iter(response.headers()) {
		println!("test: {:?}", cookie_cap);
	}
	*/

	let addr: Uri = "https://test.benelli.dev/login_with_visitor".parse().unwrap();
	//let addr: Uri = "https://httpbin.org/post".parse().unwrap();
	let mut writer = Vec::new();
	let body = body_str.as_bytes();


    let response2 = RequestBuilder::new(&addr)
		.method(Method::POST)
		.body(body)
		.header("content-type", "application/x-www-form-urlencoded")
		.header("Content-Length", &body.len())
		.header("Cookie", set_cookies)
        .header("Connection", "Keep-Alive")
        .send(&mut stream, &mut writer)
        .unwrap();
	
	//println!("Status: {} {}", response2.status_code(), response2.reason());
	let set_cookies = response2.headers().get("Set-Cookie").unwrap();
	//println!("{:?}", set_cookies);

	//println!("Call executed");
	//println!("{}", String::from_utf8_lossy(&writer));
	//println!("{}", response2.headers());
	const REDIRECT_CODE: StatusCode = StatusCode::new(302);	
	//println!("Comparing: {} and {}", REDIRECT_CODE, response2.status_code());	
	let addr: Uri = if response2.status_code() == REDIRECT_CODE {
		response2.headers().get("Location").unwrap().parse().unwrap()
	} else { addr };
	let mut writer = Vec::new();
	//Add header `Connection: Close`
	//println!("{}", addr);
	println!("[+] Last Call, as logged in User");
	let _response = RequestBuilder::new(&addr)
		.header("Connection", "Close")
		.header("Cookie", set_cookies)
		.send(&mut stream, &mut writer)
		.unwrap();

	
	//println!("{}", String::from_utf8_lossy(&writer));
	writer
}