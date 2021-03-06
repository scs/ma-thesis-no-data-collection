// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![allow(dead_code)]

#[cfg(not(target_env = "sgx"))]
use sgx_tstd as std;

use std::untrusted::fs;
use std::vec::Vec;
use std::io::{self, Write, Read, BufReader};
use std::sync::Arc;
use std::collections::HashMap;
use std::net;
use std::net::Shutdown;

use crate::mixnet::{BASE_URL, HTTPS_BASE_URL};
use crate::mixnet::router;
use http_req::uri::Uri;


#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub version: Option<u8>,
    pub headers: HashMap<String, String>,
    pub target_uri: Option<Uri>,
    pub body: HashMap<String, String>,
    pub target: Option<String>,
    pub zattoo_cdn: Option<String>,
    pub uuid: Option<String>,
    pub inital_auth_req: bool,
    pub regexes: Vec<Regex>,
    pub t_id: u64
}
use regex::Regex;

extern crate webpki;
extern crate rustls;
extern crate mio;
extern crate sgx_types;

use rustls::{Session, NoClientAuth};
use mio::net::{TcpListener, TcpStream};
use codec::{alloc::string::String};
use std::{
	string::ToString,
};
use urlencoding::decode;
//use httparse::*;
use threadpool::ThreadPool;
use std::boxed::Box;

use std::sync::SgxMutex as Mutex;
use std::time::{Duration, Instant};

lazy_static!{
    static ref PROXY_TARGET_REGEX: Regex = Regex::new("proxy-target=([^;]*)").unwrap();
    static ref PROXY_UUID_REGEX: Regex = Regex::new("proxy-uuid=([^;]*)").unwrap();
    static ref PROXY_ZATTOO_CDN_REGEX: Regex = Regex::new("proxy-zattoo-cdn=([^;]*)").unwrap();

    static ref POLL: Arc<mio::Poll> = Arc::new(mio::Poll::new().unwrap());
}

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);
//use async_std::task;
//Router
//static mut ROUTER: router::Router<()> = router::load_all_routes();

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward(u16),
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Arc<Mutex<Connection>>>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,
}

impl TlsServer {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
            
        }
    }

    fn accept(&mut self) -> bool {
        match self.server.accept() {
            Ok((socket, addr)) => {
                debug!("Accepting new connection from {:?}", addr);

                let tls_session = rustls::ServerSession::new(&self.tls_config);
                let mode = self.mode.clone();

                let token = mio::Token(self.next_id);
                self.next_id += 1;

                self.connections.insert(token, Arc::new(Mutex::new(Connection::new(socket, token, mode, tls_session))));
                let mut con = self.connections[&token].lock().unwrap();
                con.register();
                drop(con);
                true
            }
            Err(e) => {
                println!("encountered error while accepting connection; err={:?}", e);
                false
            }
        }
    }

    fn conn_event(&mut self, event: &mio::event::Event) {
        let token = event.token();
        if self.connections.contains_key(&token) {
            let mut con =  self.connections
                .get_mut(&token)
                .unwrap().lock().unwrap();
            
                con.ready(event);

            if con.is_closed() {
                drop(con);
                self.connections.remove(&token);
            } else {
                drop(con);
            }
            
        }
    }

    fn run(&mut self, max_conn: u32){
        POLL.register(&self.server,
            LISTENER,
            mio::Ready::readable(),
            mio::PollOpt::level())
            .unwrap();
        let mut events = mio::Events::with_capacity(512);

        println!("[+] Server in Enclave is running now on: {}", HTTPS_BASE_URL);
        let pool = ThreadPool::new(6);
        //println!("num_cs {}",num_tcs);
        'outer: loop {
            POLL.poll(&mut events, None)
            .unwrap();
            for event in events.iter() {
                match event.token() {
                    LISTENER => {
                        if self.connections.len() as u32 == max_conn {
                            println!("Capacity max...");
                            continue;
                        }
                        if !self.accept() {
                            break 'outer;
                        }
                    }
                    _  => {
                        let token = event.token().clone();
                        if self.connections.contains_key(&token) {
                            let mut con =  self.connections
                                .get_mut(&token)
                                .unwrap();
                                let con_c = Arc::clone(&con);
                                pool.execute(move ||{
                                    let mut con_t = con_c.lock().unwrap();
                                    con_t.ready(&event);
                                    drop(con_t);
                                });    
                            let con = con.lock().unwrap();
                            if con.is_closed() {
                                drop(con);
                                self.connections.remove(&token);
                            } else {
                                drop(con);
                            }
                        }
                        //self.conn_event(&tok);
                        //let con = self.connections.get(&tok);
                        //self.tpool.execute( move || {self.conn_event(&event);});
                        
                    }
                }
            }
        }
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_session: rustls::ServerSession,
    back: Option<TcpStream>,
    sent_http_response: bool,
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(&net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl Connection {
    fn new(socket: TcpStream,
           token: mio::Token,
           mode: ServerMode,
           tls_session: rustls::ServerSession)
           -> Connection {
        let back = open_back(&mode); // If Mode not Forward = None
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls_session,
            back,
            sent_http_response: false,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.readiness().is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read(); // If Mode::Forward -> instant return
        }

        if ev.readiness().is_writable() {
            self.do_tls_write();
        }
        if self.closing {
            let _ = self.socket.shutdown(Shutdown::Both); // socket teardown
            self.close_back(); // If Mode::Forward -> close this
            self.closed = true;
        } else {
            self.reregister();
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(Shutdown::Both).unwrap();
        }
        self.back = None;
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let io::ErrorKind::WouldBlock = err.kind() {
                return;
            }

            error!("read error {:?}", err);
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            debug!("eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            error!("cannot process packet: {:?}", processed);
            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        let mut buf = Vec::new();
        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            error!("plaintext read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        if !buf.is_empty() {
            debug!("plaintext read {:?}", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls_session.write_all(&buf[..len]).unwrap();
            }
            None => {}
        };
    }

    /// Process some amount of received plaintext.
    /// If we are here, we successfully 1. read some TLS data (do_tls_read) 2. and stored it in buf (try_plain_read)
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_session.write_all(buf).unwrap();
            }
            ServerMode::Http => { // TODO: put in here behaviour after a Request
                /*
                let before_time = std::time::Instant::now();
                println!{"Connection: {:?} starting req", self.token};
                self.handle_request(buf);
                println!{"Connection: {:?} finished req after {:#?}", self.token, before_time.elapsed()};

                //self.send_http_response_once();*/

                self.handle_request(buf);
            }
            ServerMode::Forward(_) => {
                self.back.as_mut().unwrap().write_all(buf).unwrap();
            }
        }
    }

    fn create_request_body(&mut self, buf: &[u8], body_offset: usize, body_to_fill: &mut HashMap<String, String>) {
        if body_offset < buf.len(){ // only Converting if there is something to do
            let body_slice = &buf[body_offset..];
            let body_str = String::from_utf8(body_slice.to_vec()).expect("Body Encoding wrong");
            let it = body_str.split("&");
            for i in it {
                //println!("{:?}", i);
                let kv:Vec<&str> = i.split("=").collect();
                if kv.len() == 2 {
                    let k = kv[0].to_string();
                    let v = String::from(decode(kv[1]).unwrap()); 
                    //println!("DEBUG: VALUE: {}", v);
                    if v!=String::from(""){
                        body_to_fill.insert(k,v);
                    }
                }
            }
        }
    }

    fn parse_request<'a>(&'a mut self, buf: &'a [u8])->Result<Request, String>{
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let res = req.parse(buf);
        match res {
            Ok(status)=> {
                if status.is_complete(){
                    let mut parsed_req = Request {
                        method: req.method,
                        path: req.path,
                        version: req.version,
                        headers: HashMap::<String,String>::new(),
                        target_uri: None,
                        body: HashMap::<String,String>::new(),
                        target: None,
                        zattoo_cdn: None,
                        uuid: None,
                        inital_auth_req: false,
                        regexes: Vec::new(),
                        t_id: std::thread::current().id().as_u64().get()
                    };
                    for i in 0..req.headers.len() { // Adding Headers to Hasmap
                        let h = req.headers[i];
                        let value =  String::from_utf8(h.value.to_vec()).expect("Header error");
                        parsed_req.headers.insert(h.name.to_string().to_lowercase(), value);
                    }
                    //Debug:
                    //println!("Debug valide-headers: {:?}", parsed_req.headers);
                    /*
                    if req.path.unwrap().contains("validate-session"){
                        println!("Debug valide-headers: {:?}", parsed_req.headers);
                        println!("Debug valide-method: {:?}", parsed_req.method);
                        println!("Debug valide-path: {:?}", parsed_req.path);

                    }*/
                    if parsed_req.headers.contains_key("cookie") { // Getting Target adn UUID from Cookie
                        let cookie = parsed_req.headers.get("cookie").unwrap();
                        let target = match PROXY_TARGET_REGEX.captures(cookie.as_str()) {
                            Some(res) => Some(String::from(res.get(1).unwrap().as_str())),
                            _ => None,
                        };
                        parsed_req.target = target;
                        let uuid = match PROXY_UUID_REGEX.captures(cookie.as_str()) {
                            Some(res) => Some(String::from(res.get(1).unwrap().as_str())),
                            _ => None,
                        };
                        parsed_req.uuid = uuid;
                        let zattoo_cdn = match PROXY_ZATTOO_CDN_REGEX.captures(cookie.as_str()) {
                            Some(res) => Some(String::from(res.get(1).unwrap().as_str())),
                            _ => None,
                        };
                        parsed_req.zattoo_cdn = zattoo_cdn;
                        //parsed_req.auth = cookie.contains("proxy-auth")
                    }
                    let method = parsed_req.method.unwrap();
                    if method.eq("POST") | method.eq("PUT") | method.eq("PATCH"){
                        self.create_request_body(&buf, status.unwrap(), &mut parsed_req.body);
                    }
                    //remove post and initial body then check if cookie is contained
                    parsed_req.inital_auth_req = if parsed_req.body.contains_key("proxy_login"){
                        parsed_req.method = Some("GET"); // cleanup
                        parsed_req.body.remove("proxy_login");
                        parsed_req.body.contains_key("cookie")
                    } else {false};
                
                    Ok(parsed_req)
                } else {
                    Err(String::from("Request was incomplete"))
                }
            },
            _ => {
                Err(String::from("Couldn't parse the Request"))
            }
        }
        //let res = req.parse(buf).unwrap();
    }

    fn handle_request(&mut self, buf: &[u8]){
        let res = match self.parse_request(&buf) {
            Ok(req) => {
                //println!("Debug: {:?}", req);
                match req.path {
                    Some(ref path) => {
                        router::handle_routes(path, req).unwrap()
                    },
                    None => {
                        router::not_found().unwrap()            
                    }
                }
            },
            Err(m) => {
                debug!("[Enclave-TLS-Server-Parsing]: {}", m);
                router::internal_server_error().unwrap() 
            } 
        };
        self.send_response(res);
        //self.tls_session.send_close_notify();
    }

    fn send_response(&mut self, response: Vec<u8>){
        self.tls_session
            .write_all(&response)
            .unwrap();
    }

    fn send_http_response_once(&mut self) {
        let response = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from server\r\n";
        if !self.sent_http_response {
            self.tls_session
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tls_session.send_close_notify();
            println!("Returned to client successfully!");
        } else {
            let my_str = "&email=userb@user.com&password=User1234";
            let wr = crate::mixnet::test_http::login_to_target_service(my_str);
            let contents = String::from_utf8_lossy(&wr).to_string();
            let status_line = "HTTP/1.1 200 OK";
            let response = format!(
                "{}\r\nContent-Length: {}\r\n\r\n{}",
                status_line,
                contents.len(),
                contents
            );
            self.tls_session.write_all(response.as_bytes()).unwrap();
            self.tls_session.send_close_notify();
            println!("closed everything");
        }
    }

    fn do_tls_write(&mut self) {
        let rc = self.tls_session.write_tls(&mut self.socket);
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&self) {
 
        POLL.register(&self.socket,
                      self.token,
                      self.event_set(),
                      mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
        if self.back.is_some() {
            POLL.register(self.back.as_ref().unwrap(),
                          self.token,
                          mio::Ready::readable(),
                          mio::PollOpt::level() | mio::PollOpt::oneshot())
                .unwrap();
        }
    }

    fn reregister(&self) {
        POLL.reregister(&self.socket,
                        self.token,
                        self.event_set(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
        if self.back.is_some() {
            POLL.reregister(self.back.as_ref().unwrap(),
                            self.token,
                            mio::Ready::readable(),
                            mio::PollOpt::level() | mio::PollOpt::oneshot())
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)
            .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)
            .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn make_config(cert: &str, key: &str) -> Arc<rustls::ServerConfig> {

    let mut config = rustls::ServerConfig::new(NoClientAuth::new());

    let certs = load_certs(cert);
    let privkey = load_private_key(key);
    config.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).unwrap();

    Arc::new(config)
}



pub fn prep_server(max_conn: u32) {
    let addr: net::SocketAddr = BASE_URL.parse().unwrap();
    //let cert = "end.fullchain";
    let cert = "localhost.crt"; // TODO: add it to the browser
    //let key = "end.rsa";
    let key = "localhost.key";
    //let mode = ServerMode::Echo;
    let mode = ServerMode::Http;

    let config = make_config(cert, key);

    let listener = TcpListener::bind(&addr).expect("cannot listen on port");
    listener.set_ttl(5).expect("could not set TTL");

    let mut tlsserv = TlsServer::new(listener, mode, config);
    tlsserv.run(max_conn);
}