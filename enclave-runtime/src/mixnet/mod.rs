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

pub mod tls_server;
pub mod tls_server_client;
pub mod test_http;
//pub mod proxy;

const BASE_URL: &str = "127.0.0.1:8000"; 
const TARGET_URL: &str = "https://test.benelli.dev";

pub fn my_testing(){
    println!("Testing...");
    //test_http::start_tcp_listener();
    tls_server_client::run_server(128);
}