/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![feature(trait_alias)]
#![crate_name = "enclave_runtime"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(not(feature = "test"))]
use sgx_types::size_t;


use crate::{
	error::{Error, Result},
	global_components::{EnclaveValidatorAccessor, GLOBAL_DISPATCHER_COMPONENT},
	ocall::OcallApi,
	rpc::worker_api_direct::{public_api_rpc_handler, side_chain_io_handler},
	utils::{hash_from_slice, utf8_str_from_raw, write_slice_and_whitespace_pad, DecodeRaw},
};
use base58::ToBase58;
use codec::{alloc::string::String, Decode, Encode};
use ita_stf::{Getter, ShardIdentifier, Stf};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::{immediate_dispatcher::ImmediateDispatcher, DispatchBlockImport},
	block_importer::ParentchainBlockImporter,
	indirect_calls_executor::IndirectCallsExecutor,
	light_client::{
		concurrent_access::ValidatorAccess, BlockNumberOps, LightClientState, NumberFor,
	},
};
use itc_tls_websocket_server::{connection::TungsteniteWsConnection, run_ws_server};
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_extrinsics_factory::ExtrinsicsFactory;
use itp_nonce_cache::{MutateNonce, Nonce, GLOBAL_NONCE_CACHE};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_settings::node::{
	REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION, RUNTIME_TRANSACTION_VERSION, TEEREX_MODULE,
};
use itp_sgx_crypto::{aes, ed25519, rsa3072, Ed25519Seal, Rsa3072Seal};
use itp_sgx_io as io;
use itp_sgx_io::SealedIO;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::{
	handle_state::HandleState, query_shard_state::QueryShardState, GlobalFileStateHandler,
};
use itp_storage::StorageProof;
use itp_types::{Block, Header, SignedBlock};
use its_sidechain::top_pool_rpc_author::global_author_container::GLOBAL_RPC_AUTHOR_COMPONENT;
use log::*;
use sgx_types::sgx_status_t;
use sp_core::{crypto::Pair, H256};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::traits::Block as BlockT;
use std::{slice, sync::Arc, vec::Vec};
use substrate_api_client::compose_extrinsic_offline;

use std::io::Write;

//use itc_rest_client::{http_client::HttpClient, rest_client::RestClient, RestGet, RestPath};


use http_req::{request::{RequestBuilder,Method}, tls, uri::Uri, response::StatusCode, response};
//use std::ffi::CStr;
//use std::ffi::CString;
use std::net::TcpStream;
use std::net::TcpListener;
//use std::os::raw::c_char;
//use std::prelude::v1::*;
use regex::Regex;
//from tutorial (doc.rust.lang.org/book)
use std::io::prelude::*;
//use std::fs;

mod attestation;
mod global_components;
mod ipfs;
mod ocall;
mod utils;

pub mod cert;
pub mod error;
pub mod rpc;
mod sync;
pub mod tls_ra;
pub mod top_pool_execution;

#[cfg(feature = "test")]
pub mod test;

#[cfg(feature = "test")]
pub mod tests;

// this is a 'dummy' for production mode
#[cfg(not(feature = "test"))]
#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	unreachable!("Tests are not available when compiled in production mode.")
}

pub const CERTEXPIRYDAYS: i64 = 90i64;

pub type Hash = sp_core::H256;
pub type AuthorityPair = sp_core::ed25519::Pair;

#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
	// initialize the logging environment in the enclave
	env_logger::init();

	if let Err(e) = ed25519::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let signer = match Ed25519Seal::unseal().map_err(Error::Crypto) {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	info!("[Enclave initialized] Ed25519 prim raw : {:?}", signer.public().0);

	if let Err(e) = rsa3072::create_sealed_if_absent() {
		return e.into()
	}

	// create the aes key that is used for state encryption such that a key is always present in tests.
	// It will be overwritten anyway if mutual remote attastation is performed with the primary worker
	if let Err(e) = aes::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let state_handler = GlobalFileStateHandler;

	// for debug purposes, list shards. no problem to panic if fails
	let shards = state_handler.list_shards().unwrap();
	debug!("found the following {} shards on disk:", shards.len());
	for s in shards {
		debug!("{}", s.encode().to_base58())
	}
	//shards.into_iter().map(|s| debug!("{}", s.encode().to_base58()));

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
	pubkey: *mut u8,
	pubkey_size: u32,
) -> sgx_status_t {
	let rsa_pubkey = match Rsa3072Seal::unseal_pubkey() {
		Ok(key) => key,
		Err(e) => return e.into(),
	};

	let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
		Ok(k) => k,
		Err(x) => {
			println!("[Enclave] can't serialize rsa_pubkey {:?} {}", rsa_pubkey, x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	write_slice_and_whitespace_pad(pubkey_slice, rsa_pubkey_json.as_bytes().to_vec());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {
	if let Err(e) = ed25519::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let signer = match Ed25519Seal::unseal().map_err(Error::Crypto) {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(&signer.public());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn set_nonce(nonce: *const u32) -> sgx_status_t {
	log::info!("[Ecall Set Nonce] Setting the nonce of the enclave to: {}", *nonce);

	let mut nonce_lock = match GLOBAL_NONCE_CACHE.load_for_mutation() {
		Ok(l) => l,
		Err(e) => {
			error!("Failed to set nonce in enclave: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	*nonce_lock = Nonce(*nonce);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn mock_register_enclave_xt(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	_nonce: *const u32,
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	let genesis_hash = hash_from_slice(genesis_hash_slice);

	let mut url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let url: String = Decode::decode(&mut url_slice).unwrap();
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	let mre = OcallApi
		.get_mrenclave_of_self()
		.map_or_else(|_| Vec::<u8>::new(), |m| m.m.encode());

	let signer = Ed25519Seal::unseal().unwrap();
	let call = ([TEEREX_MODULE, REGISTER_ENCLAVE], mre, url);

	let nonce_cache = GLOBAL_NONCE_CACHE.clone();
	let mut nonce_lock = nonce_cache.load_for_mutation().expect("Nonce lock poisoning");
	let nonce_value = nonce_lock.0;

	let xt = compose_extrinsic_offline!(
		signer,
		call,
		nonce_value,
		Era::Immortal,
		genesis_hash,
		genesis_hash,
		RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION
	)
	.encode();

	*nonce_lock = Nonce(nonce_value + 1);
	std::mem::drop(nonce_lock);

	write_slice_and_whitespace_pad(extrinsic_slice, xt);
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn hello_world(		
	some_string: *const u8,
	len: usize,
) -> sgx_status_t {
	let str_slice = slice::from_raw_parts(some_string, len);
	let _ = std::io::stdout().write(str_slice);
	println!("{}", &str_slice[0]);
	//let ne = String::from_utf8(str_slice).unwrap();
	let rust_raw_string = "This is a in-Enclave";

	let wor:[u8;4] = [82, 117, 115, 116];
	
	let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

	let mut hello_string = String::from(rust_raw_string);

	for c in wor.iter() { //use str_slice 
		hello_string.push(*c as char);
	}
	hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8").as_str();

	println!("{}", &hello_string);
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn login() -> sgx_status_t {
	println!("[+] Entered Enclave");

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

	let listener = TcpListener::bind("127.0.0.1:8000").unwrap();
	for stream2 in listener.incoming() {
		let stream2 = stream2.unwrap();

		println!("handling connection:");
		handle_connection(stream2);
	}
	println!("[<-] Exiting enclave");
	sgx_status_t::SGX_SUCCESS
}
fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

	let get = b"GET / HTTP/1.1\r\n";
	let post = b"POST /login HTTP/1.1\r\n";

    if buffer.starts_with(get) {
        let contents = io::read_to_string("hello.html").unwrap();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            contents.len(),
            contents
        );

        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    } else if buffer.starts_with(post) {
		println!("Request: {}", String::from_utf8_lossy(&buffer[..]));
		println!("-----------------");
		let wr = login_to_target_service();
        let contents = String::from_utf8_lossy(&wr);

		let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            contents.len(),
            contents
        );
		//println!("response: {:?}", response);
		stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}

fn login_to_target_service() -> Vec<u8> {
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
	let credentials = "&email=userb@userb.com&password=User1234";
	body_str+=credentials;
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

fn create_extrinsics<PB>(
	genesis_hash: HashFor<PB>,
	calls: Vec<OpaqueCall>,
	nonce: &mut u32,
) -> Result<Vec<OpaqueExtrinsic>>
where
	PB: BlockT<Hash = H256>,
{
	// get information for composing the extrinsic
	let signer = Ed25519Seal::unseal()?;
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let extrinsics_buffer: Vec<OpaqueExtrinsic> = calls
		.into_iter()
		.map(|call| {
			let xt = compose_extrinsic_offline!(
				signer.clone(),
				call,
				*nonce,
				Era::Immortal,
				genesis_hash,
				genesis_hash,
				RUNTIME_SPEC_VERSION,
				RUNTIME_TRANSACTION_VERSION
			)
			.encode();
			*nonce += 1;
			xt
		})
		.map(|xt| {
			OpaqueExtrinsic::from_bytes(&xt)
				.expect("A previously encoded extrinsic has valid codec; qed.")
		})
		.collect();

	Ok(extrinsics_buffer)
}

/// this is reduced to the side chain block import RPC interface (i.e. worker-worker communication)
/// the entire rest of the RPC server is run inside the enclave and does not use this e-call function anymore
#[no_mangle]
pub unsafe extern "C" fn call_rpc_methods(
	request: *const u8,
	request_len: u32,
	response: *mut u8,
	response_len: u32,
) -> sgx_status_t {
	let request = match utf8_str_from_raw(request, request_len as usize) {
		Ok(req) => req,
		Err(e) => {
			error!("[SidechainRpc] FFI: Invalid utf8 request: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let res = match side_chain_rpc_int::<Block, _>(request, OcallApi) {
		Ok(res) => res,
		Err(e) => return e.into(),
	};

	let response_slice = slice::from_raw_parts_mut(response, response_len as usize);
	write_slice_and_whitespace_pad(response_slice, res.into_bytes());

	sgx_status_t::SGX_SUCCESS
}

fn side_chain_rpc_int<PB, O>(request: &str, _ocall_api: O) -> Result<String>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	O: EnclaveOnChainOCallApi + 'static,
{
	// Skip sidechain import now until #423 is solved.
	// let _ = EnclaveLock::read_all()?;
	//
	// let header = LightClientSeal::<PB>::unseal()
	// 	.map(|v| v.latest_finalized_header(v.num_relays()).unwrap())?;
	//
	// let importer: BlockImporter<AuthorityPair, PB, _, O, _> = BlockImporter::default();
	//
	// let io = side_chain_io_handler(move |signed_blocks| {
	// 	import_sidechain_blocks::<PB, _, _, _>(signed_blocks, &header, importer.clone(), &ocall_api)
	// });

	let io = side_chain_io_handler::<_, crate::error::Error>(move |signed_blocks| {
		log::info!("[sidechain] Imported blocks: {:?}", signed_blocks);
		Ok(())
	});

	// note: errors are still returned as Option<String>
	Ok(io
		.handle_request_sync(request)
		.unwrap_or_else(|| format!("Empty rpc response for request: {}", request)))
}

#[no_mangle]
pub unsafe extern "C" fn get_state(
	trusted_op: *const u8,
	trusted_op_size: u32,
	shard: *const u8,
	shard_size: u32,
	value: *mut u8,
	value_size: u32,
) -> sgx_status_t {
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
	let mut trusted_op_slice = slice::from_raw_parts(trusted_op, trusted_op_size as usize);
	let value_slice = slice::from_raw_parts_mut(value, value_size as usize);
	let getter = Getter::decode(&mut trusted_op_slice).unwrap();

	if let Getter::trusted(trusted_getter_signed) = getter.clone() {
		debug!("verifying signature of TrustedGetterSigned");
		if let false = trusted_getter_signed.verify_signature() {
			error!("bad signature");
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		}
	}

	let state_handler = GlobalFileStateHandler;

	let mut state = match state_handler.load_initialized(&shard) {
		Ok(s) => s,
		Err(e) => return Error::StfStateHandler(e).into(),
	};

	debug!("calling into STF to get state");
	let value_opt = Stf::get_state(&mut state, getter);

	debug!("returning getter result");
	write_slice_and_whitespace_pad(value_slice, value_opt.encode());

	sgx_status_t::SGX_SUCCESS
}

/// Call this once at worker startup to initialize the TOP pool and direct invocation RPC server
///
/// This function will run the RPC server on the same thread as it is called and will loop there.
/// That means that this function will not return as long as the RPC server is running. The calling
/// code should therefore spawn a new thread when calling this function.
#[no_mangle]
pub unsafe extern "C" fn init_direct_invocation_server(
	server_addr: *const u8,
	server_addr_size: usize,
) -> sgx_status_t {
	let mut server_addr_encoded = slice::from_raw_parts(server_addr, server_addr_size);

	let server_addr = match String::decode(&mut server_addr_encoded) {
		Ok(s) => s,
		Err(e) => {
			error!("Decoding RPC server address failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let watch_extractor = Arc::new(create_determine_watch::<Hash>());
	let connection_registry = Arc::new(ConnectionRegistry::<Hash, TungsteniteWsConnection>::new());

	let rsa_shielding_key = match Rsa3072Seal::unseal() {
		Ok(k) => k,
		Err(e) => {
			error!("Failed to unseal shielding key: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	its_sidechain::top_pool_rpc_author::initializer::initialize_top_pool_rpc_author(
		connection_registry.clone(),
		rsa_shielding_key,
	);

	let rpc_author = match GLOBAL_RPC_AUTHOR_COMPONENT.get() {
		Some(a) => a,
		None => {
			error!("Failed to retrieve global top pool author");
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let io_handler = public_api_rpc_handler(rpc_author);
	let rpc_handler = Arc::new(RpcWsHandler::new(io_handler, watch_extractor, connection_registry));

	run_ws_server(server_addr.as_str(), rpc_handler);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn init_light_client(
	genesis_header: *const u8,
	genesis_header_size: usize,
	authority_list: *const u8,
	authority_list_size: usize,
	authority_proof: *const u8,
	authority_proof_size: usize,
	latest_header: *mut u8,
	latest_header_size: usize,
) -> sgx_status_t {
	info!("Initializing light client!");

	let mut header = slice::from_raw_parts(genesis_header, genesis_header_size);
	let latest_header_slice = slice::from_raw_parts_mut(latest_header, latest_header_size);
	let mut auth = slice::from_raw_parts(authority_list, authority_list_size);
	let mut proof = slice::from_raw_parts(authority_proof, authority_proof_size);

	let header = match Header::decode(&mut header) {
		Ok(h) => h,
		Err(e) => {
			error!("Decoding Header failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let auth = match VersionedAuthorityList::decode(&mut auth) {
		Ok(a) => a,
		Err(e) => {
			error!("Decoding VersionedAuthorityList failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let proof = match StorageProof::decode(&mut proof) {
		Ok(h) => h,
		Err(e) => {
			error!("Decoding Header failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	match itc_parentchain::light_client::io::read_or_init_validator::<Block>(header, auth, proof) {
		Ok(header) => write_slice_and_whitespace_pad(latest_header_slice, header.encode()),
		Err(e) => return e.into(),
	}

	// Initialize the global parentchain block import dispatcher instance.
	let signer = match Ed25519Seal::unseal() {
		Ok(s) => s,
		Err(e) => {
			error!("Error retrieving signer key pair: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let shielding_key = match Rsa3072Seal::unseal() {
		Ok(s) => s,
		Err(e) => {
			error!("Error retrieving shielding key: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let validator_access = Arc::new(EnclaveValidatorAccessor::default());
	let genesis_hash =
		match validator_access.execute_on_validator(|v| v.genesis_hash(v.num_relays())) {
			Ok(g) => g,
			Err(e) => {
				error!("Error retrieving genesis hash: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	let stf_executor =
		Arc::new(StfExecutor::new(Arc::new(OcallApi), Arc::new(GlobalFileStateHandler)));
	let extrinsics_factory =
		Arc::new(ExtrinsicsFactory::new(genesis_hash, signer, GLOBAL_NONCE_CACHE.clone()));
	let indirect_calls_executor =
		Arc::new(IndirectCallsExecutor::new(shielding_key, stf_executor.clone()));
	let parentchain_block_importer = Arc::new(ParentchainBlockImporter::new(
		validator_access,
		Arc::new(OcallApi),
		stf_executor,
		extrinsics_factory,
		indirect_calls_executor,
	));
	let block_import_dispatcher = Arc::new(ImmediateDispatcher::new(parentchain_block_importer));

	GLOBAL_DISPATCHER_COMPONENT.initialize(block_import_dispatcher);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn sync_parentchain(
	blocks_to_sync: *const u8,
	blocks_to_sync_size: usize,
	_nonce: *const u32,
) -> sgx_status_t {
	let blocks_to_sync = match Vec::<SignedBlock>::decode_raw(blocks_to_sync, blocks_to_sync_size) {
		Ok(blocks) => blocks,
		Err(e) => return Error::Codec(e).into(),
	};

	if let Err(e) = sync_parentchain_internal(blocks_to_sync) {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`sync_parentchain`] function to be able to use the handy `?` operator.
///
/// Sync parentchain blocks to the light-client:
/// * iterates over parentchain blocks and scans for relevant extrinsics
/// * validates and execute those extrinsics (containing indirect calls), mutating state
/// * sends `confirm_call` xt's of the executed unshielding calls
/// * sends `confirm_blocks` xt's for every synced parentchain block
fn sync_parentchain_internal(blocks_to_sync: Vec<SignedBlock>) -> Result<()> {
	let block_import_dispatcher =
		GLOBAL_DISPATCHER_COMPONENT.get().ok_or(Error::ComponentNotInitialized)?;

	block_import_dispatcher.dispatch_import(blocks_to_sync).map_err(|e| e.into())
}
