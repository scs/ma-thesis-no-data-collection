/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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
use crate::{error::Error, Enclave, EnclaveResult};
/*
use codec::Encode;
use frame_support::{ensure, sp_runtime::app_crypto::sp_core::H256};
*/
use frame_support::ensure;
use itp_enclave_api_ffi as ffi;
use sgx_types::*;

pub trait MixNet: Send + Sync + 'static {
	fn start_mixnet_server(
		&self
	) -> EnclaveResult<()>;
}

impl MixNet for Enclave {
	fn start_mixnet_server(
		&self
	) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let result = unsafe {
			ffi::start_mixnet_server(
				self.eid,
				&mut retval,
			)
		};
		match result {
			sgx_status_t::SGX_SUCCESS => {},
			_ => {
				println!("[-] ECALL Enclave Failes {}!", result.as_str());
			}
		}
		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
        ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));
		Ok(())
	}
}
