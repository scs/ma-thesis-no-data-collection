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
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	error::{Error, Result},
	traits::ShieldingCrypto,
};
use derive_more::Display;
use itp_settings::files::RSA3072_SEALED_KEY_FILE;
use itp_sgx_io::{seal, unseal, SealedIO};
use log::*;
use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
use std::{sgxfs::SgxFile, vec::Vec};

#[derive(Copy, Clone, Debug, Display)]
pub struct Rsa3072Seal;

impl SealedIO for Rsa3072Seal {
	type Error = Error;
	type Unsealed = Rsa3072KeyPair;
	fn unseal() -> Result<Self::Unsealed> {
		let raw = unseal(RSA3072_SEALED_KEY_FILE)?;
		let key: Rsa3072KeyPair =
			serde_json::from_slice(&raw).map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(key.into())
	}

	fn seal(unsealed: Rsa3072KeyPair) -> Result<()> {
		let key_json =
			serde_json::to_vec(&unsealed).map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(seal(&key_json, RSA3072_SEALED_KEY_FILE)?)
	}
}

impl ShieldingCrypto for Rsa3072KeyPair {
	type Error = Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut cipher_buffer = Vec::new();
		self.encrypt_buffer(data, &mut cipher_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(cipher_buffer)
	}

	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut decrypted_buffer = Vec::new();
		self.decrypt_buffer(data, &mut decrypted_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(decrypted_buffer)
	}
}

impl Rsa3072Seal {
	pub fn unseal_pubkey() -> Result<Rsa3072PubKey> {
		let pair = Self::unseal()?;
		let pubkey = pair.export_pubkey().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(pubkey)
	}
}

pub fn create_sealed_if_absent() -> Result<()> {
	if SgxFile::open(RSA3072_SEALED_KEY_FILE).is_err() {
		info!("[Enclave] Keyfile not found, creating new! {}", RSA3072_SEALED_KEY_FILE);
		return create_sealed()
	}
	Ok(())
}

pub fn create_sealed() -> Result<()> {
	let rsa_keypair = Rsa3072KeyPair::new().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
	// println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
	Rsa3072Seal::seal(rsa_keypair)
}
