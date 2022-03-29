This repo contains the code base for the master thesis ****Towards User Privacy for Subscription Based Services****.



------------
# Preparation


Before you can start MIXNET, you need a running [integritee-node](https://github.com/integritee-network/integritee-node "integritee-node"). The last version we used was commit 6b3f13932775f71c414d02bed8abac808cb75f73 .

Build the node:
```
# clone and build the node
cd ..
git clone https://github.com/integritee-network/integritee-node.git
cd integritee-node
# Install the correct rust-toolchain 
rustup show
# build the node
cargo build --release
# another 10min
````
After successfully building you can start the node with these example parameters:
`./target/release/integritee-node --dev --tmp --ws-port 9995 --port 30395 --rpc-port 9996`

# MIXNET

Building MIXNET:
```
# clone and build the worker and the client
git clone https://github.com/integritee-network/worker.git
cd worker
# Install the correct rust-toolchain 
rustup show
SGX_MODE=SW make
# this might take 10min+ on a fast machine

```

Preparation:
```
cd ~/bin
# create empty INTEL key files
touch spid.txt key.txt
# fill the files with your Intel SGX development and production (commercial) license
echo "<YOUR SPID>" > bin/spid.txt
echo "<YOUR KEY>" > bin/key.txt
# prepare service
./integritee-service init-shard
./integritee-service shielding-key
./integritee-service signing-key
./integritee-service mrenclave > ~/mrenclave.b58
./integritee-service run --skip-ra
```

After building and preparing MIXNET, you can run it using the following commands:
`cd bin/ && ./integritee-service -p 9995 mixnet`
Make sure that the port is the same as the one you used for --ws-port in the Integritee-node.

To add new services, edit the [services.txt](https://github.com/scs/ma-thesis-no-data-collection/blob/main/bin/ma-thesis/services.txt "services.txt") file and don't forget to add corresponding logic to the [frontend selection](https://github.com/scs/ma-thesis-no-data-collection/blob/main/bin/ma-thesis/html/index.html "frontend selection") as well as necessary adjustments in the [proxy-module](https://github.com/scs/ma-thesis-no-data-collection/blob/main/enclave-runtime/src/mixnet/proxy.rs "proxy-module") (Cookie Validation, special cases etc).
