use capnp_rpc::{pry, rpc_twoparty_capnp, twoparty, RpcSystem};
use tokio::task::{self, JoinHandle};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use std::{sync::{Arc, Mutex}, io::{Error, ErrorKind}};
// use bdk_chain::{bitcoin, BlockId};
use bdk_chain::{
    self,
    bitcoin::{self, consensus::Decodable, hashes::Hash, address::{Address, NetworkUnchecked, AddressType}},
    keychain_txout::KeychainTxOutIndex,
    local_chain::LocalChain,
    miniscript::{Descriptor, DescriptorPublicKey},
    BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, Merge,
};
use crate::chain_capnp::{chain::Client as ChainClient};
use crate::init_capnp::init::Client as InitClient;
use crate::proxy_capnp::thread::Client as ThreadClient;
use crate::BdkWallet;
use std::str::FromStr;

pub struct RpcInterface {
    pub rpc_handle: JoinHandle<Result<(), capnp::Error>>,
    pub disconnector: capnp_rpc::Disconnector<twoparty::VatId>,
    pub thread: ThreadClient,
    pub chain_interface: ChainClient,
}


impl RpcInterface {
    /// Create an IPC interface by performing the handshake with Bitcoin Core on the provided stream.
    pub async fn new(stream: tokio::net::UnixStream) -> Result<Self, Box<dyn std::error::Error>> {
        let (reader, writer) = stream.into_split();
        let network = Box::new(twoparty::VatNetwork::new(
            reader.compat(),
            writer.compat_write(),
            rpc_twoparty_capnp::Side::Client,
            Default::default(),
        ));

        let mut rpc = RpcSystem::new(network, None);
        let init_interface: InitClient = rpc.bootstrap(rpc_twoparty_capnp::Side::Server);
        let disconnector = rpc.get_disconnector();
        let rpc_handle = task::spawn_local(rpc);

        let mk_init_req = init_interface.construct_request();
        let response = mk_init_req.send().promise.await?;
        let thread_map = response.get()?.get_thread_map()?;

        let mk_thread_req = thread_map.make_thread_request();
        let response = mk_thread_req.send().promise.await?;
        let thread = response.get()?.get_result()?;

        let mut mk_chain_req = init_interface.make_chain_request();
        mk_chain_req.get().get_context()?.set_thread(thread.clone());
        let response = mk_chain_req.send().promise.await?;
        let chain_interface = response.get()?.get_result()?;

        // Send an init message to Core to exercise the interface.
        let mut mk_mess_req = chain_interface.init_message_request();
        mk_mess_req.get().get_context()?.set_thread(thread.clone());
        mk_mess_req
            .get()
            .set_message("Oxydation of the Bitcoin Core wallet in progress..");
        let _ = mk_mess_req.send().promise.await?;

        Ok(Self {
            rpc_handle,
            thread,
            chain_interface,
            disconnector,
        })
    }
    pub async fn find_coins_request(&self, outpoints: Vec<bitcoin::OutPoint>) -> Vec<(bitcoin::OutPoint, bitcoin::TxOut)> {
        println!("DEBUG: Requesting coin information for {} outpoints", outpoints.len());
        let mut find_coins_req = self.chain_interface.find_coins_request();
        
        // Set the thread context
        find_coins_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        
        // Initialize the coins list with the outpoints
        let mut coins_list = find_coins_req.get().init_coins(outpoints.len() as u32);
        for (i, outpoint) in outpoints.iter().enumerate() {
            let mut pair = coins_list.reborrow().get(i as u32);
            
            // Serialize the outpoint to binary data
            let mut outpoint_data = Vec::new();
            outpoint_data.extend_from_slice(&outpoint.txid[..]);
            outpoint_data.extend_from_slice(&outpoint.vout.to_le_bytes());
            // let data_reader = capnp::data::Reader::FromPointer(*outpoint_data);
            pair.reborrow().set_key(&outpoint_data[..]);
            
            // Set the key (outpoint)
            // pair.reborrow().set_key(&outpoint_data.as_ref());
            // pair.reborrow().set_key(data_reader);
            
            // Initialize the value (will be filled by Bitcoin Core)
            pair.get_value().unwrap();
        }
        
        // Send the request and process the response
        let response = find_coins_req.send().promise.await.unwrap();
        let result_data = response.get().unwrap();
        let coins_result = result_data.get_coins().unwrap();
        
        let mut result_coins = Vec::with_capacity(coins_result.len() as usize);
        
        for i in 0..coins_result.len() {
            let pair = coins_result.get(i);
            
            // Get the outpoint from the key
            let outpoint_bytes = pair.get_key().unwrap();
            if outpoint_bytes.len() < 36 {
                println!("WARNING: Invalid outpoint data received");
                continue;
            }
            
            let txid = bitcoin::Txid::from_slice(&outpoint_bytes[0..32])
                .expect("Core must provide valid txids");
            let vout = u32::from_le_bytes([
                outpoint_bytes[32], 
                outpoint_bytes[33], 
                outpoint_bytes[34], 
                outpoint_bytes[35]
            ]);
            let outpoint = bitcoin::OutPoint { txid, vout };
            
            // Get the coin data from the value
            let coin_bytes = pair.get_value().unwrap();
            if coin_bytes.is_empty() {
                println!("DEBUG: Empty coin for outpoint {}:{} (not found/spent)", txid, vout);
                continue;
            }
            
            // Parse the coin data according to Bitcoin Core serialization format
            
            // 1. Parse the height and coinbase flag (VARINT encoding: height * 2 + coinbase)
            // Note: This is a simplified approach. A proper VARINT decoder would be more robust
            let mut height_code = 0u32;
            let mut offset = 0;
            let mut shift = 0;
            
            while offset < coin_bytes.len() {
                let byte = coin_bytes[offset];
                height_code |= ((byte & 0x7f) as u32) << shift;
                offset += 1;
                
                if byte & 0x80 == 0 {
                    break; // End of VARINT
                }
                shift += 7;
            }
            
            let height = height_code >> 1; // Divide by 2
            let is_coinbase = (height_code & 1) != 0;
            
            // 2. Parse the amount (next 8 bytes after VARINT)
            if offset + 8 > coin_bytes.len() {
                println!("WARNING: Insufficient data for amount in coin");
                continue;
            }
            
            let value = u64::from_le_bytes([
                coin_bytes[offset], coin_bytes[offset+1], coin_bytes[offset+2], coin_bytes[offset+3],
                coin_bytes[offset+4], coin_bytes[offset+5], coin_bytes[offset+6], coin_bytes[offset+7],
            ]);
            offset += 8;
            
            // 3. Parse the script (remaining bytes)
            if offset >= coin_bytes.len() {
                println!("WARNING: No script data in coin");
                continue;
            }
            
            // Getting the script data - first byte might be length prefix in some serialization formats
            let script_data = &coin_bytes[offset..];
            let script = bitcoin::ScriptBuf::from(script_data.to_vec());
            
            // Create TxOut with parsed value and script
            let txout = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: script,
            };
            
            println!("Found coin: {}:{} - {} satoshis (height: {}, coinbase: {})",
                     txid, vout, value, height, is_coinbase);
            
            result_coins.push((outpoint, txout));
        }
        
        println!("Found {} coins in mempool/UTXO set", result_coins.len());
        result_coins
    }
    // Helper functions for serialization
  
    pub async fn get_tip(&self) -> BlockId {
        println!("DEBUG: Requesting tip");
        let mut height_req = self.chain_interface.get_height_request();
        height_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        let response = height_req.send().promise.await.unwrap();
        let height_i32 = response.get().unwrap().get_result();
        let height = height_i32.try_into().expect("Height is never negative.");
        let mut hash_req = self.chain_interface.get_block_hash_request();
        hash_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        hash_req.get().set_height(height_i32);
        let response = hash_req.send().promise.await.unwrap();
        let hash = bitcoin::BlockHash::from_slice(response.get().unwrap().get_result().unwrap())
            .expect("Core must be serving valid hashes.");

        BlockId { height, hash }
    }

    // NOTE: not entirely correct, but good enough for the purpose of this PoC
    pub async fn is_in_best_chain(
        &self,
        node_tip_hash: &bitcoin::BlockHash,
        ancestor: &bitcoin::BlockHash,
    ) -> bool {
        let mut find_req = self.chain_interface.find_ancestor_by_hash_request();
        find_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        find_req.get().set_block_hash(node_tip_hash.as_ref());
        find_req.get().set_ancestor_hash(ancestor.as_ref());
        let response = find_req.send().promise.await.unwrap();
        response.get().unwrap().get_result()
    }

    pub async fn has_blocks(&self, node_tip_hash: &bitcoin::BlockHash, start_height: i32) -> bool {
        let mut has_blocks_req = self.chain_interface.has_blocks_request();
        has_blocks_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        has_blocks_req.get().set_block_hash(node_tip_hash.as_ref());
        has_blocks_req.get().set_min_height(start_height);
        let response = has_blocks_req.send().promise.await.unwrap();
        response.get().unwrap().get_result()
    }


    pub async fn get_block(
        &self,
        node_tip_hash: &bitcoin::BlockHash,
        height: i32,
    ) -> bitcoin::Block {
        println!("DEBUG: Requesting block at height {}", height);
        let mut find_req = self.chain_interface.find_ancestor_by_height_request();
        find_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        find_req.get().set_block_hash(node_tip_hash.as_ref());
        find_req.get().set_ancestor_height(height);
        find_req.get().get_ancestor().unwrap().set_want_data(true);
        let response = find_req.send().promise.await.unwrap();
        bitcoin::Block::consensus_decode(
            &mut response
                .get()
                .unwrap()
                .get_ancestor()
                .unwrap()
                .get_data()
                .unwrap(),
        )
        .expect("Core must provide valid blocks")
    }

    pub async fn common_ancestor(
        &self,
        node_tip_hash: &bitcoin::BlockHash,
        wallet_tip_hash: &bitcoin::BlockHash,
    ) -> Option<BlockId> {
        let mut find_req = self.chain_interface.find_common_ancestor_request();
        find_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        find_req.get().set_block_hash1(node_tip_hash.as_ref());
        find_req.get().set_block_hash1(wallet_tip_hash.as_ref());
        find_req.get().get_ancestor().unwrap().set_want_height(true);
        find_req.get().get_ancestor().unwrap().set_want_hash(true);
        let response = find_req.send().promise.await.unwrap();
        let response = response.get().unwrap();
        let ancestor = response.get_ancestor().unwrap();
        if !ancestor.get_found() {
            return None;
        }
        let height = ancestor
            .get_height()
            .try_into()
            .expect("Can't be negative.");
        let hash = bitcoin::BlockHash::from_slice(ancestor.get_hash().unwrap())
            .expect("Core must provide valid blocks");
        Some(BlockId { height, hash })
    }

    pub async fn show_progress(&self, title: &str, progress: i32, resume_possible: bool) {
        let mut mk_mess_req = self.chain_interface.show_progress_request();
        mk_mess_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        mk_mess_req.get().set_title(title);
        mk_mess_req.get().set_progress(progress);
        mk_mess_req.get().set_resume_possible(resume_possible);
        let _ = mk_mess_req.send().promise.await.unwrap();
    }

    pub async fn register_notifications(&self, wallet: Arc<Mutex<BdkWallet>>) {
        let notif_handler = capnp_rpc::new_client(wallet);
        let mut register_req = self.chain_interface.handle_notifications_request();
        register_req
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
        register_req.get().set_notifications(notif_handler);
        let _ = register_req.send().promise.await.unwrap();
    }

    pub async fn disconnect(self) -> Result<(), capnp::Error> {
        self.disconnector.await.unwrap();
        self.rpc_handle.await.unwrap()
    }

    pub async fn create_and_broadcast_transaction(&self, utxos: Vec<bitcoin::OutPoint>, recipient_address: &str, amount: u64) -> Result<bitcoin::Txid, Box<dyn std::error::Error>> {
        // Create a transaction
        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,  // Use Version::ONE instead of raw integer
            lock_time: bitcoin::absolute::LockTime::ZERO, // Use the correct LockTime type
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey: {
                    // First try to parse as a regular address
                    if let Ok(addr) = Address::from_str(recipient_address) {
                        let checked_addr = addr.require_network(bitcoin::Network::Bitcoin)?;
                        match checked_addr.address_type() {
                            Some(AddressType::P2pkh) => checked_addr.script_pubkey(),
                            Some(AddressType::P2sh) => checked_addr.script_pubkey(),
                            Some(AddressType::P2wpkh) => checked_addr.script_pubkey(),
                            Some(AddressType::P2wsh) => checked_addr.script_pubkey(),
                            Some(AddressType::P2tr) => checked_addr.script_pubkey(),
                            Some(_) => return Err("Unknown address type".into()),
                            None => return Err("Unsupported address type".into()),
                        }
                    } else {
                        // If not a valid address string, try to parse as a script
                        let script = bitcoin::ScriptBuf::from_hex(recipient_address)?;
                        Address::from_script(&script, bitcoin::Network::Bitcoin)?.script_pubkey()
                    }
                },
            }],
        };

        // Add inputs from UTXOs
        for utxo in utxos {
            tx.input.push(bitcoin::TxIn {
                previous_output: utxo,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            });
        }

        // Sign the transaction (this is a placeholder, actual signing logic will depend on your wallet setup)
        // tx.sign(&private_keys);
        use bitcoin::consensus::Encodable; 
        // Serialize the transaction
        let mut tx_data = Vec::new();
        tx.consensus_encode(&mut tx_data)?;

        // Broadcast the transaction
        let mut broadcast_req = self.chain_interface.broadcast_transaction_request();
        broadcast_req
        .get()
        .get_context()
        .unwrap()
        .set_thread(self.thread.clone());
        broadcast_req.get().set_tx(&tx_data);
        let response = broadcast_req.send().promise.await?;

        // Get the transaction ID from the response
        let result = response.get().unwrap().get_result();
        // let txid = bitcoin::Txid::from_slice(txid_bytes)?;
        if result {
            println!("Transaction broadcast successful");
        } else {
            let error = response.get().unwrap().get_error()?;
            println!("Transaction broadcast failed: ");
            return Err(error.to_str()?.into());
        }

        Ok(tx.txid())

    }
}
