use capnp_rpc::{pry, rpc_twoparty_capnp, twoparty, RpcSystem};
use tokio::task::{self, JoinHandle};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use std::{sync::{Arc, Mutex}, io::{Error, ErrorKind}};
// use bdk_chain::{bitcoin, BlockId};
use bdk_chain::{
    self,
    bitcoin::{self, consensus::Decodable, hashes::Hash},
    keychain_txout::KeychainTxOutIndex,
    local_chain::LocalChain,
    miniscript::{Descriptor, DescriptorPublicKey},
    BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, Merge,
};
use crate::chain_capnp::{chain::Client as ChainClient};
use crate::init_capnp::init::Client as InitClient;
use crate::proxy_capnp::thread::Client as ThreadClient;
use crate::BdkWallet;

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


    /// The method takes a map of outpoints and populates it with coin information.
    /// In our Rust implementation, we pass a list of outpoints (serialized as binary data)
    /// and receive a list of pairs where each key is an outpoint and each value is a coin.
    // pub async fn find_coins_request(&self, outpoints: Vec<bitcoin::OutPoint>) -> Vec<(bitcoin::OutPoint, bitcoin::TxOut)> {
    //     let mut find_coins_request = self.chain_interface.find_coins_request();

    //     // Set the thread context for the request
    //     find_coins_request
    //         .get()
    //         .get_context()
    //         .unwrap()
    //         .set_thread(self.thread.clone());
        
    //     // Set the outpoints parameter if provided
    //     if !outpoints.is_empty() {
    //         let mut coins_list = find_coins_request.get().init_coins(outpoints.len() as u32);
    //         for (i, outpoint) in outpoints.iter().enumerate() {
    //             let mut pair = coins_list.reborrow().get(i as u32);
    //             // Serialize the outpoint to binary data
    //             let mut outpoint_data = Vec::new();
    //             outpoint.consensus_encode(&mut outpoint_data).expect("Serialization should not fail");
    //             pair.set_key(&outpoint_data);
    //             // Value will be populated by Bitcoin Core
    //             pair.set_value(&[]);
    //         }
    //     }
       
    //     // Send the request and handle the response
    //     let mut result = Vec::new();
    //     match find_coins_request.send().promise.await {
    //         Ok(response) => {
    //             match response.get() {
    //                 Ok(result_data) => {
    //                     match result_data.get_coins() {
    //                         Ok(coins) => {
    //                             println!("Found {} coins in mempool/UTXO set", coins.len());
    //                             for coin in coins.iter() {
    //                                 if let (Ok(key_data), Ok(value_data)) = (coin.get_key(), coin.get_value()) {
    //                                     if !key_data.is_empty() && !value_data.is_empty() {
    //                                         // Deserialize the outpoint and coin
    //                                         if let Ok(outpoint) = bitcoin::OutPoint::consensus_decode(&mut std::io::Cursor::new(key_data)) {
    //                                             if let Ok(txout) = bitcoin::TxOut::consensus_decode(&mut std::io::Cursor::new(value_data)) {
    //                                                 println!("Found coin: {}:{} with value {}", 
    //                                                          outpoint.txid, outpoint.vout, txout.value);
    //                                                 result.push((outpoint, txout));
    //                                             }
    //                                         }
    //                                     }
    //                                 }
    //                             }
    //                         },
    //                         Err(e) => {
    //                             eprintln!("Error getting coins: {}", e);
    //                         }
    //                     }
    //                 },
    //                 Err(e) => {
    //                     eprintln!("Error getting response: {}", e);
    //                 }
    //             }
    //         },
    //         Err(e) => {
    //             eprintln!("Error sending find_coins request: {}", e);
    //         }
    //     }
        
    //     println!("Mempool scan complete.");
    //     result
    // }

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
}
