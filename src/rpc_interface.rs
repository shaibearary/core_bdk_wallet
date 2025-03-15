use capnp_rpc::{pry, rpc_twoparty_capnp, twoparty, RpcSystem};
use tokio::task::{self, JoinHandle};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use std::{sync::{Arc, Mutex}};
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

    pub async fn get_tip(&self) -> BlockId {
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
    pub async fn find_coins_request(&self, wallet: Arc<Mutex<BdkWallet>>) {
        let mut find_coins_request = self.chain_interface.find_coins_request();

        // Set the thread context for the request
        find_coins_request
            .get()
            .get_context()
            .unwrap()
            .set_thread(self.thread.clone());
    
        // Send the request and handle the response with proper error handling
        match find_coins_request.send().promise.await {
            Ok(response) => {
                match response.get() {
                    Ok(result) => {
                        match result.get_coins() {
                            Ok(coins) => {
                                println!("Found {} coins in mempool", coins.len());
                                for coin in coins.iter() {
                                    // Process each coin found in the mempool
                                    println!("Found coin: {:?}", coin);
                                    
                                    // If you need to update the wallet with the found coins
                                    if let Ok(mut wallet_guard) = wallet.lock() {
                                        // Extract coin data and update wallet
                                        // Example: wallet_guard.add_coin(coin);
                                    }
                                }
                            },
                            Err(e) => {
                                eprintln!("Error getting coins: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Error getting response: {}", e);
                    }
                }
            },
            Err(e) => {
                eprintln!("Error sending find_coins request: {}", e);
            }
        }
        
        println!("Mempool scan complete.");
    }
    pub async fn get_block(
        &self,
        node_tip_hash: &bitcoin::BlockHash,
        height: i32,
    ) -> bitcoin::Block {
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
