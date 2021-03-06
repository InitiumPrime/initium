// Connect to future Prime nodes with some jitter so the quic connection is warm
// by the time we need it.

use {
    rand::{thread_rng, Rng},
    initium_client::connection_cache::send_wire_transaction,
    initium_gossip::cluster_info::ClusterInfo,
    initium_poh::poh_recorder::PohRecorder,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct WarmQuicCacheService {
    thread_hdl: JoinHandle<()>,
}

// ~50 seconds
const CACHE_OFFSET_SLOT: i64 = 100;
const CACHE_JITTER_SLOT: i64 = 20;

impl WarmQuicCacheService {
    pub fn new(
        cluster_info: Arc<ClusterInfo>,
        poh_recorder: Arc<Mutex<PohRecorder>>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("sol-warm-quic-service".to_string())
            .spawn(move || {
                let slot_jitter = thread_rng().gen_range(-CACHE_JITTER_SLOT, CACHE_JITTER_SLOT);
                let mut maybe_last_prime = None;
                while !exit.load(Ordering::Relaxed) {
                    let prime_pubkey =  poh_recorder
                        .lock()
                        .unwrap()
                        .prime_after_n_slots((CACHE_OFFSET_SLOT + slot_jitter) as u64);
                    if let Some(prime_pubkey) = prime_pubkey {
                        if maybe_last_prime
                            .map_or(true, |last_prime| last_prime != prime_pubkey)
                        {
                            maybe_last_prime = Some(prime_pubkey);
                            if let Some(addr) = cluster_info
                                .lookup_contact_info(&prime_pubkey, |prime| prime.tpu)
                            {
                                if let Err(err) = send_wire_transaction(&[0u8], &addr) {
                                    warn!(
                                        "Failed to warmup QUIC connection to the prime {:?}, Error {:?}",
                                        prime_pubkey, err
                                    );
                                }
                            }
                        }
                    }
                    sleep(Duration::from_millis(200));
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
