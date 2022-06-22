use {
    initium_ledger::blockstore::Blockstore,
    initium_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey, timing::timestamp},
    std::{collections::HashMap, net::SocketAddr},
};

const MINIMUM_ANCESTOR_AGREEMENT_SIZE: usize = (ANCESTOR_HASH_REPAIR_SAMPLE_SIZE + 1) / 2;
const RETRY_INTERVAL_SECONDS: usize = 5;

#[derive(Debug, PartialEq)]
pub enum DuplicateAncestorDecision {
    InvalidSample,
    AncestorsAllMatch,
    SampleNotDuplicateConfirmed,
    ContinueSearch(DuplicateSlotRepairStatus),
    EarliestAncestorNotFrozen(DuplicateSlotRepairStatus),
    EarliestMismatchFound(DuplicateSlotRepairStatus),
}

impl DuplicateAncestorDecision {
    pub fn is_retryable(&self) -> bool {
        match self {
            // If we get a bad sample from malicious validators, then retry
            DuplicateAncestorDecision::InvalidSample
            // It may be possible the validators have not yet detected duplicate confirmation
            // so retry
           |  DuplicateAncestorDecision::SampleNotDuplicateConfirmed => true,

            DuplicateAncestorDecision::AncestorsAllMatch => false,

             DuplicateAncestorDecision::ContinueSearch(_status)
            | DuplicateAncestorDecision::EarliestAncestorNotFrozen(_status)
            | DuplicateAncestorDecision::EarliestMismatchFound(_status) => false,
        }
    }

    pub fn repair_status(&self) -> Option<&DuplicateSlotRepairStatus> {
        match self {
            DuplicateAncestorDecision::InvalidSample
            | DuplicateAncestorDecision::AncestorsAllMatch
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => None,
            DuplicateAncestorDecision::ContinueSearch(status) => Some(status),
            DuplicateAncestorDecision::EarliestAncestorNotFrozen(status) => Some(status),
            DuplicateAncestorDecision::EarliestMismatchFound(status) => Some(status),
        }
    }

    fn repair_status_mut(&mut self) -> Option<&mut DuplicateSlotRepairStatus> {
        match self {
            DuplicateAncestorDecision::InvalidSample
            | DuplicateAncestorDecision::AncestorsAllMatch
            | DuplicateAncestorDecision::SampleNotDuplicateConfirmed => None,
            DuplicateAncestorDecision::ContinueSearch(status) => Some(status),
            DuplicateAncestorDecision::EarliestAncestorNotFrozen(status) => Some(status),
            DuplicateAncestorDecision::EarliestMismatchFound(status) => Some(status),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DuplicateSlotRepairStatus {
    // Any ancestor slots that are either missing or are mismatched.
    // A mismatched ancestor slot is one that has been replayed (frozen)
    // that has a different hash than the one agreed upon by the sampled peers.
    //
    //
    // These are the slots that need to be dumped in order to repair the correct
    // versions. The hash is None if the slot is not frozen, because it's:
    // 1) Dead
    // 2) Hasn't been replayed
    // 3) We don't have the slot in our Ledger
    pub correct_ancestors_to_repair: Vec<(Slot, Hash)>,
    pub repair_pubkey_and_addr: Option<(Pubkey, SocketAddr)>,
    pub start_ts: u64,
}

impl DuplicateSlotRepairStatus {
    fn new(correct_ancestors_to_repair: Vec<(Slot, Hash)>) -> Self {
        Self {
            correct_ancestors_to_repair,
            repair_pubkey_and_addr: None,
            start_ts: timestamp(),
        }
    }
}

#[derive(Default, Clone)]
pub struct DeadSlotAncestorRequestStatus {
    ancestor_request_responses: HashMap<Vec<(Slot, Hash)>, Vec<SocketAddr>>,
}

impl DeadSlotAncestorRequestStatus {
    pub fn new(
        sampled_validators: impl Iterator<Item = SocketAddr>,
        requested_mismatched_slot: Slot,
    ) -> Self {
        DeadSlotAncestorRequestStatus {
            requested_mismatched_slot,
            start_ts: timestamp(),
            sampled_validators: sampled_validators.map(|p| (p, false)).collect(),
            ..DeadSlotAncestorRequestStatus::default()
        }
    }

    pub fn add_response(
        &mut self,
        from_addr: &SocketAddr,
        response_slot_hashes: Vec<(Slot, Hash)>,
        blockstore: &Blockstore,
    ) -> Option<DuplicateAncestorDecision> {
        if let Some(did_get_response) = self.sampled_validators.get_mut(from_addr) {
            if *did_get_response {
                // If we've already received a response from this validator, return.
                return None;
            }
          
            *did_get_response = true;
            self.num_responses += 1;
        } else {
            // If this is not a response from one of the sampled validators, return.
            return None;
        }

        let validators_with_same_response = self
            .ancestor_request_responses
            .entry(response_slot_hashes.clone())
            .or_default();
        validators_with_same_response.push(*from_addr);

        
        if validators_with_same_response.len()
            == MINIMUM_ANCESTOR_AGREEMENT_SIZE.min(self.sampled_validators.len())
        {
            // When we reach MINIMUM_ANCESTOR_AGREEMENT_SIZE of the same responses,
            // check for mismatches.
            return Some(
                self.handle_sampled_validators_reached_agreement(blockstore, response_slot_hashes),
            );
        }

        
        if self.num_responses == ANCESTOR_HASH_REPAIR_SAMPLE_SIZE.min(self.sampled_validators.len())
        {
            info!(
                "{} return invalid sample no agreement",
                self.requested_mismatched_slot
            );
            return Some(DuplicateAncestorDecision::InvalidSample);
        }

        None
    }

    fn handle_sampled_validators_reached_agreement(
        &mut self,
        blockstore: &Blockstore,
        mut agreed_response: Vec<(Slot, Hash)>,
    ) -> DuplicateAncestorDecision {
        if agreed_response.is_empty() {
            info!(
                "{} return invalid sample not duplicate confirmed",
                self.requested_mismatched_slot
            );
            return DuplicateAncestorDecision::SampleNotDuplicateConfirmed;
        }

        if agreed_response.first().unwrap().0 != self.requested_mismatched_slot {
            return DuplicateAncestorDecision::InvalidSample;
        }

        let mut last_ancestor = 0;
        let mut earliest_erroring_ancestor = None;
        // Iterate from smallest to largest ancestor, performing integrity checks.
        for (i, (ancestor_slot, agreed_upon_hash)) in agreed_response.iter().rev().enumerate() {
            if i != 0 && *ancestor_slot <= last_ancestor {
                info!(
                    "{} return invalid sample out of order",
                    self.requested_mismatched_slot
                );
                // Responses were not properly ordered
                return DuplicateAncestorDecision::InvalidSample;
            }
            last_ancestor = *ancestor_slot;
            if *ancestor_slot > self.requested_mismatched_slot {
                // We should only get ancestors of `self.requested_mismatched_slot`
                // in valid responses
                info!(
                    "{} return invalid sample big ancestor",
                    self.requested_mismatched_slot
                );
                return DuplicateAncestorDecision::InvalidSample;
            }
            let our_frozen_hash = blockstore.get_bank_hash(*ancestor_slot);
            if let Some(our_frozen_hash) = our_frozen_hash {
                if earliest_erroring_ancestor.is_some() && our_frozen_hash == *agreed_upon_hash {
                    info!("{} mismatches then matches", self.requested_mismatched_slot);
                    return DuplicateAncestorDecision::InvalidSample;
                } else if our_frozen_hash != *agreed_upon_hash
                    && earliest_erroring_ancestor.is_none()
                {
                    earliest_erroring_ancestor = Some((
                        agreed_response.len() - i - 1,
                        DuplicateAncestorDecision::EarliestMismatchFound(
                            DuplicateSlotRepairStatus::default(),
                        ),
                    ));
                }
            } else if earliest_erroring_ancestor.is_none() {
                warn!(
                    "Blockstore is missing frozen hash for slot {},
                which the cluster claims is an ancestor of dead slot {}. Potentially
                our version of the dead slot chains to the wrong fork!",
                    ancestor_slot, self.requested_mismatched_slot
                );
                earliest_erroring_ancestor = Some((
                    agreed_response.len() - i - 1,
                    DuplicateAncestorDecision::EarliestAncestorNotFrozen(
                        DuplicateSlotRepairStatus::default(),
                    ),
                ));
            }
        }

        if let Some((earliest_erroring_ancestor_index, mut decision)) = earliest_erroring_ancestor {
            if earliest_erroring_ancestor_index == agreed_response.len() - 1 {
                // If the earliest ancestor is missing or a mismatch, then we need to keep searching
                // for earlier mismatches
                let repair_status = DuplicateSlotRepairStatus::new(agreed_response);
                DuplicateAncestorDecision::ContinueSearch(repair_status)
            } else {
                // We only need to look through the first `earliest_erroring_ancestor_index + 1`
                // elements and dump/repair any mismatches.
                agreed_response.truncate(earliest_erroring_ancestor_index + 1);
                let repair_status = decision.repair_status_mut().unwrap();
                repair_status.correct_ancestors_to_repair = agreed_response;
                decision
            }
        } else {
            // If we haven't returned by now, this implies all the ancestors matched our versions
            // of those ancestors. Only slot to dump and repair is `self.requested_mismatched_slot`
            DuplicateAncestorDecision::AncestorsAllMatch
        }
    }

    /// Given a timestamp in milliseconds, return if we should retry with another sample batch
    /// due to timeout
    pub fn is_expired(&self) -> bool {
        timestamp() - self.start_ts > RETRY_INTERVAL_SECONDS as u64 * 1000
    }

    #[cfg(test)]
    pub fn make_expired(&mut self) {
        self.start_ts = timestamp() - RETRY_INTERVAL_SECONDS as u64 * 1000 - 1;
    }
}

#[cfg(test)]
pub mod tests {
    use {
        super::*,
        rand::{self, seq::SliceRandom, thread_rng},
        initium_ledger::get_tmp_ledger_path_auto_delete,
        std::{collections::BTreeMap, net::IpAddr},
        tempfile::TempDir,
    };

    struct TestSetup {
        sampled_addresses: Vec<SocketAddr>,
        correct_ancestors_response: Vec<(Slot, Hash)>,
        _blockstore_temp_dir: TempDir,
        blockstore: Blockstore,
        status: DeadSlotAncestorRequestStatus,
    }

    fn create_rand_socket_addr() -> SocketAddr {
        let bytes: [u16; 8] = rand::random();
        let ip = IpAddr::from(bytes);
        SocketAddr::new(ip, 8080)
    }

    fn setup_add_response_test(request_slot: Slot, num_ancestors_in_response: usize) -> TestSetup {
        assert!(request_slot >= num_ancestors_in_response as u64);
        let sampled_addresses: Vec<SocketAddr> = std::iter::repeat_with(create_rand_socket_addr)
            .take(ANCESTOR_HASH_REPAIR_SAMPLE_SIZE)
            .collect();

        let status =
            DeadSlotAncestorRequestStatus::new(sampled_addresses.iter().cloned(), request_slot);
        let blockstore_temp_dir = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(blockstore_temp_dir.path()).unwrap();

        let correct_ancestors_response: Vec<(Slot, Hash)> =
            (request_slot - num_ancestors_in_response as u64..=request_slot)
                .map(|ancestor| (ancestor, Hash::new_unique()))
                .rev()
                .collect();

        TestSetup {
            sampled_addresses,
            correct_ancestors_response,
            _blockstore_temp_dir: blockstore_temp_dir,
            blockstore,
            status,
        }
    }

    #[test]
    fn test_add_response_invalid_peer() {
        let request_slot = 100;
        let TestSetup {
            blockstore,
            mut status,
            ..
        } = setup_add_response_test(request_slot, 10);

        // Try adding a response from an invalid peer, should not be registered
        let rand_addr = create_rand_socket_addr();
        assert!(status
            .add_response(&rand_addr, vec![(99, Hash::new_unique())], &blockstore)
            .is_none());
        assert_eq!(status.num_responses, 0);
        assert!(status.ancestor_request_responses.is_empty());
    }

    #[test]
    fn test_add_multiple_responses_same_peer() {
        let request_slot = 100;
        let TestSetup {
            sampled_addresses,
            correct_ancestors_response,
            blockstore,
            mut status,
            ..
        } = setup_add_response_test(request_slot, 10);

        // Create an incorrect response
        let mut incorrect_ancestors_response = correct_ancestors_response.clone();
        incorrect_ancestors_response.pop().unwrap();

        // Add a mixture of correct and incorrect responses from the same `responder_addr`.
        let num_repeated_responses = ANCESTOR_HASH_REPAIR_SAMPLE_SIZE;
        let responder_addr = &sampled_addresses[0];
        for i in 0..num_repeated_responses {
            let response = if i % 2 == 0 {
                // This is the first response when i == 0, so it should be the only response that
                // persists. All later responses, both correct and incorrect should be ignored
                correct_ancestors_response.clone()
            } else {
                incorrect_ancestors_response.clone()
            };
            assert!(status
                .add_response(responder_addr, response, &blockstore)
                .is_none());
            assert_eq!(status.num_responses, 1);
            assert_eq!(status.ancestor_request_responses.len(), 1);
            let correct_responses = status
                .ancestor_request_responses
                .get(&correct_ancestors_response)
                .unwrap();
            assert!(correct_responses.contains(responder_addr));
            assert_eq!(correct_responses.len(), 1);
        }
    }

    /// Add `num_correct_responses` correct responses from the sampled valdiators, and
    /// then add incorrect responses from the remaining validators.
    fn run_add_multiple_correct_and_incorrect_responses(
        incorrect_responses: Vec<(Vec<(Slot, Hash)>, usize)>,
        test_setup: &mut TestSetup,
    ) -> DuplicateAncestorDecision {
        let &mut TestSetup {
            ref sampled_addresses,
            ref correct_ancestors_response,
            ref blockstore,
            ref mut status,
            ..
        } = test_setup;

        // Generate an event order of adding correct/incorrect responses
        let events: BTreeMap<usize, Vec<(Slot, Hash)>> = incorrect_responses
            .into_iter()
            .scan(
                0,
                |total_count, /*accumulated state*/
                 (
                    incorrect_response,
                    num_responses, /*number of validators returning this response*/
                )| {
                    assert!(num_responses > 0);
                    *total_count += num_responses;
                    Some((*total_count, incorrect_response))
                },
            )
            .collect();

        let total_incorrect_responses = events.iter().last().map(|(count, _)| *count).unwrap_or(0);
        assert!(total_incorrect_responses <= ANCESTOR_HASH_REPAIR_SAMPLE_SIZE);

        let mut event_order: Vec<usize> = (0..sampled_addresses.len()).collect();
        event_order.shuffle(&mut thread_rng());

        for (event, responder_addr) in event_order.iter().zip(sampled_addresses.iter()) {
            let response = events
                .range((event + 1)..)
                .next()
                .map(|(_count, response)| response)
                .unwrap_or_else(|| correct_ancestors_response)
                .clone();

            if let Some(decision) = status.add_response(responder_addr, response, blockstore) {
                // Note we may get a decision before we've heard back from all the
                // sampled validators
                return decision;
            }
        }

        // Should never get here
        panic!("Decision must be made after hearing back from all the sampled validators");
    }

    #[test]
    fn test_add_multiple_responses_invalid_sample_no_agreement() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Create an incorrect response
        let mut incorrect_ancestors_response_0 = test_setup.correct_ancestors_response.clone();
        incorrect_ancestors_response_0.pop().unwrap();

        // Create another incorrect response
        let mut incorrect_ancestors_response_1 = incorrect_ancestors_response_0.clone();
        incorrect_ancestors_response_1.pop().unwrap();
        let desired_incorrect_responses = vec![
            (
                incorrect_ancestors_response_0,
                MINIMUM_ANCESTOR_AGREEMENT_SIZE - 1,
            ),
            (incorrect_ancestors_response_1, 2),
        ];

        // Ensure that no response gets >= MINIMUM_ANCESTOR_AGREEMENT_SIZE responses
        let total_invalid_responses: usize = desired_incorrect_responses
            .iter()
            .map(|(_, count)| count)
            .sum();
        assert!(
            ANCESTOR_HASH_REPAIR_SAMPLE_SIZE - total_invalid_responses
                < MINIMUM_ANCESTOR_AGREEMENT_SIZE
        );

        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(
                desired_incorrect_responses,
                &mut test_setup
            ),
            DuplicateAncestorDecision::InvalidSample
        );
    }

    #[test]
    fn test_add_multiple_responses_not_duplicate_confirmed() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Create an incorrect response that is empty
        let incorrect_ancestors_response = vec![];
        let desired_incorrect_responses = vec![(
            incorrect_ancestors_response,
            MINIMUM_ANCESTOR_AGREEMENT_SIZE,
        )];

        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(
                desired_incorrect_responses,
                &mut test_setup
            ),
            DuplicateAncestorDecision::SampleNotDuplicateConfirmed
        );
    }

    #[test]
    fn test_add_multiple_responses_invalid_sample_missing_requested_slot() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Create an incorrect response that is missing `request_slot`
        let incorrect_ancestors_response = vec![(request_slot - 1, Hash::new_unique())];
        let desired_incorrect_responses = vec![(
            incorrect_ancestors_response,
            MINIMUM_ANCESTOR_AGREEMENT_SIZE,
        )];

        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(
                desired_incorrect_responses,
                &mut test_setup
            ),
            DuplicateAncestorDecision::InvalidSample
        );
    }

    #[test]
    fn test_add_multiple_responses_invalid_sample_responses_not_ancestors() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Create an incorrect response. If the agreed upon response contains
        // slots >= request_slot, we still mark the responses as invalid
        let mut incorrect_ancestors_response = test_setup.correct_ancestors_response.clone();
        incorrect_ancestors_response.push((request_slot + 1, Hash::new_unique()));
        let desired_incorrect_responses = vec![(
            incorrect_ancestors_response,
            MINIMUM_ANCESTOR_AGREEMENT_SIZE,
        )];

        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(
                desired_incorrect_responses,
                &mut test_setup
            ),
            DuplicateAncestorDecision::InvalidSample
        );
    }

    #[test]
    fn test_add_multiple_responses_invalid_sample_responses_out_of_order() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Create an incorrect response that is out of order
        let mut incorrect_ancestors_response = test_setup.correct_ancestors_response.clone();
        incorrect_ancestors_response.swap_remove(0);
        let desired_incorrect_responses = vec![(
            incorrect_ancestors_response,
            MINIMUM_ANCESTOR_AGREEMENT_SIZE,
        )];

        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(
                desired_incorrect_responses,
                &mut test_setup
            ),
            DuplicateAncestorDecision::InvalidSample
        );
    }

    #[test]
    fn test_add_multiple_responses_invalid_sample_matches_then_mismatches() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Insert all the correct frozen ancestors
        for &(slot, correct_hash) in &test_setup.correct_ancestors_response {
            test_setup
                .blockstore
                .insert_bank_hash(slot, correct_hash, false);
        }

        // Create an incorrect response where there is a mismatched ancestor `X`, then
        // a matching ancestor `Y > X`
        let mut incorrect_ancestors_response = test_setup.correct_ancestors_response.clone();
        incorrect_ancestors_response[5].1 = Hash::new_unique();
        let desired_incorrect_responses = vec![(
            incorrect_ancestors_response,
            MINIMUM_ANCESTOR_AGREEMENT_SIZE,
        )];

        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(
                desired_incorrect_responses,
                &mut test_setup
            ),
            DuplicateAncestorDecision::InvalidSample
        );
    }

    #[test]
    fn test_add_multiple_responses_ancestors_all_not_frozen() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Create an incorrect response, but the agreed upon response will be the correct
        // one.
        let mut incorrect_ancestors_response = test_setup.correct_ancestors_response.clone();
        incorrect_ancestors_response.push((request_slot, Hash::new_unique()));
        let desired_incorrect_responses = vec![(
            incorrect_ancestors_response,
            MINIMUM_ANCESTOR_AGREEMENT_SIZE - 1,
        )];

        // We have no entries in the blockstore, so all the ancestors will be missing
        match run_add_multiple_correct_and_incorrect_responses(
            desired_incorrect_responses,
            &mut test_setup,
        ) {
            DuplicateAncestorDecision::ContinueSearch(repair_status) => {
                assert_eq!(
                    repair_status.correct_ancestors_to_repair,
                    test_setup.correct_ancestors_response
                );
            }
            x => panic!("Incorrect decision {:?}", x),
        };
    }

    #[test]
    fn test_add_multiple_responses_ancestors_some_not_frozen() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Set up a situation where some of our ancestors are correct,
        // but then we fork off and are missing some ancestors like so:
        //  ```
        //                 93 - 95 - 97 - 99 - 100 (our current fork, missing some slots like 98)
        //              /
        //  90 - 91 - 92 (all correct)
        //               \
        //                 93 - 94 - 95 - 96 - 97 - 98 - 99 - 100 (correct fork)
        // ```
        let rand_num: u64 = rand::random();
        let insert_even_or_odds: u64 = rand_num % 2;
        for &(slot, correct_hash) in &test_setup.correct_ancestors_response {
            if slot <= 92 {
                test_setup
                    .blockstore
                    .insert_bank_hash(slot, correct_hash, false);
            } else if slot % 2 == insert_even_or_odds {
                // Here we either skip slot 93 or 94.
                //
                // 1) If we skip slot 93, and insert mismatched slot 94 we're testing the order of
                // events `Not frozen -> Mismatched hash`
                //
                // 2) If we insert mismatched slot 93, and skip slot 94 we're testing the order of
                // events `Mismatched hash -> Not frozen`
                //
                // Both cases should return `EarliestMismatchFound`
                test_setup
                    .blockstore
                    .insert_bank_hash(slot, Hash::new_unique(), false);
            }
        }

        let repair_status =
            match run_add_multiple_correct_and_incorrect_responses(vec![], &mut test_setup) {
                DuplicateAncestorDecision::EarliestMismatchFound(repair_status)
                    if insert_even_or_odds == 1 =>
                {
                    repair_status
                }
                DuplicateAncestorDecision::EarliestAncestorNotFrozen(repair_status)
                    if insert_even_or_odds == 0 =>
                {
                    repair_status
                }
                x => panic!("Incorrect decision {:?}", x),
            };

        // Expect to find everything after 92 in the `correct_ancestors_to_repair`.
        let expected_mismatched_slots: Vec<(Slot, Hash)> = test_setup
            .correct_ancestors_response
            .into_iter()
            .filter(|(slot, _)| *slot > 92)
            .collect();
        assert_eq!(
            repair_status.correct_ancestors_to_repair,
            expected_mismatched_slots
        );
    }

    #[test]
    fn test_add_multiple_responses_ancestors_all_mismatched() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Insert all the wrong hashes for the slots
        for (slot, _) in &test_setup.correct_ancestors_response {
            test_setup
                .blockstore
                .insert_bank_hash(*slot, Hash::new_unique(), false);
        }

        // All the ancestors are mismatched, so we need to continue the search
        match run_add_multiple_correct_and_incorrect_responses(vec![], &mut test_setup) {
            DuplicateAncestorDecision::ContinueSearch(repair_status) => {
                assert_eq!(
                    repair_status.correct_ancestors_to_repair,
                    test_setup.correct_ancestors_response
                );
            }
            x => panic!("Incorrect decision {:?}", x),
        };
    }

    #[test]
    fn test_add_multiple_responses_ancestors_some_mismatched() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Set up a situation where some of our ancestors are correct,
        // but then we fork off with different versions of the correct slots.
        //  ```
        //                 93' - 94' - 95' - 96' - 97' - 98' - 99' - 100' (our current fork, missing some slots like 98)
        //              /
        //  90 - 91 - 92 (all correct)
        //               \
        //                 93 - 94 - 95 - 96 - 97 - 98 - 99 - 100 (correct fork)
        // ```

        // Insert all the wrong hashes for the slots
        for &(slot, correct_hash) in &test_setup.correct_ancestors_response {
            if slot <= 92 {
                test_setup
                    .blockstore
                    .insert_bank_hash(slot, correct_hash, false);
            } else {
                test_setup
                    .blockstore
                    .insert_bank_hash(slot, Hash::new_unique(), false);
            }
        }

        // All the ancestors are mismatched, so we need to continue the search
        match run_add_multiple_correct_and_incorrect_responses(vec![], &mut test_setup) {
            DuplicateAncestorDecision::EarliestMismatchFound(repair_status) => {
                // Expect to find everything after 92 in the `correct_ancestors_to_repair`.
                let expected_mismatched_slots: Vec<(Slot, Hash)> = test_setup
                    .correct_ancestors_response
                    .into_iter()
                    .filter(|(slot, _)| *slot > 92)
                    .collect();
                assert_eq!(
                    repair_status.correct_ancestors_to_repair,
                    expected_mismatched_slots
                );
            }
            x => panic!("Incorrect decision {:?}", x),
        };
    }

    #[test]
    fn test_add_multiple_responses_ancestors_all_match() {
        let request_slot = 100;
        let mut test_setup = setup_add_response_test(request_slot, 10);

        // Insert all the correct frozen ancestors
        for &(slot, correct_hash) in &test_setup.correct_ancestors_response {
            test_setup
                .blockstore
                .insert_bank_hash(slot, correct_hash, false);
        }

        // All the ancestors matched
        assert_eq!(
            run_add_multiple_correct_and_incorrect_responses(vec![], &mut test_setup),
            DuplicateAncestorDecision::AncestorsAllMatch
        );
    }
}
