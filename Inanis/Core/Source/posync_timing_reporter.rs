//! The posync_timing_reporter module implement Proof of Synchronizatoin timing point and timing reporter
//! structs.
use {
    initium_metrics::{datapoint_info, poh_timing_point::PohTimingPoint},
    initium_sdk::clock::Slot,
    std::{collections::HashMap, fmt},
};

/// A SlotPosyncTimestamp records timing of the events during the processing of a
/// slot by the validator
#[derive(Debug, Clone, Copy, Default)]
pub struct SlotPosyncTimestamp {
    /// Slot start time from PoSync
    pub start_time: u64,
    /// Slot end time from PoSync
    pub end_time: u64,
    /// Last shred received time from block producer
    pub full_time: u64,
}

/// Display trait
impl fmt::Display for SlotPosyncTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SlotPosyncTimestamp: start={} end={} full={}",
            self.start_time, self.end_time, self.full_time
        )
    }
}

impl SlotPosyncTimestamp {
    /// Return true if the timing points of all events are received.
    pub fn is_complete(&self) -> bool {
        self.start_time != 0 && self.end_time != 0 && self.full_time != 0
    }

    /// Update with timing point
    pub fn update(&mut self, timing_point: PosyncTimingPoint) {
        match timing_point {
            PosyncTimingPoint::PosyncSlotStart(ts) => self.start_time = ts,
            PosyncTimingPoint::PosyncSlotEnd(ts) => self.end_time = ts,
            PosyncTimingPoint::FullSlotReceived(ts) => self.full_time = ts,
        }
    }

    /// Return the time difference from slot start to slot full
    fn slot_start_to_full_time(&self) -> i64 {
        (self.full_time as i64).saturating_sub(self.start_time as i64)
    }

    /// Return the time difference from slot full to slot end
    fn slot_full_to_end_time(&self) -> i64 {
        (self.end_time as i64).saturating_sub(self.full_time as i64)
    }

    /// Report PosyncTiming for a slot
    pub fn report(&self, slot: Slot) {
        datapoint_info!(
            "posync_slot_timing",
            ("slot", slot as i64, i64),
            ("start_time", self.start_time as i64, i64),
            ("end_time", self.end_time as i64, i64),
            ("full_time", self.full_time as i64, i64),
            (
                "start_to_full_time_diff",
                self.slot_start_to_full_time(),
                i64
            ),
            ("full_to_end_time_diff", self.slot_full_to_end_time(), i64),
        );
    }
}

/// A PosyncTimingReporter manages and reports the timing of events for incoming
/// slots
#[derive(Default)]
pub struct PosyncTimingReporter {
    /// Storage map of SlotPosyncTimestamp per slot
    slot_timestamps: HashMap<Slot, SlotPosyncTimestamp>,
    last_root_slot: Slot,
}

impl PosyncTimingReporter {
    /// Return true if PosyncTiming is complete for the slot
    pub fn is_complete(&self, slot: Slot) -> bool {
        if let Some(slot_timestamp) = self.slot_timestamps.get(&slot) {
            slot_timestamp.is_complete()
        } else {
            false
        }
    }

    /// Process incoming PosyncTimingPoint from the channel
    pub fn process(&mut self, slot: Slot, root_slot: Option<Slot>, t: PosyncTimingPoint) -> bool {
        let slot_timestamp = self
            .slot_timestamps
            .entry(slot)
            .or_insert_with(SlotPosyncTimestamp::default);

        slot_timestamp.update(t);
        let is_completed = slot_timestamp.is_complete();
        if is_completed {
            slot_timestamp.report(slot);
        }

        // delete slots that are older than the root_slot
        if let Some(root_slot) = root_slot {
            if root_slot > self.last_root_slot {
                self.slot_timestamps.retain(|&k, _| k >= root_slot);
                self.last_root_slot = root_slot;
            }
        }
        is_completed
    }

    /// Return the count of slot_timestamps in tracking
    pub fn slot_count(&self) -> usize {
        self.slot_timestamps.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// Test posync_timing_reporter
    fn test_posync_timing_reporter() {
        // create a reporter
        let mut reporter = PosyncTimingReporter::default();

        // process all relevant PosyncTimingPoints for slot 42
        let complete = reporter.process(42, None, PosyncTimingPoint::PosyncSlotStart(100));
        assert!(!complete);
        let complete = reporter.process(42, None, PosyncTimingPoint::PosyncSlotEnd(200));
        assert!(!complete);
        let complete = reporter.process(42, None, PosyncTimingPoint::FullSlotReceived(150));
        // assert that the PosyncTiming is complete
        assert!(complete);

        // Move root to slot 43
        let root = Some(43);

        // process all relevant PosyncTimingPoints for slot 45
        let complete = reporter.process(45, None, PosyncTimingPoint::PosyncSlotStart(100));
        assert!(!complete);
        let complete = reporter.process(45, None, PosyncTimingPoint::PosyncSlotEnd(200));
        assert!(!complete);
        let complete = reporter.process(45, root, PosyncTimingPoint::FullSlotReceived(150));
        // assert that the PohTiming is complete
        assert!(complete);

        // assert that only one timestamp remains in track
        assert_eq!(reporter.slot_count(), 1)
    }

    #[test]
    /// Test posync_timing_reporter
    fn test_posync_timing_reporter_out_of_order() {
        // create a reporter
        let mut reporter = PosyncTimingReporter::default();

        // process all relevant PosyncTimingPoints for slot 42/43 out of order
        let mut c = 0;
        // slot_start 42
        c += reporter.process(42, None, PosyncTimingPoint::PosyncSlotStart(100)) as i32;
        // slot_full 42
        c += reporter.process(42, None, PosyncTimingPoint::FullSlotReceived(120)) as i32;
        // slot_full 43
        c += reporter.process(43, None, PosyncTimingPoint::FullSlotReceived(140)) as i32;
        // slot_end 42
        c += reporter.process(42, None, PosyncTimingPoint::PosyncSlotEnd(200)) as i32;
        // slot start 43
        c += reporter.process(43, None, PosyncTimingPoint::PosyncSlotStart(100)) as i32;
        // slot end 43
        c += reporter.process(43, None, PosyncTimingPoint::PosyncSlotEnd(200)) as i32;

        // assert that both timing points are complete
        assert_eq!(c, 2);

        // assert that both timestamps remain in track
        assert_eq!(reporter.slot_count(), 2)
    }

    #[test]
    /// Test posync_timing_reporter
    fn test_posync_timing_reporter_never_complete() {
        // create a reporter
        let mut reporter = PosyncTimingReporter::default();

        let mut c = 0;

        // process all relevant PosyncTimingPoints for slot 42/43 out of order
        // slot_start 42
        c += reporter.process(42, None, PosyncTimingPoint::PosyncSlotStart(100)) as i32;

        // slot_full 42
        c += reporter.process(42, None, PosyncTimingPoint::FullSlotReceived(120)) as i32;

        // slot_full 43
        c += reporter.process(43, None, PosyncTimingPoint::FullSlotReceived(140)) as i32;

        // skip slot 42, jump to slot 43
        // slot start 43
        c += reporter.process(43, None, PosyncTimingPoint::PosyncSlotStart(100)) as i32;

        // slot end 43
        c += reporter.process(43, None, PosyncTimingPoint::PosyncSlotEnd(200)) as i32;

        // assert that only one timing point is complete
        assert_eq!(c, 1);

        // assert that both timestamp is in track
        assert_eq!(reporter.slot_count(), 2)
    }

    #[test]
    fn test_posync_timing_reporter_overflow() {
        // create a reporter
        let mut reporter = PosyncTimingReporter::default();

        // process all relevant PosyncTimingPoints for a slot
        let complete = reporter.process(42, None, PosyncTimingPoint::PosyncSlotStart(1647624609896));
        assert!(!complete);
        let complete = reporter.process(42, None, PosyncTimingPoint::PosyncSlotEnd(1647624610286));
        assert!(!complete);
        let complete = reporter.process(42, None, PosyncTimingPoint::FullSlotReceived(1647624610281));

        // assert that the PosyncTiming is complete
        assert!(complete);
    }

    #[test]
    fn test_slot_posync_timestamp_fmt() {
        let t = SlotPosyncTimestamp::default();
        assert_eq!(format!("{}", t), "SlotPosyncTimestamp: start=0 end=0 full=0");
    }
}
