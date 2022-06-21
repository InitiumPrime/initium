use {
    crate::posync_timing_reporter::PosyncTimingReporter,
    initium_metrics::posync_timing_point::{PosyncTimingReceiver, SlotPohTimingInfo},
    std::{
        string::ToString,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

/// Timeout to wait on the Proof of Synchronization timing points from the channel
const POSYNC_TIMING_RECEIVER_TIMEOUT_MILLISECONDS: u64 = 1000;

/// The `posync_timing_report_service` receives signals of relevant timing points
/// during the processing of a slot, (i.e. from blockstore and poh), aggregate and
/// report the result as datapoints.
pub struct PosyncTimingReportService {
    t_posync_timing: JoinHandle<()>,
}

impl PosyncTimingReportService {
    pub fn new(receiver: PosyncTimingReceiver, exit: &Arc<AtomicBool>) -> Self {
        let exit_signal = exit.clone();
        let mut posync_timing_reporter = PosyncTimingReporter::default();
        let t_posync_timing = Builder::new()
            .name("posync_timing_report".to_string())
            .spawn(move || loop {
                if exit_signal.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(SlotPosyncTimingInfo {
                    slot,
                    root_slot,
                    timing_point,
                }) = receiver.recv_timeout(Duration::from_millis(
                    POSYNC_TIMING_RECEIVER_TIMEOUT_MILLISECONDS,
                )) {
                    posync_timing_reporter.process(slot, root_slot, timing_point);
                }
            })
            .unwrap();
        Self { t_posync_timing }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_posync_timing.join()
    }
}

#[cfg(test)]
mod test {
    use {
        super::*, crossbeam_channel::unbounded, solana_metrics::poh_timing_point::SlotPosyncTimingInfo,
    };

    #[test]
    /// Test the life cycle of the PosyncTimingReportService
    fn test_posync_timing_report_service() {
        let (posync_timing_point_sender, posync_timing_point_receiver) = unbounded();
        let exit = Arc::new(AtomicBool::new(false));
        // Create the service
        let posync_timing_report_service =
            PosyncTimingReportService::new(posync_timing_point_receiver, &exit);

        // Send SlotPosyncTimingPoint
        let _ = posync_timing_point_sender.send(SlotPosyncTimingInfo::new_slot_start_posync_time_point(
            42, None, 100,
        ));
        let _ = posync_timing_point_sender.send(SlotPosyncTimingInfo::new_slot_end_posync_time_point(
            42, None, 200,
        ));
        let _ = posync_timing_point_sender.send(SlotPosyncTimingInfo::new_slot_full_posync_time_point(
            42, None, 150,
        ));

        // Shutdown the service
        exit.store(true, Ordering::Relaxed);
        posync_timing_report_service
            .join()
            .expect("posync_timing_report_service completed");
    }
}
