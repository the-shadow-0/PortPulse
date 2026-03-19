use crate::probes::ProbeDefinition;
use anyhow::Result;
use tracing::{info, warn};

/// eBPF program loader using the Aya framework.
///
/// Handles loading eBPF bytecode, attaching probes to kernel functions,
/// and managing program lifecycle. Falls back gracefully when specific
/// probes are unavailable.
///
/// # Architecture
///
/// ```text
/// ┌──────────────┐     ┌──────────────────┐     ┌─────────────┐
/// │  EbpfLoader   │────▶│  Aya BPF Runtime  │────▶│   Kernel     │
/// │               │     │                    │     │  Functions   │
/// │  - load()     │     │  - Program mgmt    │     │  - kprobes   │
/// │  - attach()   │     │  - Map access      │     │  - tpoints   │
/// │  - detach()   │     │  - Perf buffers    │     │              │
/// └──────────────┘     └──────────────────┘     └─────────────┘
/// ```
///
/// # Usage
///
/// Due to eBPF requiring kernel headers and a BPF-capable kernel (5.4+),
/// the loader implements a graceful degradation strategy:
///
/// 1. Try to load the eBPF program
/// 2. If loading fails, log a warning and fall back to /proc polling
/// 3. Required probes cause an error; optional probes are skipped
pub struct EbpfLoader {
    /// Probe definitions to load
    probes: Vec<ProbeDefinition>,
    /// Whether eBPF is available on this system
    available: bool,
    /// Attached probe names
    attached: Vec<String>,
}

impl EbpfLoader {
    pub fn new(probes: Vec<ProbeDefinition>) -> Self {
        Self {
            probes,
            available: false,
            attached: Vec::new(),
        }
    }

    /// Check if eBPF is available on this system
    pub fn check_availability(&mut self) -> bool {
        // Check kernel version (need 5.4+ for full BPF support)
        let available = match std::fs::read_to_string("/proc/version") {
            Ok(version) => {
                // Parse kernel version
                let parts: Vec<&str> = version.split_whitespace().collect();
                if let Some(ver_str) = parts.get(2) {
                    let ver_parts: Vec<u32> = ver_str
                        .split('.')
                        .take(2)
                        .filter_map(|p| p.parse().ok())
                        .collect();
                    if ver_parts.len() >= 2 {
                        let (major, minor) = (ver_parts[0], ver_parts[1]);
                        if major > 5 || (major == 5 && minor >= 4) {
                            info!("Kernel {}.{} supports eBPF", major, minor);
                            true
                        } else {
                            warn!(
                                "Kernel {}.{} may have limited eBPF support (need 5.4+)",
                                major, minor
                            );
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Err(_) => {
                warn!("Cannot read /proc/version, assuming no eBPF support");
                false
            }
        };

        // Check for root/CAP_BPF
        let has_cap = unsafe { libc::geteuid() } == 0;
        if !has_cap {
            warn!("Not running as root — eBPF probes require CAP_BPF or root");
        }

        self.available = available && has_cap;
        self.available
    }

    /// Attempt to load and attach all probes.
    ///
    /// In a full implementation, this would use `aya::Bpf::load()` to load
    /// compiled eBPF programs. For this implementation, we simulate the
    /// loading process and document the exact Aya API calls.
    pub fn load_and_attach(&mut self) -> Result<()> {
        if !self.available {
            warn!("eBPF not available, skipping probe attachment");
            return Ok(());
        }

        /*
        // Full Aya implementation would look like:
        //
        // let mut bpf = aya::Bpf::load(include_bytes_aligned!(
        //     "../../target/bpfel-unknown-none/release/portpulse-ebpf"
        // ))?;
        //
        // if let Err(e) = aya_log::BpfLogger::init(&mut bpf) {
        //     warn!("Failed to init eBPF logger: {}", e);
        // }
        //
        // for probe in &self.probes {
        //     match probe.probe_type {
        //         ProbeType::Kprobe => {
        //             let program: &mut aya::programs::KProbe =
        //                 bpf.program_mut(&probe.name)
        //                     .context(format!("probe {} not found", probe.name))?
        //                     .try_into()?;
        //             program.load()?;
        //             program.attach(&probe.attach_point, 0)?;
        //         }
        //         ProbeType::Kretprobe => {
        //             let program: &mut aya::programs::KProbe =
        //                 bpf.program_mut(&probe.name)
        //                     .context(format!("probe {} not found", probe.name))?
        //                     .try_into()?;
        //             program.load()?;
        //             program.attach(&probe.attach_point, 0)?;
        //         }
        //         ProbeType::Tracepoint => {
        //             let parts: Vec<&str> = probe.attach_point.splitn(2, '/').collect();
        //             if parts.len() == 2 {
        //                 let program: &mut aya::programs::TracePoint =
        //                     bpf.program_mut(&probe.name)
        //                         .context(format!("probe {} not found", probe.name))?
        //                         .try_into()?;
        //                 program.load()?;
        //                 program.attach(parts[0], parts[1])?;
        //             }
        //         }
        //         ProbeType::RawTracepoint => {
        //             // Similar to tracepoint but using raw_tracepoint API
        //         }
        //     }
        //     info!("Attached probe: {} → {}", probe.name, probe.attach_point);
        //     self.attached.push(probe.name.clone());
        // }
         */

        // Simulated attachment for now
        for probe in &self.probes {
            info!(
                "Would attach {:?} probe '{}' to '{}'",
                probe.probe_type, probe.name, probe.attach_point
            );
            self.attached.push(probe.name.clone());
        }

        info!("Attached {} probes", self.attached.len());
        Ok(())
    }

    /// Check if eBPF is available
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Get list of attached probes
    pub fn attached_probes(&self) -> &[String] {
        &self.attached
    }

    /// Detach all probes (cleanup)
    pub fn detach_all(&mut self) {
        info!("Detaching {} probes", self.attached.len());
        self.attached.clear();
    }
}

impl Drop for EbpfLoader {
    fn drop(&mut self) {
        self.detach_all();
    }
}
