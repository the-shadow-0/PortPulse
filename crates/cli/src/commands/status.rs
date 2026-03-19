use anyhow::Result;
use portpulse_ebpf::loader::EbpfLoader;
use portpulse_ebpf::probes::default_probes;

/// Show system status and eBPF probe information
pub async fn run() -> Result<()> {
    println!("⚡ PortPulse — System Status");
    println!("═══════════════════════════");
    println!();

    // Kernel version
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let kernel = version.split_whitespace().nth(2).unwrap_or("unknown");
        println!("  Kernel:      {}", kernel);
    }

    // Check eBPF availability
    let mut loader = EbpfLoader::new(default_probes());
    let ebpf_available = loader.check_availability();
    println!(
        "  eBPF:        {}",
        if ebpf_available {
            "✓ Available"
        } else {
            "✗ Unavailable (run as root or kernel < 5.4)"
        }
    );

    // Check if running as root
    let is_root = unsafe { libc::geteuid() } == 0;
    println!("  Root:        {}", if is_root { "✓ Yes" } else { "✗ No" });

    // Probe definitions
    println!();
    println!("  📡 Probe Definitions:");
    for probe in default_probes() {
        println!(
            "    {:?} {} → {} {}",
            probe.probe_type,
            probe.name,
            probe.attach_point,
            if probe.required {
                "(required)"
            } else {
                "(optional)"
            }
        );
    }

    // /proc/net files
    println!();
    println!("  📂 /proc/net Status:");
    for file in &[
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        let available = std::path::Path::new(file).exists();
        println!("    {} {}", if available { "✓" } else { "✗" }, file);
    }

    println!();
    println!("  💡 Tip: Run as root for full eBPF support:");
    println!("    sudo portpulse live");

    Ok(())
}
