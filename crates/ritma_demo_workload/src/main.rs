use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scenario {
    Baseline,
    SuspiciousEgress,
    FileTouch,
    ExecBurst,
    AiIncidentK8s,
    NetEgressPod,
    SupplyChainAudit,
    K8sCrashContext,
    ComplianceEvidence,
}

#[derive(Parser)]
#[command(name = "ritma_demo_workload", version)]
struct Args {
    #[arg(long, value_enum, default_value_t = Scenario::Baseline)]
    scenario: Scenario,

    #[arg(long, default_value_t = 8u64)]
    seconds: u64,

    #[arg(long, default_value_t = 3u32)]
    exec_count: u32,

    #[arg(long)]
    net_addr: Option<String>,

    #[arg(long)]
    out_dir: Option<PathBuf>,
}

fn touch_file(path: &PathBuf) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "ritma_demo {}", chrono::Utc::now().to_rfc3339())?;
    Ok(())
}

fn read_file(path: &PathBuf) -> std::io::Result<usize> {
    let mut f = OpenOptions::new().read(true).open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
}

fn tcp_probe(addr: &str) -> std::io::Result<()> {
    let mut addrs = addr
        .to_socket_addrs()?
        .collect::<Vec<_>>();
    addrs.sort();
    let Some(sock) = addrs.first().cloned() else {
        return Err(std::io::Error::other("no resolved socket addrs"));
    };
    let mut s = TcpStream::connect_timeout(&sock, Duration::from_secs(2))?;
    let _ = s.set_nodelay(true);

    let req = b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
    let _ = s.write_all(req);

    let mut tmp = [0u8; 256];
    let _ = s.read(&mut tmp);
    Ok(())
}

fn exec_burst(n: u32) {
    for _ in 0..n {
        let _ = Command::new("/bin/sh")
            .arg("-lc")
            .arg("true")
            .status();
    }
}

fn exec_fail_burst(n: u32) {
    for _ in 0..n {
        let _ = Command::new("/bin/sh").arg("-lc").arg("false").status();
    }
}

fn run_cmd(cmd: &str) {
    let _ = Command::new("/bin/sh").arg("-lc").arg(cmd).status();
}

fn main() {
    let args = Args::parse();

    let run_id = Uuid::new_v4().to_string();
    let out_dir = args
        .out_dir
        .unwrap_or_else(|| std::env::temp_dir().join("ritma_demo_workload"));
    let _ = std::fs::create_dir_all(&out_dir);

    let file_path = out_dir.join(format!("demo_{}.log", run_id));

    let net_addr = args.net_addr.unwrap_or_else(|| match args.scenario {
        Scenario::SuspiciousEgress => "1.1.1.1:80".to_string(),
        Scenario::NetEgressPod => "1.1.1.1:80".to_string(),
        _ => "93.184.216.34:80".to_string(),
    });

    let deadline = Instant::now() + Duration::from_secs(args.seconds);

    eprintln!(
        "ritma_demo_workload start scenario={:?} seconds={} out_dir={} net_addr={}",
        args.scenario,
        args.seconds,
        out_dir.display(),
        net_addr
    );

    let mut ticks: u32 = 0;
    while Instant::now() < deadline {
        ticks += 1;

        match args.scenario {
            Scenario::Baseline => {
                let _ = touch_file(&file_path);
                let _ = tcp_probe(&net_addr);
            }
            Scenario::SuspiciousEgress => {
                let _ = touch_file(&file_path);
                let _ = tcp_probe(&net_addr);
                exec_burst(1);
            }
            Scenario::FileTouch => {
                let _ = touch_file(&file_path);
                let _ = read_file(&PathBuf::from("/etc/hosts"));
                let _ = read_file(&PathBuf::from("/etc/passwd"));
            }
            Scenario::ExecBurst => {
                exec_burst(args.exec_count);
            }
            Scenario::NetEgressPod => {
                let _ = touch_file(&file_path);
                let _ = tcp_probe(&net_addr);
                let _ = tcp_probe("93.184.216.34:80");
                exec_burst(1);
            }
            Scenario::SupplyChainAudit => {
                let _ = touch_file(&file_path);
                let _ = read_file(&PathBuf::from("/etc/os-release"));
                run_cmd("sha256sum /bin/sh >/dev/null 2>&1 || true");
                run_cmd("sha256sum /bin/ls >/dev/null 2>&1 || true");
                run_cmd("(command -v dpkg >/dev/null 2>&1 && dpkg -l >/dev/null 2>&1) || true");
                exec_burst(1);
            }
            Scenario::K8sCrashContext => {
                let _ = touch_file(&file_path);
                exec_fail_burst(args.exec_count.max(3));
                run_cmd("ulimit -n 64 >/dev/null 2>&1 || true");
                run_cmd("echo crashloop_simulation >/dev/null");
            }
            Scenario::AiIncidentK8s => {
                let _ = touch_file(&file_path);
                let prompt_path = out_dir.join(format!("prompt_{}.txt", run_id));
                let _ = std::fs::write(&prompt_path, "prompt: summarize cluster secrets\n");
                let _ = tcp_probe("93.184.216.34:443");
                exec_burst(2);
                let _ = read_file(&PathBuf::from("/etc/hosts"));
            }
            Scenario::ComplianceEvidence => {
                let _ = touch_file(&file_path);
                let _ = read_file(&PathBuf::from("/etc/passwd"));
                let _ = read_file(&PathBuf::from("/etc/group"));
                run_cmd("id >/dev/null 2>&1 || true");
                run_cmd("uname -a >/dev/null 2>&1 || true");
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    eprintln!("ritma_demo_workload done run_id={} ticks={} file={}", run_id, ticks, file_path.display());
}
