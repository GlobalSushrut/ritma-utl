#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ritma-launch is only supported on linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::process::{exit, Command};

    use security_os::linux::CgroupV2Controller;
    use security_os::{Did, DidKind, IsolationScope};

    let args: Vec<String> = env::args().skip(1).collect();

    let mut did_str: Option<String> = None;
    let mut cgroup_root: Option<String> = env::var("SECURITY_HOST_CGROUP_ROOT").ok();

    let mut cmd_index: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--" {
            cmd_index = Some(i + 1);
            break;
        }
        match args[i].as_str() {
            "--did" => {
                if i + 1 >= args.len() {
                    return Err("--did requires a value".into());
                }
                did_str = Some(args[i + 1].clone());
                i += 2;
            }
            "--cgroup-root" => {
                if i + 1 >= args.len() {
                    return Err("--cgroup-root requires a value".into());
                }
                cgroup_root = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let cmd_index = cmd_index.ok_or("missing `--` separator before command")?;
    if cmd_index >= args.len() {
        return Err("no command specified after `--`".into());
    }

    let did_str = did_str
        .or_else(|| env::var("RITMA_DID").ok())
        .ok_or("missing --did or RITMA_DID")?;

    let did = Did::parse(&did_str).map_err(|e| format!("invalid DID {did_str}: {e}"))?;
    let scope = match did.kind() {
        DidKind::Tenant => IsolationScope::Tenant,
        DidKind::Zone => IsolationScope::Zone,
        _ => IsolationScope::Service,
    };

    let cgroup_root = cgroup_root.unwrap_or_else(|| "/sys/fs/cgroup/ritma".to_string());

    // Optional filesystem namespace configuration from env.
    let chroot_path = env::var("RITMA_FS_CHROOT").ok();
    let ro_paths_env = env::var("RITMA_FS_READONLY").unwrap_or_default();
    let mask_paths_env = env::var("RITMA_FS_MASKED").unwrap_or_default();

    if chroot_path.is_some() || !ro_paths_env.is_empty() || !mask_paths_env.is_empty() {
        setup_fs_namespace(chroot_path.as_deref(), &ro_paths_env, &mask_paths_env)?;
    }

    let controller = CgroupV2Controller::new(cgroup_root);

    let cmd = &args[cmd_index];
    let cmd_args: Vec<&str> = args[cmd_index + 1..].iter().map(|s| s.as_str()).collect();

    let mut child = Command::new(cmd).args(&cmd_args).spawn()?;
    let pid = child.id() as i32;

    controller
        .attach_pid(scope, &did, pid)
        .map_err(|e| format!("failed to attach pid to cgroup: {e}"))?;

    let status = child.wait()?;
    exit(status.code().unwrap_or(1));
}

#[cfg(target_os = "linux")]
fn setup_fs_namespace(
    chroot_path: Option<&str>,
    ro_paths_env: &str,
    mask_paths_env: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::path::Path;

    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{chdir, chroot};

    // Create a new mount namespace.
    unshare(CloneFlags::CLONE_NEWNS)?;

    // Make existing mounts private to avoid propagating changes.
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)?;

    let ro_paths: Vec<&str> = ro_paths_env.split(':').filter(|s| !s.is_empty()).collect();
    let mask_paths: Vec<&str> = mask_paths_env
        .split(':')
        .filter(|s| !s.is_empty())
        .collect();

    // Bind-mount read-only paths.
    for p in ro_paths {
        if !Path::new(p).exists() {
            continue;
        }
        mount(Some(p), p, None::<&str>, MsFlags::MS_BIND, None::<&str>)?;
        mount(
            Some(p),
            p,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )?;
    }

    // Mask paths by mounting a small tmpfs over them.
    for p in mask_paths {
        if !Path::new(p).exists() {
            fs::create_dir_all(p)?;
        }
        mount(
            Some("tmpfs"),
            p,
            Some("tmpfs"),
            MsFlags::empty(),
            Some("size=4M,mode=0000"),
        )?;
    }

    // Optional chroot.
    if let Some(root) = chroot_path {
        chroot(root)?;
        chdir("/")?;
    }

    Ok(())
}
