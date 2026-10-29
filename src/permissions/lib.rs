//! Immutable CLI resource policy shared by runtime and asynchronous native clients.
//!
//! This owns process-wide authority, not mutable per-VM state. CLI initialization
//! publishes an owned snapshot before user code; workers cannot replace it.

use std::sync::OnceLock;

mod endpoint_authorization;
pub use endpoint_authorization::ResolvedNetworkEndpoint;

use bun_core::{Fd, PathBuffer, ZBox};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    FsRead,
    FsWrite,
    Net,
    Env,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub enabled: bool,
    pub secure: bool,
    pub allow_inspector: bool,
    pub allow_run: bool,
    pub allow_worker: bool,
    pub allow_ffi: bool,
    pub allow_sys: bool,
    pub working_directory: Box<[u8]>,
    pub read: Vec<Box<[u8]>>,
    pub write: Vec<Box<[u8]>>,
    pub net: Vec<Box<[u8]>>,
    pub env: Vec<Box<[u8]>>,
}

#[derive(Debug)]
pub enum InitializationError {
    AlreadyInitialized,
    InvalidPathGrant,
    InvalidNetworkGrant,
    InvalidEnvironmentGrant,
}

impl std::fmt::Display for InitializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyInitialized => "the process permission policy cannot be replaced",
            Self::InvalidPathGrant => "invalid filesystem grant",
            Self::InvalidNetworkGrant => "invalid network grant (use an ASCII hostname or canonical IP with an optional port)",
            Self::InvalidEnvironmentGrant => "invalid environment-variable grant",
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PermissionDenied;

impl std::fmt::Display for PermissionDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Permission denied by experimental resource policy")
    }
}

impl std::error::Error for PermissionDenied {}

#[derive(Clone, Copy, Debug)]
pub enum NetworkOperation {
    Connect,
    Listen,
    Resolve,
}

#[derive(Clone, Copy, Debug)]
pub enum NetworkResource<'a> {
    Endpoint { host: &'a [u8], port: u16 },
    Hostname(&'a [u8]),
    UnixSocket(&'a [u8]),
}

#[derive(Debug)]
struct NetworkGrant {
    host: Vec<u8>,
    wildcard: bool,
    port: Option<u16>,
}

struct Policy {
    config: Config,
    read: Vec<PathGrant>,
    write: Vec<PathGrant>,
    net: Vec<NetworkGrant>,
    local: Vec<LocalGrant>,
}

enum LocalGrant {
    Filesystem(PathGrant),
    Abstract(Vec<u8>),
    Pipe(Vec<u8>),
}

struct PathGrant {
    target: Vec<u8>,
    entry: Vec<u8>,
}

static POLICY: OnceLock<Policy> = OnceLock::new();

pub fn initialize(config: Config) -> Result<(), InitializationError> {
    if let Some(policy) = POLICY.get() {
        return if policy.config == config {
            Ok(())
        } else {
            Err(InitializationError::AlreadyInitialized)
        };
    }
    let mut policy = Policy {
        config,
        read: Vec::new(),
        write: Vec::new(),
        net: Vec::new(),
        local: Vec::new(),
    };
    if policy.config.enabled {
        for (grants, paths) in [
            (&policy.config.read, &mut policy.read),
            (&policy.config.write, &mut policy.write),
        ] {
            for grant in grants {
                if grant.as_ref() == b"*" {
                    continue;
                }
                paths.push(PathGrant {
                    target: canonical_path_with_config(
                        grant,
                        &policy.config.working_directory,
                        Some(&policy.config),
                    )
                    .ok_or(InitializationError::InvalidPathGrant)?,
                    entry: canonical_entry_with_config(
                        grant,
                        &policy.config.working_directory,
                        Some(&policy.config),
                    )
                    .ok_or(InitializationError::InvalidPathGrant)?,
                });
            }
        }
        for grant in &policy.config.net {
            if grant.as_ref() == b"*" {
                continue;
            }
            if let Some(path) = grant.strip_prefix(b"unix:") {
                policy.local.push(LocalGrant::Filesystem(PathGrant {
                    target: canonical_path_with_config(
                        path,
                        &policy.config.working_directory,
                        Some(&policy.config),
                    )
                    .ok_or(InitializationError::InvalidNetworkGrant)?,
                    entry: canonical_entry_with_config(
                        path,
                        &policy.config.working_directory,
                        Some(&policy.config),
                    )
                    .ok_or(InitializationError::InvalidNetworkGrant)?,
                }));
            } else if let Some(name) = grant.strip_prefix(b"abstract:") {
                if name.is_empty() || name.contains(&0) || name.len() > 107 {
                    return Err(InitializationError::InvalidNetworkGrant);
                }
                policy.local.push(LocalGrant::Abstract(name.to_vec()));
            } else if let Some(name) = grant.strip_prefix(b"pipe:") {
                if name.is_empty() || name.contains(&0) || name.len() > 256 {
                    return Err(InitializationError::InvalidNetworkGrant);
                }
                policy
                    .local
                    .push(LocalGrant::Pipe(name.to_ascii_lowercase()));
            } else {
                policy.net.push(
                    parse_network_grant(grant).ok_or(InitializationError::InvalidNetworkGrant)?,
                );
            }
        }
        for grant in &policy.config.env {
            if grant.is_empty()
                || grant.contains(&0)
                || grant.contains(&b'=')
                || grant[..grant.len().saturating_sub(1)].contains(&b'*')
            {
                return Err(InitializationError::InvalidEnvironmentGrant);
            }
        }
    }
    POLICY
        .set(policy)
        .map_err(|_| InitializationError::AlreadyInitialized)
}

// An uninitialized process is the ordinary unrestricted bootstrap/embedder.
// CLI execution must publish its final policy before creating user VMs.
pub fn enabled() -> bool {
    POLICY.get().is_some_and(|policy| policy.config.enabled)
}

fn entries(policy: &Policy, scope: Scope) -> &[Box<[u8]>] {
    match scope {
        Scope::FsRead => &policy.config.read,
        Scope::FsWrite => &policy.config.write,
        Scope::Net => &policy.config.net,
        Scope::Env => &policy.config.env,
    }
}

pub fn is_restricted(scope: Scope) -> bool {
    POLICY.get().is_some_and(|policy| {
        policy.config.enabled
            && !entries(policy, scope)
                .iter()
                .any(|entry| entry.as_ref() == b"*")
            && (policy.config.secure || !entries(policy, scope).is_empty())
    })
}

pub fn any_restricted() -> bool {
    [Scope::FsRead, Scope::FsWrite, Scope::Net, Scope::Env]
        .into_iter()
        .any(is_restricted)
}

#[derive(Clone, Copy, Debug)]
pub enum Capability {
    Subprocess,
    Shell,
    Worker,
    ForeignFunction,
    NativeAddon,
    NativeExtension,
    Inspector,
    SystemInformation,
    ProcessControl,
}

pub fn capability_allowed(capability: Capability) -> bool {
    let Some(policy) = POLICY.get() else {
        return true;
    };
    if !policy.config.enabled || (!policy.config.secure && !any_restricted()) {
        return true;
    }
    match capability {
        Capability::Subprocess | Capability::Shell => policy.config.allow_run,
        Capability::Worker => policy.config.allow_worker,
        Capability::ForeignFunction | Capability::NativeAddon | Capability::NativeExtension => {
            policy.config.allow_ffi
        }
        Capability::Inspector => policy.config.allow_inspector,
        Capability::SystemInformation | Capability::ProcessControl => policy.config.allow_sys,
    }
}

pub fn inspector_allowed() -> bool {
    capability_allowed(Capability::Inspector)
}

pub fn allows(scope: Scope, resource: &[u8]) -> bool {
    if matches!(scope, Scope::FsRead | Scope::FsWrite) {
        return check_path(scope, resource);
    }
    if !is_restricted(scope) {
        return true;
    }
    let Some(policy) = POLICY.get() else {
        return false;
    };
    match scope {
        Scope::FsRead | Scope::FsWrite => check_path(scope, resource),
        Scope::Net => {
            for prefix in [&b"unix:"[..], &b"abstract:"[..], &b"pipe:"[..]] {
                if let Some(name) = resource.strip_prefix(prefix) {
                    let path = if prefix == b"abstract:" {
                        let mut path = vec![0];
                        path.extend_from_slice(name);
                        path
                    } else if prefix == b"pipe:" {
                        let mut path = br"\\.\pipe\".to_vec();
                        path.extend_from_slice(name);
                        path
                    } else {
                        name.to_vec()
                    };
                    return check_local(NetworkOperation::Connect, &path).is_ok();
                }
            }
            let Some(grant) = parse_network_grant(resource) else {
                return false;
            };
            if grant.wildcard {
                return false;
            }
            let endpoint = match grant.port {
                Some(port) => NetworkResource::Endpoint {
                    host: &grant.host,
                    port,
                },
                None => NetworkResource::Hostname(&grant.host),
            };
            check_network(
                if grant.port.is_some() {
                    NetworkOperation::Connect
                } else {
                    NetworkOperation::Resolve
                },
                endpoint,
            )
            .is_ok()
        }
        Scope::Env => {
            if resource.is_empty() || resource.contains(&0) || resource.contains(&b'=') {
                return false;
            }
            policy.config.env.iter().any(|entry| {
                let prefix = entry.last() == Some(&b'*');
                let grant = if prefix {
                    &entry[..entry.len() - 1]
                } else {
                    entry.as_ref()
                };
                if prefix {
                    resource
                        .get(..grant.len())
                        .is_some_and(|value| equal_environment(value, grant))
                } else {
                    equal_environment(resource, grant)
                }
            })
        }
    }
}

fn equal_environment(left: &[u8], right: &[u8]) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// Windows filesystem paths can exercise network authority even with wildcard filesystem grants.
pub fn requires_path_check(scope: Scope) -> bool {
    is_restricted(scope) || (cfg!(windows) && is_restricted(Scope::Net))
}

pub fn check_path(scope: Scope, path: &[u8]) -> bool {
    if !matches!(scope, Scope::FsRead | Scope::FsWrite) {
        return false;
    }
    if !filesystem_network_allowed(path, false) {
        return false;
    }
    if !is_restricted(scope) {
        return true;
    }
    let Some(policy) = POLICY.get() else {
        return false;
    };
    let Ok(cwd) = bun_sys::getcwd_alloc() else {
        return false;
    };
    let Some(path) = canonical_path(path, cwd.as_zstr().as_bytes()) else {
        return false;
    };
    let grants = match scope {
        Scope::FsRead => &policy.read,
        _ => &policy.write,
    };
    grants.iter().any(|grant| path_within(&path, &grant.target))
}

/// Authorize a directory entry without following its final symlink.
pub fn check_entry(scope: Scope, path: &[u8]) -> bool {
    if !matches!(scope, Scope::FsRead | Scope::FsWrite) {
        return false;
    }
    if !filesystem_network_allowed(path, true) {
        return false;
    }
    if !is_restricted(scope) {
        return true;
    }
    let Some(policy) = POLICY.get() else {
        return false;
    };
    let Ok(cwd) = bun_sys::getcwd_alloc() else {
        return false;
    };
    let Some(path) = canonical_entry(path, cwd.as_zstr().as_bytes()) else {
        return false;
    };
    let grants = match scope {
        Scope::FsRead => &policy.read,
        _ => &policy.write,
    };
    grants
        .iter()
        .any(|grant| path_within(&path, &grant.target) || path_within(&path, &grant.entry))
}

fn canonical_entry(path: &[u8], cwd: &[u8]) -> Option<Vec<u8>> {
    canonical_entry_with_config(path, cwd, POLICY.get().map(|policy| &policy.config))
}

fn canonical_entry_with_config(
    path: &[u8],
    cwd: &[u8],
    config: Option<&Config>,
) -> Option<Vec<u8>> {
    // A trailing separator makes the kernel traverse the final component even
    // for lstat/readlink/lutimes. Preserve this before absolute_path trims it.
    if path.last().is_some_and(|byte| separator(*byte)) {
        return canonical_path_with_config(path, cwd, config);
    }
    let absolute = absolute_path(path, cwd)?;
    let Some(parent) = bun_paths::dirname(&absolute) else {
        return canonical_path_with_config(&absolute, cwd, config);
    };
    if parent.len() == absolute.len() {
        return canonical_path_with_config(&absolute, cwd, config);
    }
    let leaf = absolute[parent.len()..]
        .iter()
        .copied()
        .skip_while(|byte| separator(*byte))
        .collect::<Vec<_>>();
    if leaf.is_empty() {
        return canonical_path_with_config(&absolute, cwd, config);
    }
    let mut result = canonical_path_with_config(parent, cwd, config)?;
    if !result.last().is_some_and(|byte| separator(*byte)) {
        result.push(b'/');
    }
    result.extend_from_slice(&leaf);
    (result.len() < bun_core::MAX_PATH_BYTES).then_some(result)
}

pub fn check_fd(scope: Scope, descriptor: Fd) -> bool {
    if !matches!(scope, Scope::FsRead | Scope::FsWrite) {
        return false;
    }
    if !requires_path_check(scope) {
        return true;
    }
    if !descriptor.is_valid() {
        return false;
    }
    let mut buffer = PathBuffer::uninit();
    let Ok(path) = permission_descriptor_path(descriptor, &mut buffer) else {
        return false;
    };
    check_path(scope, path)
}

// FILE_NAME_OPENED avoids SMB normalization queries before host authorization.
fn permission_descriptor_path(descriptor: Fd, buffer: &mut PathBuffer) -> bun_sys::Maybe<&[u8]> {
    #[cfg(windows)]
    if is_restricted(Scope::Net) {
        return bun_sys::windows::get_fd_path_opened_only(descriptor, buffer);
    }
    bun_sys::get_fd_path(descriptor, buffer).map(|path| &*path)
}

/// Authorize a child relative to a directory descriptor, without changing cwd.
pub fn check_at_path(scope: Scope, directory: Fd, path: &[u8], entry: bool) -> bool {
    if !matches!(scope, Scope::FsRead | Scope::FsWrite) {
        return false;
    }
    if !requires_path_check(scope) {
        return true;
    }
    let check = |path: &[u8]| {
        if entry {
            check_entry(scope, path)
        } else {
            check_path(scope, path)
        }
    };
    if bun_paths::is_absolute(path) || directory == Fd::cwd() {
        return check(path);
    }
    if !directory.is_valid() {
        return false;
    }
    let mut buffer = PathBuffer::uninit();
    let Ok(parent) = permission_descriptor_path(directory, &mut buffer) else {
        return false;
    };
    let Some(path) = absolute_path(path, parent) else {
        return false;
    };
    check(&path)
}

fn separator(byte: u8) -> bool {
    byte == b'/' || (cfg!(windows) && byte == b'\\')
}

fn path_within(path: &[u8], grant: &[u8]) -> bool {
    let matches = |a: &[u8], b: &[u8]| {
        if cfg!(windows) {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    matches(path, grant)
        || (path
            .get(..grant.len())
            .is_some_and(|prefix| matches(prefix, grant))
            && (grant.last().is_some_and(|byte| separator(*byte))
                || path.get(grant.len()).is_some_and(|byte| separator(*byte))))
}

fn absolute_path(path: &[u8], cwd: &[u8]) -> Option<Vec<u8>> {
    if path.is_empty()
        || path.contains(&0)
        || path.len() >= bun_core::MAX_PATH_BYTES
        || path
            .split(|byte| separator(*byte))
            .any(|part| part == b"..")
    {
        return None;
    }
    #[cfg(windows)]
    if path.starts_with(b"\\\\?\\")
        || path.starts_with(b"\\\\.\\")
        || path.contains(&b':') && !bun_paths::is_absolute(path)
    {
        return None;
    }
    let mut absolute = if bun_paths::is_absolute(path) {
        path.to_vec()
    } else {
        let mut joined = cwd.to_vec();
        joined.push(b'/');
        joined.extend_from_slice(path);
        joined
    };
    if absolute.len() >= bun_core::MAX_PATH_BYTES {
        return None;
    }
    while absolute.len() > 1 && absolute.last().is_some_and(|byte| separator(*byte)) {
        if cfg!(windows) && absolute.len() == 3 && absolute[1] == b':' {
            break;
        }
        absolute.pop();
    }
    Some(absolute)
}

fn filesystem_network_allowed(path: &[u8], entry: bool) -> bool {
    if !cfg!(windows) || !is_restricted(Scope::Net) {
        return true;
    }
    let Ok(cwd) = bun_sys::getcwd_alloc() else {
        return false;
    };
    absolute_path(path, cwd.as_zstr().as_bytes()).is_some_and(|absolute| {
        let config = POLICY.get().map(|policy| &policy.config);
        if !unc_network_allowed(&absolute, config) {
            return false;
        }
        // Entry operations do not traverse the final symlink unless the
        // caller supplied a trailing separator. Check its parent instead.
        let inspected = if entry && !path.last().is_some_and(|byte| separator(*byte)) {
            bun_paths::dirname(&absolute).unwrap_or(&absolute)
        } else {
            &absolute
        };
        filesystem_path_preflight(inspected, config)
    })
}

// Reject local reparses and remote drive mappings before realpath can contact
// a redirector. Direct UNC roots are checked against the network grant first.
fn filesystem_path_preflight(absolute: &[u8], config: Option<&Config>) -> bool {
    if !unc_network_allowed(absolute, config) {
        return false;
    }
    #[cfg(windows)]
    if config.is_some_and(|config| {
        config.enabled
            && (config.secure || !config.net.is_empty())
            && !config.net.iter().any(|grant| grant.as_ref() == b"*")
    }) {
        return bun_sys::windows::check_path_without_remote_reparse(absolute).is_ok();
    }
    true
}

fn unc_network_allowed(absolute: &[u8], config: Option<&Config>) -> bool {
    if !cfg!(windows)
        || !absolute.starts_with(b"\\\\")
            && !absolute.starts_with(b"//")
            && !(absolute.len() >= 2 && separator(absolute[0]) && separator(absolute[1]))
    {
        return true;
    }
    let host = absolute[2..]
        .split(|byte| separator(*byte))
        .next()
        .unwrap_or_default();
    unc_host_allowed(host, config)
}

fn unc_host_allowed(host: &[u8], config: Option<&Config>) -> bool {
    let Some(config) = config.filter(|config| config.enabled) else {
        return true;
    };
    if (!config.secure && config.net.is_empty())
        || config.net.iter().any(|grant| grant.as_ref() == b"*")
    {
        return true;
    }
    let Some(host) = normalize_host(host) else {
        return false;
    };
    // A UNC path delegates protocol/port selection to the OS redirector. A
    // port-scoped TCP grant must not authorize that wider native capability.
    config
        .net
        .iter()
        .filter_map(|grant| parse_network_grant(grant))
        .any(|grant| {
            grant.port.is_none()
                && if grant.wildcard {
                    host.len() > grant.host.len() + 1
                        && host.ends_with(&grant.host)
                        && host[host.len() - grant.host.len() - 1] == b'.'
                } else {
                    host == grant.host
                }
        })
}

fn canonical_path(path: &[u8], cwd: &[u8]) -> Option<Vec<u8>> {
    canonical_path_with_config(path, cwd, POLICY.get().map(|policy| &policy.config))
}

fn canonical_path_with_config(path: &[u8], cwd: &[u8], config: Option<&Config>) -> Option<Vec<u8>> {
    let mut absolute = absolute_path(path, cwd)?;
    if !filesystem_path_preflight(&absolute, config) {
        return None;
    }
    let mut suffix: Vec<Vec<u8>> = Vec::new();
    loop {
        if !filesystem_path_preflight(&absolute, config) {
            return None;
        }
        let name = ZBox::from_bytes(&absolute);
        let mut buffer = PathBuffer::uninit();
        match bun_sys::realpath(name.as_zstr(), &mut buffer) {
            Ok(canonical) => {
                let mut result = canonical.to_vec();
                if !unc_network_allowed(&result, config) {
                    return None;
                }
                for component in suffix.iter().rev() {
                    if !result.last().is_some_and(|byte| separator(*byte)) {
                        result.push(b'/');
                    }
                    result.extend_from_slice(component);
                }
                return (result.len() < bun_core::MAX_PATH_BYTES).then_some(result);
            }
            Err(error) => {
                if error.errno != bun_sys::E::ENOENT as _ {
                    return None;
                }
                // A dangling symlink is not a missing destination component.
                match bun_sys::lstat(name.as_zstr()) {
                    Err(error) if error.errno == bun_sys::E::ENOENT as _ => {}
                    _ => return None,
                }
                let parent = bun_paths::dirname(&absolute)?;
                if parent.len() == absolute.len() || parent.is_empty() {
                    return None;
                }
                let component = absolute[parent.len()..]
                    .iter()
                    .copied()
                    .skip_while(|byte| separator(*byte))
                    .collect::<Vec<_>>();
                if component.is_empty() || component == b"." || component == b".." {
                    return None;
                }
                suffix.push(component);
                absolute.truncate(parent.len());
            }
        }
    }
}

fn normalize_host(host: &[u8]) -> Option<Vec<u8>> {
    let host = host
        .strip_prefix(b"[")
        .and_then(|value| value.strip_suffix(b"]"))
        .unwrap_or(host);
    let host = host.strip_suffix(b".").unwrap_or(host);
    if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(host).ok()?;
    if let Ok(ip) = text.parse::<std::net::IpAddr>() {
        return Some(ip.to_string().into_bytes());
    }
    if host
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return None;
    }
    if !host.split(|byte| *byte == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
    }) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn parse_network_grant(input: &[u8]) -> Option<NetworkGrant> {
    let (host, port) = if input.starts_with(b"[") {
        let close = input.iter().position(|byte| *byte == b']')?;
        let rest = &input[close + 1..];
        let port = if rest.is_empty() {
            None
        } else {
            Some(
                std::str::from_utf8(rest.strip_prefix(b":")?)
                    .ok()?
                    .parse()
                    .ok()?,
            )
        };
        (&input[1..close], port)
    } else if input.iter().filter(|byte| **byte == b':').count() == 1 {
        let colon = input.iter().position(|byte| *byte == b':')?;
        (
            &input[..colon],
            Some(
                std::str::from_utf8(&input[colon + 1..])
                    .ok()?
                    .parse()
                    .ok()?,
            ),
        )
    } else {
        (input, None)
    };
    let wildcard = host.starts_with(b"*.");
    let host = normalize_host(if wildcard { &host[2..] } else { host })?;
    if wildcard
        && std::str::from_utf8(&host)
            .ok()?
            .parse::<std::net::IpAddr>()
            .is_ok()
    {
        return None;
    }
    Some(NetworkGrant {
        host,
        wildcard,
        port,
    })
}

pub fn check_network(
    operation: NetworkOperation,
    resource: NetworkResource<'_>,
) -> Result<(), PermissionDenied> {
    if let NetworkResource::UnixSocket(path) = resource {
        return check_local(operation, path);
    }
    if !is_restricted(Scope::Net) {
        return Ok(());
    }
    let Some(policy) = POLICY.get() else {
        return Err(PermissionDenied);
    };
    let (host, port) = match resource {
        NetworkResource::Endpoint { host, port } => (host, Some(port)),
        NetworkResource::Hostname(host) => (host, None),
        NetworkResource::UnixSocket(_) => return Err(PermissionDenied),
    };
    let host = normalize_host(host).ok_or(PermissionDenied)?;
    let authorized = policy.net.iter().any(|grant| {
        let hostname_matches = if grant.wildcard {
            host.len() > grant.host.len() + 1
                && host.ends_with(&grant.host)
                && host[host.len() - grant.host.len() - 1] == b'.'
        } else {
            host == grant.host
        };
        hostname_matches
            && (matches!(operation, NetworkOperation::Resolve)
                || grant.port.is_none()
                || grant.port == port)
    });
    if authorized {
        Ok(())
    } else {
        Err(PermissionDenied)
    }
}

fn check_local(operation: NetworkOperation, path: &[u8]) -> Result<(), PermissionDenied> {
    let abstract_name = path.strip_prefix(&[0]);
    let pipe_prefix = br"\\.\pipe\";
    let pipe_name = if cfg!(windows)
        && path
            .get(..pipe_prefix.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(pipe_prefix))
    {
        Some(&path[pipe_prefix.len()..])
    } else {
        None
    };
    let filesystem = abstract_name.is_none() && pipe_name.is_none();
    if filesystem
        && matches!(operation, NetworkOperation::Listen)
        && (!check_entry(Scope::FsWrite, path) || !check_path(Scope::FsWrite, path))
    {
        return Err(PermissionDenied);
    }
    if !is_restricted(Scope::Net) {
        return Ok(());
    }
    let Some(policy) = POLICY.get() else {
        return Err(PermissionDenied);
    };
    let canonical = if filesystem {
        let cwd = bun_sys::getcwd_alloc().map_err(|_| PermissionDenied)?;
        Some(canonical_path(path, cwd.as_zstr().as_bytes()).ok_or(PermissionDenied)?)
    } else {
        None
    };
    let authorized = policy.local.iter().any(|grant| match grant {
        LocalGrant::Filesystem(grant) => canonical
            .as_ref()
            .is_some_and(|path| path == &grant.target || path == &grant.entry),
        LocalGrant::Abstract(grant) => abstract_name.is_some_and(|name| name == grant),
        LocalGrant::Pipe(grant) => pipe_name.is_some_and(|name| name.eq_ignore_ascii_case(grant)),
    });
    if authorized {
        Ok(())
    } else {
        Err(PermissionDenied)
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;

    fn network_config(grants: &[&[u8]]) -> Config {
        Config {
            enabled: true,
            secure: true,
            allow_inspector: false,
            allow_run: false,
            allow_worker: false,
            allow_ffi: false,
            allow_sys: false,
            working_directory: b"/".into(),
            read: Vec::new(),
            write: Vec::new(),
            net: grants.iter().map(|grant| (*grant).into()).collect(),
            env: Vec::new(),
        }
    }

    #[test]
    fn unc_requires_unported_hostname_authority_before_policy_publication() {
        let config = network_config(&[b"files.example:445"]);
        assert!(!unc_host_allowed(b"files.example", Some(&config)));
        let config = network_config(&[b"files.example"]);
        assert!(unc_host_allowed(b"FILES.EXAMPLE", Some(&config)));
        assert!(!unc_host_allowed(b"other.example", Some(&config)));
        let config = network_config(&[b"*.example"]);
        assert!(unc_host_allowed(b"files.example", Some(&config)));
        assert!(!unc_host_allowed(b"example", Some(&config)));
        assert!(!unc_host_allowed(b"notexample", Some(&config)));
        let config = network_config(&[]);
        assert!(!unc_host_allowed(b"files.example", Some(&config)));
        let config = network_config(&[b"*"]);
        assert!(unc_host_allowed(b"files.example", Some(&config)));
        assert!(unc_host_allowed(b"files.example", None));
        let mut config = network_config(&[]);
        config.secure = false;
        assert!(unc_host_allowed(b"files.example", Some(&config)));
    }
}
