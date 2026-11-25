# TP 3: Linux Access Control CTF
this is provided by eddine aka boualamallah djamel eddine
- **Course / Module:** Computer Systems Security

> [!NOTE]
> **Scope & Rules:** All enumeration, exploitation, and verification steps were carried out strictly inside the challenge container as the unprivileged `student` account. No root password guessing, host/Docker socket attacks, or kernel exploits were used.

---

## Table of Contents

- [Flags at a Glance](#flags-at-a-glance)
- [Setup & Session Recording](#setup--session-recording)
- [Flag 1: Hidden Does Not Mean Protected](#flag-1-hidden-does-not-mean-protected)
- [Flag 2: The Confused Deputy](#flag-2-the-confused-deputy)
- [Flag 3: Sudo and Least Privilege](#flag-3-sudo-and-least-privilege)
- [Flag 4: Root Executes What You Can Modify](#flag-4-root-executes-what-you-can-modify)
- [Flag 5: Linux Capabilities](#flag-5-linux-capabilities)
- [Wrap-Up & Remediation Matrix](#wrap-up--remediation-matrix)

---

## Flags at a Glance

| # | Recovered Value | Target Resource | Access-Control Failure |
| :- | :--- | :--- | :--- |
| **1** | `FLAG{hidden_files_are_not_access_control}` | `/opt/lab/data/.cache/.old/.tmp/.flag1` | Hidden dotfile with `0644` world-readable permissions |
| **2** | `FLAG{confused_deputy_reads_for_the_attacker}` | `/root/flag2.txt` | Confused deputy via SUID helper (`/opt/lab/bin/read-vault`) |
| **3** | `FLAG{least_privilege_is_not_optional}` | `/root/flag3.txt` | `NOPASSWD` `sudo` script invokes relative `./tar` |
| **4** | `FLAG{root_should_never_execute_student_writable_code}` | `/root/flag4.txt` | Root loop executes world-writable (`0777`) script |
| **5** | `FLAG{capabilities_can_be_more_precise_than_suid}` | `/root/flag5.txt` | `cap_dac_read_search=ep` on `/opt/lab/bin/lab-python` |

---

## Setup & Session Recording

Started an interactive shell via Python's `pty` module and recorded terminal activity to `~/tp3_session.log` while verifying identity (`uid=1001(student)`) and initial files in `/home/student`.

```bash
which python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
script -q -a ~/tp3_session.log
id && pwd && ls -la
```

![Setup & Initial Environment](./screenshots/01_setup_environment.png)

---

## Flag 1: Hidden Does Not Mean Protected

### Enumeration & Retrieval

```bash
find /opt/lab -name "*flag*" -o -name ".*" 2>/dev/null
ls -la /opt/lab/data/.cache/.old/.tmp/.flag1
namei -l /opt/lab/data/.cache/.old/.tmp/.flag1
cat /opt/lab/data/.cache/.old/.tmp/.flag1
```

> [!TIP]
> **Flag 1:** `FLAG{hidden_files_are_not_access_control}`

### Analysis & Fix

- **Permissions & Path:** `/opt/lab/data/.cache/.old/.tmp/.flag1` is owned by `root:root` with mode `-rw-r--r--` (`0644`), and all ancestor directories (`data`, `.cache`, `.old`, `.tmp`) have `drwxr-xr-x` (`0755`) permissions.
- **Root Cause:** Prefixing filenames or folders with `.` only hides entries from default `ls` output; Linux Discretionary Access Control (DAC) still grants read access to `others` and directory traversal (`x`) along the entire path.
- **Remediation:** Set `.flag1` to `chmod 600` (owned by `root:root`) and/or restrict directory permissions (`chmod 700`).

![Flag 1 Hidden File Permissions and Output](./screenshots/02_flag1_hidden_file.png)

---

## Flag 2: The Confused Deputy

### Enumeration & Retrieval

```bash
find / -perm -4000 -type f 2>/dev/null
ls -la /opt/lab/bin/read-vault
/opt/lab/bin/read-vault
/opt/lab/bin/read-vault /root/flag2.txt
```

> [!TIP]
> **Flag 2:** `FLAG{confused_deputy_reads_for_the_attacker}`

### Analysis & Fix

- **Mechanism:** `/opt/lab/bin/read-vault` (`-rwsr-xr-x`, owned by `root:root`) runs with effective UID `0` (`euid=0`) while accepting a `<file>` path from `student` (`uid=1001`).
- **Root Cause:** The SUID binary acts as a **confused deputy**—it uses `root` privileges to open arbitrary paths supplied by an unprivileged caller without checking whether the real user (`ruid`) is authorized to read that file.
- **Remediation:** Verify caller permissions against the real UID or drop privileges (`setresuid()` / `seteuid()`) before opening caller-supplied file paths.

![Flag 2 SUID Binary and Confused Deputy Output](./screenshots/03_flag2_confused_deputy.png)

---

## Flag 3: Sudo and Least Privilege

### Enumeration & Retrieval

```bash
sudo -l
cat /usr/local/bin/backup-report
cd /home/student && echo 'cat /root/flag3.txt > /home/student/flag3.txt' > tar && chmod +x tar
sudo /usr/local/bin/backup-report && cat /home/student/flag3.txt
```

> [!TIP]
> **Flag 3:** `FLAG{least_privilege_is_not_optional}`

### Analysis & Fix

- **Mechanism:** `sudo -l` grants `student` `(root) NOPASSWD: /usr/local/bin/backup-report`, which executes `./tar -cf /opt/lab/backups/student-backup.tar /opt/lab/data/* >/dev/null 2>&1` as `root`.
- **Root Cause:** Authorizing a `root` script that calls a relative command (`./tar`) allows `student` to place an executable `tar` script in `/home/student` and run arbitrary commands with `root` privileges.
- **Remediation:** Use explicit absolute binary paths inside privileged scripts (such as `/usr/bin/tar`), protect scripts and directories from unprivileged writes, and enforce `env_reset` and `secure_path` in `sudoers`.

![Flag 3 Sudo Rule, Backup Script, and Flag Output](./screenshots/04_flag3_sudo_path.png)

---

## Flag 4: Root Executes What You Can Modify

### Enumeration & Retrieval

```bash
ps aux | grep root
cat /opt/lab/bin/root-maintenance-loop.sh
ls -l /opt/lab/bin/maintenance.sh
echo 'cat /root/flag4.txt > /home/student/flag4.txt' > /opt/lab/bin/maintenance.sh && sleep 15 && cat /home/student/flag4.txt
```

> [!TIP]
> **Flag 4:** `FLAG{root_should_never_execute_student_writable_code}`

### Analysis & Fix

- **Mechanism:** A `root` process runs `/bin/bash /opt/lab/bin/root-maintenance-loop.sh`, executing `/opt/lab/bin/maintenance.sh` every 10 seconds. Although owned by `root:root`, `/opt/lab/bin/maintenance.sh` had mode `-rwxrwxrwx` (`0777`).
- **Root Cause:** A privileged execution loop trusted a file that any user could overwrite, allowing `student` to inject commands executed as `root`.
- **Remediation:** Set `chown root:root` and `chmod 755` (or `700`) on `/opt/lab/bin/maintenance.sh` and ensure privileged scripts are not writable by unprivileged accounts.

![Flag 4 Root Loop, 0777 Permissions, and Flag Output](./screenshots/05_flag4_writable_script.png)

---

## Flag 5: Linux Capabilities

### Enumeration & Capability Inspection

```bash
getcap -r / 2>/dev/null
ls -la /opt/lab/bin/lab-python
/opt/lab/bin/lab-python -c "import os; print(os.listdir('/root')); print(open('/root/flag5.txt').read())"
grep -E "Cap|NoNewPrivs" /proc/self/status && capsh --decode=$(awk '/CapBnd/{print $2}' /proc/self/status) 2>/dev/null || true
```

> [!TIP]
> **Flag 5:** `FLAG{capabilities_can_be_more_precise_than_suid}`

### Analysis & Fix

- **Mechanism & Runtime Observation:** `getcap -r / 2>/dev/null` found `/opt/lab/bin/lab-python` configured with `cap_dac_read_search=ep` (`-rwxr-xr-x`, owned by `root:root`). `CAP_DAC_READ_SEARCH` bypasses DAC read and directory search checks so `/root/flag5.txt` can be read without SUID. In this runtime environment, executing `/opt/lab/bin/lab-python` returned `Operation not permitted` (`EPERM`) because `CAP_DAC_READ_SEARCH` is omitted from the container's capability bounding set (`CapBnd: 00000000a80425fb`).
- **Root Cause:** Assigning `cap_dac_read_search=ep` to a general-purpose interpreter (`lab-python`) gives any user who can run it a broad DAC read/search bypass across restricted directories.
- **Remediation:** Remove the capability from the interpreter (`setcap -r /opt/lab/bin/lab-python`) and scope capabilities strictly to minimal, single-purpose binaries.

![Flag 5 Capabilities Scan, Execution Check, and Bounding Set](./screenshots/06_flag5_capabilities.png)

---

## Wrap-Up & Remediation Matrix

| # | Weakness | Mechanism | Privilege Gained | Primary Fix |
| :- | :--- | :--- | :--- | :--- |
| **1** | Hidden does not mean protected | `0644` file behind `.cache/.old/.tmp` (`0755`) | Standard DAC read | `chmod 600` on flag / `700` on parent folder |
| **2** | Confused deputy | SUID binary opens caller-supplied path | `euid=0` file read | Check `ruid` authorization / drop privileges |
| **3** | Over-broad `sudo` | `NOPASSWD` script resolves relative `./tar` | `root` command execution | Use absolute paths (`/usr/bin/tar`) & `secure_path` |
| **4** | Writable code run by `root` | `0777` script executed in a `root` loop | `root` code execution | `chown root:root` and `chmod 755` / `700` |
| **5** | Over-broad capability | `cap_dac_read_search=ep` on Python binary | DAC read/search bypass | `setcap -r` on interpreter; narrow capability scope |
