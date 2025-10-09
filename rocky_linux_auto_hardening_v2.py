#!/usr/bin/env python3
"""
cis_rocky9_l1.py — CIS Rocky Linux 9 v2.0.0 (Level 1 Server)

Características:
- Interactivo por defecto (confirmación por bloque); --auto aplica todo sin preguntar
- --crypto-policy DEFAULT|FUTURE
- Backups por sesión (manifest + tar.gz) y rollback --rollback <timestamp>
- Resumen final (aplicados / saltados / fallidos)
- Controles L1 integrados: módulos kernel, montajes, autofs, DNF, SELinux, GRUB, kernel, crypto,
  servicios/cron/at (permisos), sysctl red, firewalld, SSH/sudo/su/PAM/políticas/cron/banners,
  journald/rsyslog/auditd/AIDE, permisos /var/log, y dconf/GDM si existe GUI.

ADVERTENCIA: Cambios en SSH/SELinux/GRUB/audit/firewall pueden cortar acceso remoto.
Prueba en preproducción y ten consola fuera de banda (OOB).
"""

import argparse
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

# -------------------- Utilidades base --------------------

def check_root():
    if os.geteuid() != 0:
        sys.exit("[!] Debe ejecutarse como root")

def run(cmd, check=True, capture=False, shell=False):
    printable = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    log(f"$ {printable}")
    try:
        if capture:
            out = subprocess.run(cmd, check=check, text=True, capture_output=True, shell=shell)
            return out.stdout.strip()
        else:
            subprocess.run(cmd, check=check, shell=shell, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            return ""
    except subprocess.CalledProcessError as e:
        log(f"  [!] error ({e.returncode}) ejecutando: {printable}")
        if check:
            raise
        return ""

SESSION_TS = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
LOG_DIR = Path("/var/log/cis-hardener")
BACKUP_ROOT = Path("/var/backups/cis-hardener")
BACKUP_SESSION = BACKUP_ROOT / SESSION_TS
LOG_FILE = LOG_DIR / f"{SESSION_TS}.log"

def ensure_dirs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_SESSION.mkdir(parents=True, exist_ok=True)

def log(msg):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{os.uname().nodename}] {msg}\n")
    print(msg)

def press(title, auto=False):
    if auto:
        print(f"\n➤ {title}  [AUTO: aplicar]")
        return True
    try:
        ans = input(f"\n➤ {title}  [ENTER=aplicar | s=salta | q=salir]: ").strip().lower()
    except EOFError:
        ans = ""
    if ans == "q":
        log("Saliendo por petición del usuario.")
        sys.exit(0)
    return ans != "s"

def manifest_path() -> Path:
    return BACKUP_SESSION / "manifest.txt"

def already_backed_up(path: Path) -> bool:
    m = manifest_path()
    if not m.exists():
        return False
    try:
        return path.as_posix() in m.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False

def backup_file(path: Path):
    """
    Copia preservando estructura bajo BACKUP_SESSION.
    - Evita rutas absolutas (usamos lstrip('/')).
    - No repite backups dentro de la misma sesión.
    """
    try:
        if not path.exists() or already_backed_up(path):
            return
        dest = BACKUP_SESSION / path.as_posix().lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        manifest_path().parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path(), "a", encoding="utf-8") as man:
            man.write(path.as_posix() + "\n")
        log(f"  [bk] {path} -> {dest}")
    except Exception as e:
        log(f"  [!] backup falló para {path}: {e}")

def restore_session(ts: str):
    sdir = BACKUP_ROOT / ts
    man = sdir / "manifest.txt"
    if not man.exists():
        tgz = BACKUP_ROOT / f"{ts}.tar.gz"
        if tgz.exists():
            print(f"[*] Extrayendo {tgz} ...")
            with tarfile.open(tgz, "r:gz") as t:
                t.extractall(path=BACKUP_ROOT)
            sdir = BACKUP_ROOT / ts
            man = sdir / "manifest.txt"
        if not man.exists():
            sys.exit(f"[!] No encuentro sesión {ts} en {BACKUP_ROOT}")
    print(f"[*] Restaurando backups de {ts} ...")
    for line in man.read_text(encoding="utf-8", errors="ignore").splitlines():
        src = sdir / line.lstrip("/")
        dst = Path(line)
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            print(f"  [<-] {dst} restaurado")
    run(["sysctl", "--system"], check=False)
    run(["systemctl", "daemon-reload"], check=False)
    if shutil.which("augenrules"):
        run(["augenrules", "--load"], check=False)
    if Path("/boot/grub2").exists():
        run(["grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"], check=False)
    print("[OK] Rollback completado.")
    sys.exit(0)

def write_or_replace_kv(file: Path, key: str, value: str, sep=" "):
    backup_file(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    lines = file.read_text(encoding="utf-8", errors="ignore").splitlines() if file.exists() else []
    pat = re.compile(rf"^\s*{re.escape(key)}\b")
    hit = False
    out = []
    for ln in lines:
        if pat.match(ln):
            out.append(f"{key}{sep}{value}")
            hit = True
        else:
            out.append(ln)
    if not hit:
        out.append(f"{key}{sep}{value}")
    file.write_text("\n".join(out) + "\n", encoding="utf-8")

def append_once(file: Path, line: str):
    backup_file(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    if file.exists() and line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
        return
    with open(file, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def sysctl_set(key: str, value: str):
    f = Path("/etc/sysctl.d/60-cis.conf")
    backup_file(f)
    if not f.exists():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("", encoding="utf-8")
    txt = f.read_text(encoding="utf-8", errors="ignore")
    pat = re.compile(rf"^\s*{re.escape(key)}\s*=\s*.*$", re.M)
    if pat.search(txt):
        txt = pat.sub(f"{key} = {value}", txt)
    else:
        if txt and not txt.endswith("\n"):
            txt += "\n"
        txt += f"{key} = {value}\n"
    f.write_text(txt, encoding="utf-8")
    subprocess.run(["sysctl", "-w", f"{key}={value}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def file_contains(path: Path, regex: str):
    if not path.exists():
        return False
    return re.search(regex, path.read_text(encoding="utf-8", errors="ignore"), re.M) is not None

# -------------------- Controles (bloques) --------------------

def ctrl_fs_modules():
    # 1.1.1 — Deshabilitar módulos de kernel no usados
    mods = ["cramfs","freevxfs","hfs","hfsplus","jffs2","squashfs","udf","usb-storage"]
    for m in mods:
        conf = Path(f"/etc/modprobe.d/{m}.conf")
        backup_file(conf)
        append_once(conf, f"install {m} /bin/false")
        append_once(conf, f"blacklist {m}")
        out = run(["lsmod"], check=False, capture=True)
        if re.search(rf"^{re.escape(m).replace('-', '_')}\b", out or "", re.M):
            run(["modprobe", "-r", m], check=False)
            run(["rmmod", m], check=False)

def ctrl_mounts():
    # 1.1.2 — Montajes nodev/nosuid/noexec (si existen en /etc/fstab)
    pairs = [
        ("/tmp", ["nodev","nosuid","noexec"]),
        ("/dev/shm", ["nodev","nosuid","noexec"]),
        ("/home", ["nodev","nosuid"]),
        ("/var", ["nodev","nosuid"]),
        ("/var/tmp", ["nodev","nosuid","noexec"]),
        ("/var/log", ["nodev","nosuid","noexec"]),
        ("/var/log/audit", ["nodev","nosuid","noexec"]),
    ]
    fstab = Path("/etc/fstab")
    fstab_txt = fstab.read_text(encoding="utf-8", errors="ignore") if fstab.exists() else ""
    for mnt, opts in pairs:
        if not re.search(rf"\s{re.escape(mnt)}\s", fstab_txt):
            log(f"  [!] {mnt} no tiene entrada en /etc/fstab (se omite)")
            continue
        for opt in opts:
            out = run(["findmnt", "-kn", mnt], check=False, capture=True)
            if out and (f",{opt}," in out or out.strip().endswith(f",{opt}") or f",{opt}" in out.strip()):
                continue
            backup_file(fstab)
            lines = fstab.read_text(encoding="utf-8", errors="ignore").splitlines()
            new = []
            for ln in lines:
                if not ln.strip() or ln.strip().startswith("#"):
                    new.append(ln); continue
                cols = re.split(r"\s+", ln.strip())
                if len(cols) >= 4 and cols[1] == mnt and opt not in cols[3].split(","):
                    cols[3] = cols[3] + "," + opt
                    ln = "\t".join(cols)
                new.append(ln)
            fstab.write_text("\n".join(new) + "\n", encoding="utf-8")
            run(["mount", "-o", "remount", mnt], check=False)

def ctrl_autofs():
    # 1.1.3 — Deshabilitar automontaje
    run(["systemctl", "disable", "--now", "autofs"], check=False)
    run(["systemctl", "mask", "autofs"], check=False)

def ctrl_dnf():
    # 1.2 — DNF seguro
    write_or_replace_kv(Path("/etc/dnf/dnf.conf"), "gpgcheck", "1", sep="=")
    for repo in Path("/etc/yum.repos.d").glob("*.repo"):
        backup_file(repo)
        txt = repo.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^\s*gpgcheck\s*=", txt, re.M):
            txt = re.sub(r"^\s*gpgcheck\s*=.*$", "gpgcheck=1", txt, flags=re.M)
        else:
            txt += ("\n" if not txt.endswith("\n") else "") + "gpgcheck=1\n"
        repo.write_text(txt, encoding="utf-8")
        if re.search(r"^\s*baseurl\s*=\s*http://", txt, re.M):
            log(f"  [!] repo http:// detectado en {repo} (recom. https://)")

def ctrl_selinux():
    # 1.3 — SELinux
    run(["grubby", "--update-kernel", "ALL", "--remove-args", "selinux=0 enforcing=0"], check=False)
    write_or_replace_kv(Path("/etc/selinux/config"), "SELINUX", "enforcing")
    if shutil.which("setenforce"):
        run(["setenforce", "1"], check=False)

def ctrl_grub():
    # 1.4 — Protecciones GRUB
    for d in [Path("/boot/grub2"), Path("/boot/efi/EFI/rocky")]:
        if d.exists():
            run(["chown", "-R", "root:root", str(d)], check=False)
            run(["chmod", "-R", "go-rwx", str(d)], check=False)
    f = Path("/etc/grub.d/40_custom")
    backup_file(f)
    content = f.read_text(encoding="utf-8", errors="ignore") if f.exists() else ""
    if "set superusers=" not in content:
        content += '\nset superusers="root"\n'
    if "password_pbkdf2" not in content:
        content += '# Ejecuta: grub2-mkpasswd-pbkdf2 y pega aquí: password_pbkdf2 root <hash>\n'
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    if Path("/boot/efi/EFI/rocky").exists():
        run(["grub2-mkconfig", "-o", "/boot/efi/EFI/rocky/grub.cfg"], check=False)
    else:
        run(["grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"], check=False)

def ctrl_kernel():
    # 1.5 — Kernel hardening
    sysctl_set("kernel.randomize_va_space", "2")
    sysctl_set("kernel.yama.ptrace_scope", "1")
    cdir = Path("/etc/systemd/coredump.conf.d")
    cdir.mkdir(parents=True, exist_ok=True)
    f = cdir / "60-coredump.conf"
    backup_file(f)
    f.write_text("[Coredump]\nProcessSizeMax=0\nStorage=none\n", encoding="utf-8")
    run(["systemctl", "daemon-reload"], check=False)

def ctrl_crypto(policy="DEFAULT"):
    # 1.6 — Crypto policy
    if shutil.which("update-crypto-policies"):
        run(["update-crypto-policies", "--set", policy], check=False)
        run(["update-crypto-policies"], check=False)
    else:
        log("  [!] update-crypto-policies no disponible")

def ctrl_services():
    # 2.x — Servicios/paquetes legacy + cron/at completos
    # chrony
    run(["dnf", "-y", "install", "chrony"], check=False)
    run(["systemctl", "enable", "--now", "chronyd"], check=False)

    # postfix loopback (si existe)
    if shutil.which("postfix") or Path("/etc/postfix/main.cf").exists():
        write_or_replace_kv(Path("/etc/postfix/main.cf"), "inet_interfaces", "loopback-only")
        run(["systemctl", "enable", "--now", "postfix"], check=False)
        run(["systemctl", "reload", "postfix"], check=False)

    # Paquetes legacy a eliminar
    pkgs = ["setroubleshoot","setroubleshoot-server","mcstrans","telnet","telnet-server","tftp","tftp-server",
            "ypbind","ypserv","rsh","rsh-server","talk","talk-server","xinetd","vsftpd"]
    for p in pkgs: run(["dnf","-y","remove",p], check=False)

    # Servicios legacy a deshabilitar/mask
    svcs = ["autofs.service","avahi-daemon.socket","bluetooth.service","cups.socket","cyrus-imapd.service","dhcpd.service",
            "dnsmasq.service","dovecot.service","dovecot.socket","httpd.service","httpd.socket","named.service",
            "nfs-server.service","nginx.service","rpcbind.socket","rsyncd.socket","smb.service","snmpd.service",
            "squid.service","telnet.socket","tftp.socket","vsftpd.service","xinetd.service","ypserv.service"]
    all_units = run(["systemctl", "list-unit-files"], capture=True, check=False)
    for s in svcs:
        if s.split(".")[0] in all_units:
            run(["systemctl","disable","--now",s], check=False)
            run(["systemctl","mask",s], check=False)

    # ===== 2.4 — Cron & At (permisos/propiedad + presencia) =====
    run(["dnf","-y","install","cronie","at"], check=False)
    run(["systemctl","enable","--now","crond"], check=False)

    perms = [
        (Path("/etc/crontab"), 0o600, "root:root"),
        (Path("/etc/cron.hourly"), 0o700, "root:root"),
        (Path("/etc/cron.daily"), 0o700, "root:root"),
        (Path("/etc/cron.weekly"), 0o700, "root:root"),
        (Path("/etc/cron.monthly"), 0o700, "root:root"),
        (Path("/etc/cron.d"), 0o700, "root:root"),
    ]
    for p, mode, owner in perms:
        if p.exists():
            backup_file(p)
            run(["chown", owner, str(p)], check=False)
            run(["chmod", oct(mode)[2:], str(p)], check=False)

    for f in [Path("/etc/cron.allow"), Path("/etc/at.allow")]:
        backup_file(f); f.touch(exist_ok=True)
        run(["chown","root:root",str(f)], check=False)
        run(["chmod","0600",str(f)], check=False)
    for f in [Path("/etc/cron.deny"), Path("/etc/at.deny")]:
        if f.exists(): backup_file(f); f.unlink(missing_ok=True)

def ctrl_net_sysctl():
    # 3.3 — Sysctl IPv4/IPv6
    kv = {
        "net.ipv4.ip_forward":"0",
        "net.ipv4.conf.all.send_redirects":"0",
        "net.ipv4.conf.default.send_redirects":"0",
        "net.ipv4.conf.all.accept_source_route":"0",
        "net.ipv4.conf.default.accept_source_route":"0",
        "net.ipv4.conf.all.accept_redirects":"0",
        "net.ipv4.conf.default.accept_redirects":"0",
        "net.ipv4.conf.all.secure_redirects":"0",
        "net.ipv4.conf.default.secure_redirects":"0",
        "net.ipv4.conf.all.log_martians":"1",
        "net.ipv4.conf.default.log_martians":"1",
        "net.ipv4.icmp_echo_ignore_broadcasts":"1",
        "net.ipv4.icmp_ignore_bogus_error_responses":"1",
        "net.ipv4.tcp_syncookies":"1",
        "net.ipv4.conf.all.rp_filter":"1",
        "net.ipv4.conf.default.rp_filter":"1",
        "net.ipv6.conf.all.accept_ra":"0",
        "net.ipv6.conf.default.accept_ra":"0",
        "net.ipv6.conf.all.accept_redirects":"0",
        "net.ipv6.conf.default.accept_redirects":"0",
    }
    for k,v in kv.items():
        sysctl_set(k, v)

def ctrl_firewalld():
    # 4.2 — firewalld
    if not shutil.which("firewall-cmd"):
        log("  [!] firewalld no está instalado"); return
    zone = run(["firewall-cmd", "--get-default-zone"], capture=True, check=False) or "public"
    run(["firewall-cmd", "--permanent", "--zone", zone, "--add-service=ssh"], check=False)
    run(["firewall-cmd", "--permanent", "--zone=trusted", "--add-interface=lo"], check=False)
    run(["firewall-cmd", "--reload"], check=False)
    run(["systemctl", "enable", "--now", "firewalld"], check=False)

def ctrl_access():
    # 5.x — SSH/sudo/su/PAM/políticas/cron/banners + PAM extra + SSHD-T + dconf (1.8)
    # --- SSH permisos y endurecimiento ---
    sshd = Path("/etc/ssh/sshd_config")
    backup_file(sshd)
    run(["chown","root:root",str(sshd)], check=False)
    run(["chmod","0600",str(sshd)], check=False)
    for priv in Path("/etc/ssh").glob("ssh_host_*_key"):
        run(["chown","root:root",str(priv)], check=False); run(["chmod","0600",str(priv)], check=False)
    for pub in Path("/etc/ssh").glob("ssh_host_*_key.pub"):
        run(["chown","root:root",str(pub)], check=False); run(["chmod","0644",str(pub)], check=False)

    # Permisos de /etc/ssh/sshd_config.d/*
    incdir = Path("/etc/ssh/sshd_config.d")
    if incdir.exists():
        for f in incdir.glob("*.conf"):
            backup_file(f)
            run(["chown","root:root",str(f)], check=False)
            run(["chmod","0600",str(f)], check=False)

    # Listas fuertes — pasarán `sshd -T` para ciphers/mac/kex
    strong_ciphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
    strong_macs    = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    strong_kex     = "curve25519-sha256,curve25519-sha256@libssh.org"

    write_or_replace_kv(sshd,"Ciphers",strong_ciphers)
    write_or_replace_kv(sshd,"MACs",strong_macs)
    write_or_replace_kv(sshd,"KexAlgorithms",strong_kex)

    base_ssh = {
        "LogLevel":"INFO","MaxAuthTries":"4","MaxStartups":"10:30:60","MaxSessions":"10",
        "X11Forwarding":"no","GSSAPIAuthentication":"no","HostbasedAuthentication":"no","IgnoreRhosts":"yes",
        "LoginGraceTime":"60","PermitEmptyPasswords":"no","PermitRootLogin":"no","PermitUserEnvironment":"no",
        "ClientAliveInterval":"300","ClientAliveCountMax":"0","UsePAM":"yes","DisableForwarding":"yes",
        "Banner":"/etc/issue.net",
    }
    for k,v in base_ssh.items(): write_or_replace_kv(sshd,k,v)

    # (Opcional) listas de acceso si defines variables de entorno
    env_allow_users  = os.environ.get("SSH_ALLOW_USERS","").strip()
    env_allow_groups = os.environ.get("SSH_ALLOW_GROUPS","").strip()
    if env_allow_users:  write_or_replace_kv(sshd,"AllowUsers",env_allow_users)
    if env_allow_groups: write_or_replace_kv(sshd,"AllowGroups",env_allow_groups)

    Path("/etc/issue.net").write_text("Acceso solo autorizado. Actividad monitorizada.\n", encoding="utf-8")
    run(["systemctl","restart","sshd"], check=False)

    # --- sudo/su ---
    run(["dnf","-y","install","sudo"], check=False)
    sudoers = Path("/etc/sudoers")
    append_once(sudoers,"Defaults use_pty")
    append_once(sudoers,"Defaults logfile=/var/log/sudo.log")
    append_once(sudoers,"Defaults timestamp_timeout=5")
    Path("/var/log/sudo.log").touch(exist_ok=True); run(["chmod","0600","/var/log/sudo.log"], check=False)

    su_pam = Path("/etc/pam.d/su")
    backup_file(su_pam)
    if not file_contains(su_pam, r"^\s*auth\s+required\s+pam_wheel\.so\b"):
        with open(su_pam,"a",encoding="utf-8") as f: f.write("auth required pam_wheel.so use_uid\n")

    # --- 5.3.x — PAM: faillock + pwhistory + nullok off ---
    pam_files = [Path("/etc/pam.d/system-auth"), Path("/etc/pam.d/password-auth")]

    # faillock (preauth y authfail) y even_deny_root
    for pf in pam_files:
        if pf.exists():
            backup_file(pf)
            txt = pf.read_text(encoding="utf-8",errors="ignore")
            if "pam_faillock.so preauth" not in txt:
                txt += "\nauth        required      pam_faillock.so preauth silent\n"
            if "pam_faillock.so authfail" not in txt:
                txt += "auth        required      pam_faillock.so authfail\n"
            pf.write_text(txt, encoding="utf-8")

    faillock = Path("/etc/security/faillock.conf")
    write_or_replace_kv(faillock,"deny","5")
    write_or_replace_kv(faillock,"unlock_time","900")
    if not file_contains(faillock, r"^\s*even_deny_root\b"):
        append_once(faillock,"even_deny_root")

    # pwhistory — archivo dedicado + uso en PAM + use_authtok; eliminar nullok si aparece
    pwh_conf = Path("/etc/security/pwhistory.conf")
    write_or_replace_kv(pwh_conf,"remember","24", sep=" = ")
    write_or_replace_kv(pwh_conf,"enforce_for_root","yes", sep=" = ")
    for pf in pam_files:
        if pf.exists():
            backup_file(pf)
            txt = pf.read_text(encoding="utf-8",errors="ignore")
            if "pam_pwhistory.so" not in txt:
                txt += "\npassword    requisite     pam_pwhistory.so use_authtok\n"
            elif "use_authtok" not in txt:
                txt = re.sub(r"(pam_pwhistory\.so)(.*)", r"\1\2 use_authtok", txt)
            txt = re.sub(r"(pam_unix\.so[^\n]*?)\s+nullok", r"\1", txt)  # quitar nullok
            pf.write_text(txt, encoding="utf-8")

    # pwquality (ya estaba)
    pwdir = Path("/etc/security/pwquality.conf.d")
    pwdir.mkdir(parents=True, exist_ok=True)
    pwfile = pwdir / "50-pwquality.conf"
    backup_file(pwfile)
    pwfile.write_text("minlen = 14\nminclass = 4\nucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\n", encoding="utf-8")

    # login.defs + INACTIVE
    login_defs = Path("/etc/login.defs")
    write_or_replace_kv(login_defs,"PASS_MAX_DAYS","365")
    write_or_replace_kv(login_defs,"PASS_MIN_DAYS","1")
    write_or_replace_kv(login_defs,"PASS_WARN_AGE","7")
    useradd = Path("/etc/default/useradd")
    if file_contains(useradd, r"^INACTIVE="): write_or_replace_kv(useradd,"INACTIVE","30", sep="=")
    else: append_once(useradd,"INACTIVE=30")

    # umask global
    for f in [Path("/etc/profile"), Path("/etc/bashrc"), *Path("/etc/profile.d").glob("*.sh")]:
        if f.exists() and not file_contains(f, r"^\s*umask\s+027\b"):
            append_once(f, "umask 027")

    # cron/at allow-only (refuerzo)
    run(["systemctl","enable","--now","crond"], check=False)
    for p in [Path("/etc/cron.allow"), Path("/etc/at.allow")]:
        backup_file(p); p.touch(exist_ok=True)
        run(["chmod","0600",str(p)], check=False); run(["chown","root:root",str(p)], check=False)
    for p in [Path("/etc/cron.deny"), Path("/etc/at.deny")]:
        if p.exists(): backup_file(p); p.unlink(missing_ok=True)

    # Banners TTY
    for b in [Path("/etc/motd"), Path("/etc/issue"), Path("/etc/issue.net")]: backup_file(b)
    Path("/etc/motd").write_text("Uso exclusivo autorizado. Actividad monitorizada.\n", encoding="utf-8")
    Path("/etc/issue").write_text("Acceso solo autorizado. Actividad monitorizada.\n", encoding="utf-8")
    run(["chmod","0644","/etc/motd","/etc/issue","/etc/issue.net"], check=False)

    # ===== 1.8.x — DCONF / GDM (solo si hay GUI) =====
    if shutil.which("dconf") or Path("/etc/dconf/db/local.d").exists():
        ddir = Path("/etc/dconf/db/local.d"); ldir = Path("/etc/dconf/db/local.d/locks")
        ddir.mkdir(parents=True, exist_ok=True); ldir.mkdir(parents=True, exist_ok=True)

        banner_conf = ddir / "00-banner"
        backup_file(banner_conf)
        banner_conf.write_text(
            "[org/gnome/login-screen]\n"
            "banner-message-enable=true\n"
            "banner-message-text='Acceso solo autorizado. Actividad monitorizada.'\n"
            "disable-user-list=true\n", encoding="utf-8"
        )
        # Idle & lock delay, automount OFF, autorun-never
        session_conf = ddir / "00-session"
        backup_file(session_conf)
        session_conf.write_text(
            "[org/gnome/desktop/session]\n"
            "idle-delay=uint32 900\n"
            "[org/gnome/desktop/screensaver]\n"
            "lock-delay=uint32 5\n"
            "[org/gnome/desktop/media-handling]\n"
            "automount=false\n"
            "automount-open=false\n"
            "autorun-never=true\n", encoding="utf-8"
        )
        # Locks (evitar cambios de usuario)
        lockfile = ldir / "locks"
        append_once(lockfile, "/org/gnome/login-screen/banner-message-enable")
        append_once(lockfile, "/org/gnome/login-screen/banner-message-text")
        append_once(lockfile, "/org/gnome/login-screen/disable-user-list")
        append_once(lockfile, "/org/gnome/desktop/media-handling/automount")
        append_once(lockfile, "/org/gnome/desktop/media-handling/automount-open")
        append_once(lockfile, "/org/gnome/desktop/media-handling/autorun-never")

        run(["dconf","update"], check=False)

def ctrl_logging_audit():
    # 6.x — journald/rsyslog/auditd/AIDE + extras
    # journald persistente y ForwardToSyslog
    jdir = Path("/etc/systemd/journald.conf.d")
    jdir.mkdir(parents=True, exist_ok=True)
    jf = jdir / "60-journald.conf"
    backup_file(jf)
    jf.write_text(
        "[Journal]\n"
        "Storage=persistent\n"
        "SystemMaxUse=1G\n"
        "RuntimeMaxUse=200M\n"
        "ForwardToSyslog=yes\n",  # requerido por varios 6.2.x
        encoding="utf-8"
    )
    run(["systemctl","reload-or-restart","systemd-journald"], check=False)

    # rsyslog
    run(["dnf","-y","install","rsyslog"], check=False)
    run(["systemctl","enable","--now","rsyslog"], check=False)

    # (Opcional) journal-remote/upload si presentes (no forzamos en L1)
    if shutil.which("systemd-journal-remote"):
        run(["systemctl","enable","--now","systemd-journal-remote.socket"], check=False)
    if shutil.which("systemd-journal-upload"):
        run(["systemctl","enable","--now","systemd-journal-upload.service"], check=False)

    # auditd + aide
    run(["dnf","-y","install","audit","audit-libs","aide"], check=False)
    run(["grubby","--update-kernel","ALL","--args","audit=1 audit_backlog_limit=8192"], check=False)
    run(["systemctl","enable","--now","auditd"], check=False)

    # reglas auditd
    rules = Path("/etc/audit/rules.d/60-cis.rules")
    backup_file(rules); rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text("""## CIS L1 core audit rules (aprox)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod,chown,fchmod,fchmodat,fchown,fchownat,lchown -k perm_mod
-a always,exit -F arch=b32 -S chmod,chown,fchmod,fchmodat,fchown,fchownat,lchown -k perm_mod
-a always,exit -F arch=b64 -S mount -k mounts
-a always,exit -F arch=b32 -S mount -k mounts
-w /usr/bin/sudo -p x -k privileged
-w /usr/bin/passwd -p x -k privileged
-w /bin/su -p x -k privileged
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod  -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k auditconfig
-e 2
""", encoding="utf-8")
    if shutil.which("augenrules"): run(["augenrules","--load"], check=False)
    else: run(["service","auditd","restart"], check=False)

    # AIDE init + cron 05:00 (solo si realmente está instalado)
    aide_bin = shutil.which("aide") or "/usr/sbin/aide"
    if Path(aide_bin).exists():
        if not (Path("/var/lib/aide/aide.db.gz").exists() or Path("/var/lib/aide/aide.db").exists()):
            run([str(aide_bin),"--init"], check=False)
            if Path("/var/lib/aide/aide.db.new.gz").exists():
                shutil.move("/var/lib/aide/aide.db.new.gz","/var/lib/aide/aide.db.gz")
        current_cron = run(["crontab","-u","root","-l"], check=False, capture=True) or ""
        line = "0 5 * * * /usr/sbin/aide --check || /usr/sbin/aide --check"
        if line not in current_cron:
            p = subprocess.Popen(["crontab","-u","root","-"], stdin=subprocess.PIPE, text=True)
            p.communicate((current_cron+"\n" if current_cron else "") + line + "\n")
    else:
        log("  [!] AIDE no está disponible tras la instalación; se omite init/cron")

    # ===== 6.2.4.x — Permisos en /var/log, /var/log/sssd, /var/log/gdm =====
    log_dirs = [
        (Path("/var/log"),     0o755, "root:root"),
        (Path("/var/log/sssd"),0o700, "root:root"),
        (Path("/var/log/gdm"), 0o750, "root:root"),
    ]
    for d, mode, owner in log_dirs:
        if d.exists():
            backup_file(d)
            run(["chown", "-R", owner, str(d)], check=False)
            run(["chmod", oct(mode)[2:], str(d)], check=False)

# -------------------- Main --------------------

def pack_backups_tar(ts: str):
    sdir = BACKUP_ROOT / ts
    if not sdir.exists():
        return
    tgz = BACKUP_ROOT / f"{ts}.tar.gz"
    try:
        with tarfile.open(tgz, "w:gz") as tar:
            tar.add(sdir, arcname=ts)
        log(f"[+] Tar de backups creado: {tgz}")
    except Exception as e:
        log(f"[!] No se pudo crear el tar.gz: {e}")

def main():
    parser = argparse.ArgumentParser(description="CIS Rocky Linux 9 L1 (Server) – remediación")
    parser.add_argument("--auto", action="store_true", help="aplica todos los controles sin preguntar")
    parser.add_argument("--crypto-policy", default="DEFAULT", choices=["DEFAULT","FUTURE"], help="política criptográfica")
    parser.add_argument("--rollback", metavar="TIMESTAMP", help="restaura backups de una sesión dada")
    args = parser.parse_args()

    check_root()
    if args.rollback:
        restore_session(args.rollback)

    ensure_dirs()
    log(f"==> CIS Rocky 9 L1 Server — Sesión {SESSION_TS} — Auto:{args.auto} — Crypto:{args.crypto_policy}")

    # Definición de controles para iterar con resumen
    controls = [
        ("1.1.1 — Deshabilitar módulos de kernel no usados", ctrl_fs_modules),
        ("1.1.2 — Montajes nodev/nosuid/noexec", ctrl_mounts),
        ("1.1.3 — Deshabilitar automontaje (autofs)", ctrl_autofs),
        ("1.2 — DNF seguro (gpgcheck=1)", ctrl_dnf),
        ("1.3 — SELinux enforcing + limpieza arranque", ctrl_selinux),
        ("1.4 — Proteger GRUB (permisos + password block)", ctrl_grub),
        ("1.5 — ASLR/ptrace/coredumps off", ctrl_kernel),
        ("1.6 — Crypto policy", lambda: ctrl_crypto(args.crypto_policy)),
        ("2.x — Servicios/paquetes legacy + cron/at", ctrl_services),
        ("3.3 — Sysctl IPv4/IPv6", ctrl_net_sysctl),
        ("4.2 — firewalld mínimo (SSH + lo)", ctrl_firewalld),
        ("5.x — SSH/sudo/su/PAM/políticas/cron/banners (+dconf)", ctrl_access),
        ("6.x — journald/rsyslog/auditd/AIDE (+/var/log perms)", ctrl_logging_audit),
    ]

    applied = 0
    skipped = 0
    failed = []
    for title, fn in controls:
        log(f"=== {title} ===")
        do_it = args.auto or press(title, auto=False)
        if not do_it:
            skipped += 1
            log(f"  [~] Omitido por el usuario")
            continue
        try:
            fn()
            applied += 1
            log(f"  [+] {title} aplicado")
        except Exception as e:
            failed.append((title, str(e)))
            log(f"  [!] Error en '{title}': {e}")

    pack_backups_tar(SESSION_TS)

    # Resumen
    total = len(controls)
    log("=== RESUMEN ===")
    log(f"Aplicados: {applied}/{total}  |  Saltados: {skipped}  |  Fallidos: {len(failed)}")
    if failed:
        for t, err in failed:
            log(f"  - {t}: {err}")

    log(f"==> Finalizado. Log: {LOG_FILE}")
    log(f"    • Backups de esta sesión: {BACKUP_SESSION}")
    log(f"    • Rollback: {sys.argv[0]} --rollback {SESSION_TS}")
    print("\n[!] Recomendado REINICIAR para aplicar completamente GRUB/SELinux/audit.\n")

if __name__ == "__main__":
    main()
