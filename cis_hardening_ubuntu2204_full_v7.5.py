#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening_ubuntu2204_full_v7.5.py
Hardening CIS Level 1 para Ubuntu 22.04 (producción, conservador, con backups y rollback robusto).

- NO rompe SSH (no toca AllowUsers/PasswordAuthentication por defecto) ni sudo (valida con visudo).
- Respeta el grupo %sudo, no bloquea "sudo su".
- Backups versionados + rollback robusto (omite archivos de identidad y tipos no regulares).
- --auto para aplicar sin preguntar; sin --auto pregunta control por control.
- Registra todo en /var/log/cis_hardening/cis_hardening_<ts>.log
- Cobertura ampliada (objetivo ~90–95% CIS L1) con salvaguardas.

Uso:
  sudo python3 cis_hardening_ubuntu2204_full_v7.5.py --auto
  sudo python3 cis_hardening_ubuntu2204_full_v7.5.py --auto --firewall-backend ufw
  sudo python3 cis_hardening_ubuntu2204_full_v7.5.py --list-backups
  sudo python3 cis_hardening_ubuntu2204_full_v7.5.py --rollback <timestamp>
"""
import argparse, os, sys, shutil, subprocess, datetime, glob, re, logging, stat
from pathlib import Path

BASE_BACKUP_DIR = "/var/backups/cis_hardening"
LOG_DIR = "/var/log/cis_hardening"
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
LOG_FILE = os.path.join(LOG_DIR, f"cis_hardening_{TIMESTAMP}.log")

# Exclusiones de rollback (archivos de identidad/sensibles)
ROLLBACK_EXCLUDES = {
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    # Puedes añadir más si lo necesitas:
    # "/etc/hostname",
    # "/etc/hosts",
    # "/etc/resolv.conf",
}

def require_root():
    if os.geteuid() != 0:
        print("ERROR: Este script debe ejecutarse como root (sudo).")
        sys.exit(1)

def run(cmd, check=False, capture=False, text=True):
    logging.debug(f"CMD: {cmd}")
    if capture:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text)
        logging.debug(f"stdout: {res.stdout}\nstderr: {res.stderr}")
        if check and res.returncode != 0:
            raise RuntimeError(f"Comando falló: {cmd}\nstdout: {res.stdout}\nstderr: {res.stderr}")
        return res
    else:
        res = subprocess.run(cmd, shell=True)
        if check and res.returncode != 0:
            raise RuntimeError(f"Comando falló: {cmd}")
        return res

def ensure_dirs(backup_path, log_dir):
    os.makedirs(backup_path, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    os.chmod(backup_path, 0o700)
    os.chmod(log_dir, 0o750)

def backup_path_for(dest_path: str, backup_root: str) -> str:
    dest = Path(backup_root) / Path(dest_path).relative_to('/')
    dest.parent.mkdir(parents=True, exist_ok=True)
    return str(dest)

def backup_file(path, backup_root):
    path = Path(path)
    if not path.exists():
        logging.info(f"No existe {path}, nada que respaldar.")
        return None
    dest = backup_path_for(str(path), backup_root)
    if path.is_dir():
        shutil.copytree(path, dest, dirs_exist_ok=True)
    else:
        shutil.copy2(path, dest)
    logging.info(f"Backup: {path} -> {dest}")
    return dest

def list_backups(base_dir=BASE_BACKUP_DIR):
    if not os.path.isdir(base_dir):
        return []
    return sorted(os.listdir(base_dir))

def _safe_copy_for_rollback(src, dst):
    """Copia segura para rollback con exclusiones y tipos de archivo."""
    # Excluir rutas sensibles
    if dst in ROLLBACK_EXCLUDES:
        logging.info(f"Omitido (exclusión rollback): {dst}")
        return
    try:
        st = os.lstat(src)
        mode = st.st_mode
        # Evitar sockets, fifos, dispositivos, puertas
        if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
            logging.info(f"Omitido (tipo no regular): {src}")
            return
        # Enlace simbólico: replicar symlink
        if stat.S_ISLNK(mode):
            try:
                # Eliminar destino existente si es symlink o archivo
                try:
                    os.unlink(dst)
                except FileNotFoundError:
                    pass
                target = os.readlink(src)
                os.symlink(target, dst)
                logging.info(f"Restaurado symlink {src} -> {dst} (->{target})")
                return
            except Exception as e:
                logging.warning(f"No se pudo restaurar symlink {src}: {e}")
                return
        # Directorio: crear y continuar
        if stat.S_ISDIR(mode):
            Path(dst).mkdir(parents=True, exist_ok=True)
            return
        # Archivo regular: copiar metadatos
        Path(os.path.dirname(dst)).mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        logging.info(f"Restaurado {src} -> {dst}")
    except Exception as e:
        logging.error(f"Error restaurando {src} -> {dst}: {e}")

def rollback(backup_timestamp):
    bdir = os.path.join(BASE_BACKUP_DIR, backup_timestamp)
    if not os.path.isdir(bdir):
        raise RuntimeError(f"No existe backup: {bdir}")
    for root, dirs, files in os.walk(bdir):
        # Crear directorios primero
        for d in dirs:
            src_dir = os.path.join(root, d)
            rel = os.path.relpath(src_dir, bdir)
            dst_dir = os.path.join('/', rel)
            _safe_copy_for_rollback(src_dir, dst_dir)
        # Copiar archivos
        for f in files:
            src = os.path.join(root, f)
            rel = os.path.relpath(src, bdir)
            dst = os.path.join('/', rel)
            _safe_copy_for_rollback(src, dst)
    logging.info("Rollback completado. Revisa servicios (sshd, sudoers, auditd, rsyslog).")

def interactive_confirm(prompt):
    while True:
        r = input(f"{prompt} [y/n]: ").strip().lower()
        if r in ('y','yes'): return True
        if r in ('n','no'): return False

def safe_write(path, content, backup_root, validate_cmd=None):
    path = Path(path)
    if path.exists():
        backup_file(str(path), backup_root)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup_file(str(path.parent), backup_root)
    tmp = str(path) + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(content)
    if validate_cmd:
        res = run(validate_cmd.format(file=tmp), capture=True)
        if res.returncode != 0:
            logging.error(f"Validación falló para {path}: {res.stderr}")
            os.remove(tmp); return False
    os.replace(tmp, str(path))
    logging.info(f"Escrito {path}")
    return True

def validate_sshd_config(file):
    return run(f"sshd -t -f {file}", capture=True).returncode == 0

def validate_sudoers(file=None):
    cmd = f"visudo -c -f {file}" if file else "visudo -c"
    r = run(cmd, capture=True)
    ok = r.returncode == 0 or "parsed OK" in (r.stdout + r.stderr) or "Syntax OK" in (r.stdout + r.stderr)
    return ok

def is_ssh_session():
    return bool(os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_CLIENT'))

def ensure_pkg(pkgs: str):
    run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}", check=False)

# -----------------------
# Controles
# -----------------------
def ctl_update_packages(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Aplicar 'apt-get update && apt-get -y upgrade'? "): return
    run("apt-get update", check=True)
    run("DEBIAN_FRONTEND=noninteractive apt-get -y upgrade", check=True)

def ctl_unattended_upgrades(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Habilitar unattended-upgrades? "): return
    conf = "/etc/apt/apt.conf.d/20auto-upgrades"
    content = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
    backup_file(conf, backup_root)
    with open(conf,'w',encoding='utf-8') as f: f.write(content)
    ensure_pkg("unattended-upgrades apt-listchanges")

def ctl_sshd_hardening_safe(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Ajustar sshd_config (conservador, sin bloquear usuarios)? "): return
    conf = "/etc/ssh/sshd_config"
    backup_file(conf, backup_root)
    try:
        with open(conf,'r',encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []
    wanted = {
        'PermitRootLogin': 'no',
        'X11Forwarding': 'no',
        'LogLevel': 'VERBOSE',
        'MaxAuthTries': '4',
        'ClientAliveInterval': '300',
        'ClientAliveCountMax': '0',
        'Protocol': '2',
        'AllowTcpForwarding': 'no',
        'UsePAM': 'yes',
        'PermitEmptyPasswords': 'no',
        'Banner': '/etc/issue.net',
        'IgnoreRhosts': 'yes',
        'HostbasedAuthentication': 'no',
        'PermitUserEnvironment': 'no',
        'LoginGraceTime': '60',
    }
    present = set(); new_lines = []
    for ln in lines:
        m = re.match(r'^\s*([A-Za-z][A-Za-z0-9]+)\s+(.*)$', ln)
        if m and m.group(1) in wanted:
            k = m.group(1); new_lines.append(f"{k} {wanted[k]}\n"); present.add(k)
        else: new_lines.append(ln)
    for k,v in wanted.items():
        if k not in present: new_lines.append(f"\n{k} {v}\n")
    tmp = conf + ".new"
    with open(tmp,'w',encoding='utf-8') as f: f.writelines(new_lines)
    if not validate_sshd_config(tmp):
        logging.error("Validación de sshd_config falló. No se aplican cambios."); os.remove(tmp); return
    shutil.copy2(tmp, conf); os.remove(tmp)
    try:
        import pwd, grp
        os.chown(conf, pwd.getpwnam('root').pw_uid, grp.getgrnam('root').gr_gid)
        os.chmod(conf, 0o600)
    except Exception: pass
    run("systemctl reload sshd", check=False)

def ctl_sudo_secure(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Ajustar sudo (comentar NOPASSWD excepto root/%sudo, +use_pty, +logfile)? "): return
    targets = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
    for t in targets:
        if not os.path.exists(t): continue
        backup_file(t, backup_root)
        with open(t,'r',encoding='utf-8') as f: lines = f.readlines()
        mod = False; out = []
        for ln in lines:
            if ("NOPASSWD" in ln and not ln.lstrip().startswith('#')
                and not re.search(r'^\s*(root|%root|%sudo)\b', ln)):
                out.append("# CIS: NOPASSWD deshabilitado\n# " + ln); mod = True
            else: out.append(ln)
        text = ''.join(out)
        if not re.search(r"(?m)^\s*Defaults\s+use_pty\b", text):
            text += "\nDefaults use_pty\n"; mod = True
        if not re.search(r'(?m)^\s*Defaults\s+logfile\s*=', text):
            text += 'Defaults logfile="/var/log/sudo.log"\n'; mod = True
        if mod:
            tmp = t + ".new"
            with open(tmp,'w',encoding='utf-8') as f: f.write(text)
            if validate_sudoers(tmp): shutil.copy2(tmp, t); logging.info(f"Ajustado {t}")
            else: logging.error(f"Sudoers inválido en {t}, se descartan cambios.")
            os.remove(tmp)

def ctl_uid0_only_root(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Deshabilitar cuentas con UID 0 distintas de root? "): return
    passwd = "/etc/passwd"
    backup_file(passwd, backup_root)
    try:
        with open(passwd,'r',encoding='utf-8') as f: lines = f.readlines()
    except FileNotFoundError: return
    out = []; changed = []
    for ln in lines:
        p = ln.split(':')
        if len(p) > 6:
            try: uid = int(p[2])
            except: uid = None
            if uid == 0 and p[0] != 'root':
                p[6] = '/usr/sbin/nologin\n'; out.append(':'.join(p)); changed.append(p[0])
            else: out.append(ln)
        else: out.append(ln)
    if changed:
        tmp = passwd + ".new"
        with open(tmp,'w',encoding='utf-8') as f: f.writelines(out)
        shutil.copy2(tmp, passwd); os.remove(tmp)
        for u in changed: run(f"passwd -l {u}")
        logging.info(f"Cuentas UID0 ajustadas: {', '.join(changed)}")

def ctl_sensitive_file_perms(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Ajustar permisos/ownership /etc/(passwd,shadow,group,gshadow)? "): return
    files = ["/etc/passwd","/etc/group","/etc/shadow","/etc/gshadow"]
    modes = {"/etc/passwd":0o644,"/etc/group":0o644,"/etc/shadow":0o000,"/etc/gshadow":0o000}
    for p in files:
        if os.path.exists(p):
            backup_file(p, backup_root)
            try:
                import pwd, grp
                os.chown(p, pwd.getpwnam('root').pw_uid, grp.getgrnam('root').gr_gid)
            except Exception: pass
            os.chmod(p, modes[p]); logging.info(f"propietario root:root y chmod {oct(modes[p])} {p}")

def ctl_pam_pwquality(backup_root, auto=False, **kw):
    ensure_pkg("libpam-pwquality")
    conf = "/etc/pam.d/common-password"
    if not os.path.exists(conf): logging.info("No existe common-password, omitiendo."); return
    if not auto and not interactive_confirm("Aplicar política de contraseñas (pam_pwquality minlen=12)? "): return
    backup_file(conf, backup_root)
    with open(conf,'r',encoding='utf-8') as f: lines = f.readlines()
    out, mod = [], False
    for ln in lines:
        if 'pam_pwquality.so' in ln:
            new = re.sub(r'pam_pwquality\.so.*','pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1', ln)
            out.append(new); mod = True
        else: out.append(ln)
    if not mod:
        for i,ln in enumerate(out):
            if ln.strip().startswith('password') and 'pam_unix.so' in ln:
                out.insert(i, 'password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n'); mod = True; break
    # Asegurar sha512 en pam_unix (sin desactivar yescrypt si ya está)
    for i,ln in enumerate(out):
        if 'pam_unix.so' in ln and ln.strip().startswith('password') and 'sha512' not in ln:
            out[i] = ln.rstrip() + ' sha512\n'
    tmp = conf+".new"
    with open(tmp,'w',encoding='utf-8') as f:
        f.writelines(out)
    shutil.copy2(tmp, conf)
    os.remove(tmp)

def ctl_pam_pwhistory(backup_root, auto=False, **kw):
    conf = "/etc/pam.d/common-password"
    if not os.path.exists(conf): return
    if not auto and not interactive_confirm("Habilitar historial de contraseñas (pam_pwhistory remember=5)? "): return
    backup_file(conf, backup_root)
    content = open(conf,'r',encoding='utf-8').read()
    if re.search(r'(?m)^password\s+required\s+pam_pwhistory\.so', content):
        content = re.sub(r'(?m)^password\s+required\s+pam_pwhistory\.so.*$', 'password required pam_pwhistory.so remember=5 use_authtok', content)
    else:
        content = re.sub(r'(?m)^(password\s+.*pam_unix\.so.*)$','password required pam_pwhistory.so remember=5 use_authtok\n\\1', content, count=1)
    tmp = conf+".new"
    with open(tmp,'w',encoding='utf-8') as f:
        f.write(content)
    shutil.copy2(tmp, conf)
    os.remove(tmp)

def ctl_pam_faillock(backup_root, auto=False, **kw):
    # Bloqueo de intentos fallidos (deny=5, unlock=900) de forma segura
    auth = "/etc/pam.d/common-auth"; account="/etc/pam.d/common-account"
    if not (os.path.exists(auth) and os.path.exists(account)): return
    if not auto and not interactive_confirm("Configurar pam_faillock (deny=5 unlock_time=900)? "): return
    backup_file(auth, backup_root); backup_file(account, backup_root)
    a = open(auth,'r',encoding='utf-8').read()
    if "pam_faillock.so preauth" not in a:
        a = a.replace("auth [success=1 default=ignore] pam_unix.so nullok_secure",
                      "auth [success=1 default=ignore] pam_unix.so nullok_secure\nauth required pam_faillock.so preauth silent deny=5 unlock_time=900")
    if "pam_faillock.so authfail" not in a:
        a = a.replace("auth requisite pam_deny.so",
                      "auth required pam_faillock.so authfail deny=5 unlock_time=900\nauth requisite pam_deny.so")
    with open(auth+".new",'w',encoding='utf-8') as f:
        f.write(a)
    shutil.copy2(auth+".new", auth)
    os.remove(auth+".new")
    acc = open(account,'r',encoding='utf-8').read()
    if "account required pam_faillock.so" not in acc:
        acc = "account required pam_faillock.so\n" + acc
    with open(account+".new",'w',encoding='utf-8') as f:
        f.write(acc)
    shutil.copy2(account+".new", account)
    os.remove(account+".new")

def ctl_pam_umask(backup_root, auto=False, **kw):
    conf = "/etc/pam.d/common-session"
    if not os.path.exists(conf): return
    if not auto and not interactive_confirm("Habilitar pam_umask en common-session? "): return
    backup_file(conf, backup_root)
    content = open(conf,'r',encoding='utf-8').read()
    if "pam_umask.so" not in content:
        content += "\nsession optional pam_umask.so\n"
    tmp = conf+".new"
    with open(tmp,'w',encoding='utf-8') as f:
        f.write(content)
    shutil.copy2(tmp, conf)
    os.remove(tmp)

def ctl_login_defs(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Ajustar /etc/login.defs (PASS_MAX_DAYS/MIN_DAYS/WARN_AGE, UMASK)? "): return
    conf = "/etc/login.defs"; backup_file(conf, backup_root)
    content = open(conf,'r',encoding='utf-8').read() if os.path.exists(conf) else ""
    def set_kv(k, v):
        nonlocal content
        if re.search(rf'(?m)^\s*{k}\s+', content): content = re.sub(rf'(?m)^\s*{k}\s+.*$', f"{k} {v}", content)
        else: content += f"\n{k} {v}\n"
    set_kv('PASS_MAX_DAYS','365'); set_kv('PASS_MIN_DAYS','7'); set_kv('PASS_WARN_AGE','7'); set_kv('UMASK','027'); set_kv('ENCRYPT_METHOD','SHA512')
    tmp = conf+".new"
    with open(tmp,'w',encoding='utf-8') as f:
        f.write(content)
    shutil.copy2(tmp, conf)
    os.remove(tmp)

def ctl_issue_banners(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Configurar banners legales (/etc/issue, /etc/issue.net)? "): return
    banner = ("USO AUTORIZADO ÚNICAMENTE. Toda actividad puede ser monitoreada y reportada. "
              "Al continuar, aceptas estas condiciones.\n")
    for p in ("/etc/issue", "/etc/issue.net"):
        safe_write(p, banner, backup_root); os.chmod(p, 0o644)

def ctl_rsyslog_and_logrotate(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Asegurar rsyslog instalado y habilitado? "): return
    ensure_pkg("rsyslog logrotate"); run("systemctl enable --now rsyslog", check=False)
    for f in ["/etc/rsyslog.conf"] + glob.glob("/etc/rsyslog.d/*.conf"):
        if os.path.exists(f): backup_file(f, backup_root); os.chmod(f, 0o640)

def ctl_journald_persistent(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Configurar journald persistente con compresión? "): return
    confd = "/etc/systemd/journald.conf.d"; Path(confd).mkdir(parents=True, exist_ok=True)
    conf = f"{confd}/99-cis.conf"; content = "[Journal]\nStorage=persistent\nCompress=yes\n"
    safe_write(conf, content, backup_root); run("systemctl restart systemd-journald", check=False)

def _get_ssh_port():
    port = 22
    try:
        with open("/etc/ssh/sshd_config",'r',encoding='utf-8') as f:
            for ln in f:
                m = re.match(r'^\s*Port\s+(\d+)', ln)
                if m: port = int(m.group(1)); break
    except Exception: pass
    return port

def ctl_firewall(backup_root, auto=False, firewall_backend="ufw", **kw):
    if firewall_backend == "none":
        logging.info("Firewall: sin cambios (backend=none)"); return
    if firewall_backend == "ufw":
        if not auto and not interactive_confirm("Configurar UFW (deny incoming, allow SSH, enable)? "): return
        ensure_pkg("ufw")
        run("ufw default deny incoming", check=False)
        run("ufw default allow outgoing", check=False)
        run(f"ufw allow {_get_ssh_port()}/tcp", check=False)
        status = run("ufw status", capture=True)
        if 'inactive' in (status.stdout+status.stderr):
            run("yes | ufw enable", check=False); logging.info("UFW habilitado con regla de SSH")
    elif firewall_backend == "nftables":
        if not auto and not interactive_confirm("Configurar nftables (permitir SSH y políticas básicas)? "): return
        ensure_pkg("nftables")
        rules = f"""table inet filter {{
  chain input {{
    type filter hook input priority 0;
    ct state established,related accept
    iif lo accept
    tcp dport {_get_ssh_port()} accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    drop
  }}
  chain forward {{ type filter hook forward priority 0; drop }}
  chain output {{ type filter hook output priority 0; accept }}
}}
"""
        safe_write("/etc/nftables.conf", rules, backup_root); run("systemctl enable --now nftables", check=False)
    else:
        logging.warning(f"Backend firewall desconocido: {firewall_backend}")

def ctl_blacklist_fs_modules(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Blacklistear módulos de FS poco comunes? "): return
    conf = "/etc/modprobe.d/cis_fs.conf"
    content = ("install cramfs /bin/true\ninstall freevxfs /bin/true\ninstall jffs2 /bin/true\n"
               "install hfs /bin/true\ninstall hfsplus /bin/true\ninstall udf /bin/true\n")
    safe_write(conf, content, backup_root)

def ctl_blacklist_protocols(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Blacklistear protocolos de red (dccp, sctp, rds, tipc) y usb-storage? "): return
    conf = "/etc/modprobe.d/blacklist-protocols.conf"
    content = ("install dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true\ninstall tipc /bin/true\n"
               "install usb-storage /bin/true\n")
    safe_write(conf, content, backup_root)

def ctl_sysctl_network_hardening(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Aplicar sysctl de red y kernel (conservador)? "): return
    conf = "/etc/sysctl.d/60-cis.conf"
    content = """
# IPv4
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# IPv6
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Kernel misc
kernel.kptr_restrict=1
kernel.randomize_va_space=2
fs.suid_dumpable=0
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1
"""
    if safe_write(conf, content, backup_root): run("sysctl --system", check=False)

def ctl_core_dumps_off(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Desactivar core dumps (limits.d)? "): return
    conf = "/etc/security/limits.d/99-coredump.conf"
    content = "* hard core 0\n* soft core 0\n"
    safe_write(conf, content, backup_root)
    logging.info("Core dumps deshabilitados (límites y sysctl)")

def ctl_sticky_world_writable_dirs(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Aplicar sticky bit en directorios world-writable? "): return
    r = run("df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null", capture=True)
    dirs = [d for d in r.stdout.splitlines() if d.strip()]
    for d in dirs:
        try: os.chmod(d, os.stat(d).st_mode | 0o1000); logging.info(f"Sticky bit aplicado: {d}")
        except Exception as e: logging.warning(f"No se pudo aplicar sticky en {d}: {e}")

def ctl_auditd_basic(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Instalar y habilitar auditd con reglas ampliadas? "): return
    ensure_pkg("auditd audispd-plugins"); run("systemctl enable --now auditd", check=False)
    rules = "/etc/audit/rules.d/cis-basic.rules"
    content = """
## Reglas CIS L1 ampliadas (conservadoras)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,stime,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /etc/issue -p wa -k banners
-w /etc/issue.net -p wa -k banners
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_chng
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate,rename,renameat,unlink,unlinkat -F auid>=1000 -F auid!=-1 -k file_mods
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-e 2
"""
    safe_write(rules, content, backup_root)
    run("chown root:root /etc/audit/rules.d/*.rules 2>/dev/null || true", check=False)
    run("chmod 640 /etc/audit/rules.d/*.rules 2>/dev/null || true", check=False)
    run("augenrules --load", check=False)

def ctl_find_legacy_entries(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Comentar entradas heredadas (+) en passwd/group/shadow? "): return
    for f in ("/etc/passwd","/etc/group","/etc/shadow"):
        if not os.path.exists(f): continue
        backup_file(f, backup_root)
        with open(f,'r',encoding='utf-8') as fh: lines = fh.readlines()
        out, mod = [], False
        for ln in lines:
            if ln.startswith('+'): out.append('# ' + ln); mod = True; logging.info(f"Entrada heredada (+) comentada en {f}: {ln.strip()}")
            else: out.append(ln)
        if mod:
            tmp = f+".new"
            with open(tmp,'w',encoding='utf-8') as fh:
                fh.writelines(out)
            shutil.copy2(tmp,f)
            os.remove(tmp)

def ctl_home_dirs_ownership_perms(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Corregir permisos de $HOME (propietario correcto y <= 750)? "): return
    r = run("awk -F: '($3>=1000)&&($1!=\"nobody\") {print $1\" \" $6}' /etc/passwd", capture=True)
    for line in r.stdout.splitlines():
        try: user, home = line.split()
        except ValueError: continue
        if os.path.isdir(home):
            st = os.stat(home)
            import pwd
            try: pw = pwd.getpwnam(user); uid, gid = pw.pw_uid, pw.pw_gid
            except KeyError: continue
            if st.st_uid != uid or st.st_gid != gid:
                backup_file(home, backup_root)
                try: os.chown(home, uid, gid); logging.info(f"chown {user}:{gid} {home}")
                except Exception as e: logging.warning(f"No se pudo chown {home}: {e}")
            mode = st.st_mode & 0o777
            if mode & 0o027:
                try: os.chmod(home, 0o750); logging.info(f"chmod 750 {home}")
                except Exception as e: logging.warning(f"No se pudo chmod {home}: {e}")

def ctl_tmout(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Configurar TMOUT=900 en /etc/profile.d? "): return
    conf = "/etc/profile.d/99-tmout.sh"; content = "TMOUT=900\nreadonly TMOUT\nexport TMOUT\n"
    safe_write(conf, content, backup_root)

def ctl_services_desktop_disable_if_inactive(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Deshabilitar servicios desktop si no se usan (apport, cups, avahi)? "): return
    for svc in ("apport","cups","avahi-daemon"):
        is_active = run(f"systemctl is-active {svc}.service", capture=True)
        if "active" in (is_active.stdout+is_active.stderr):
            logging.info(f"{svc} activo, no se toca"); continue
        run(f"systemctl stop {svc}.service", check=False)
        run(f"systemctl disable {svc}.service", check=False)
        run(f"systemctl mask {svc}.service", check=False)
        logging.info(f"{svc} deshabilitado/mask (si estaba instalado)")

def ctl_cron_at_defaults(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Asegurar cron/at (allow/deny y permisos)? "): return
    files = {
        "/etc/crontab": 0o600,
        "/etc/cron.hourly": 0o700,
        "/etc/cron.daily": 0o700,
        "/etc/cron.weekly": 0o700,
        "/etc/cron.monthly": 0o700,
        "/etc/cron.d": 0o700,
    }
    for p,m in files.items():
        if os.path.exists(p):
            backup_file(p, backup_root)
            os.chmod(p, m if os.path.isfile(p) else m)
            logging.info(f"Permisos {oct(m)} {p}")
    for p in ("/etc/cron.allow","/etc/at.allow"):
        if not os.path.exists(p): safe_write(p, "root\n", backup_root)
        os.chmod(p, 0o600)
    for p in ("/etc/cron.deny","/etc/at.deny"):
        if os.path.exists(p): backup_file(p, backup_root); os.remove(p); logging.info(f"Eliminado {p}")

def ctl_aide_install_init(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Instalar e inicializar AIDE? "): return
    ensure_pkg("aide")
    if not os.path.exists("/var/lib/aide/aide.db.gz"):
        run("aideinit || true", check=False)
        if os.path.exists("/var/lib/aide/aide.db.new.gz"):
            backup_file("/var/lib/aide/aide.db.gz", backup_root)
            shutil.copy2("/var/lib/aide/aide.db.new.gz", "/var/lib/aide/aide.db.gz")
            logging.info("AIDE DB inicializada")

def ctl_aide_cron_daily(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Configurar tarea diaria de AIDE? "): return
    path = "/etc/cron.daily/aide-check"
    content = "#!/bin/sh\n/usr/bin/aide --check > /var/log/aide-check.log 2>&1 || true\n"
    safe_write(path, content, backup_root); os.chmod(path, 0o700)

def ctl_legacy_net_pkgs(backup_root, auto=False, **kw):
    pkgs = ["telnet","rsh-client","talk","tftp","xinetd","nis"]
    found = []
    for p in pkgs:
        r = run(f"dpkg -s {p}", capture=True)
        if r.returncode == 0: found.append(p)
    if found:
        logging.info(f"Paquetes legacy presentes: {', '.join(found)}")
        if auto: run(f"apt-get -y purge {' '.join(found)}", check=False)

def ctl_duplicate_ids_report(backup_root, auto=False, **kw):
    r = run("awk -F: '{print $3}' /etc/passwd | sort | uniq -d", capture=True)
    logging.info("UIDs duplicados: " + (r.stdout.strip() or "ninguno"))
    r = run("awk -F: '{print $3}' /etc/group | sort | uniq -d", capture=True)
    logging.info("GIDs duplicados: " + (r.stdout.strip() or "ninguno"))

def ctl_grub_cfg_perms(backup_root, auto=False, **kw):
    path = "/boot/grub/grub.cfg"
    if not os.path.exists(path): return
    if not auto and not interactive_confirm("Asegurar permisos 600 en /boot/grub/grub.cfg? "): return
    backup_file(path, backup_root)
    try:
        import pwd, grp
        os.chown(path, pwd.getpwnam('root').pw_uid, grp.getgrnam('root').gr_gid)
    except Exception: pass
    os.chmod(path, 0o600)
    logging.info("Permisos de grub.cfg asegurados (600, root:root)")

def ctl_useradd_inactive(backup_root, auto=False, **kw):
    conf = "/etc/default/useradd"
    if not os.path.exists(conf): return
    if not auto and not interactive_confirm("Establecer INACTIVE=30 en /etc/default/useradd? "): return
    backup_file(conf, backup_root)
    content = open(conf,'r',encoding='utf-8').read()
    if re.search(r'(?m)^\s*INACTIVE\s*=', content):
        content = re.sub(r'(?m)^\s*INACTIVE\s*=.*$', "INACTIVE=30", content)
    else:
        content += "\nINACTIVE=30\n"
    tmp = conf+".new"
    with open(tmp,'w',encoding='utf-8') as f:
        f.write(content)
    shutil.copy2(tmp, conf)
    os.remove(tmp)

def ctl_wireless_disable_if_unused(backup_root, auto=False, **kw):
    if not auto and not interactive_confirm("Deshabilitar wpa_supplicant si no hay Wi‑Fi? "): return
    r = run("iw dev 2>/dev/null | awk '/Interface/ {print $2}'", capture=True)
    if r.stdout.strip():
        logging.info("Interfaces Wi‑Fi detectadas, no se toca wpa_supplicant.")
        return
    run("systemctl stop wpa_supplicant 2>/dev/null || true", check=False)
    run("systemctl disable wpa_supplicant 2>/dev/null || true", check=False)
    run("systemctl mask wpa_supplicant 2>/dev/null || true", check=False)
    logging.info("wpa_supplicant deshabilitado/mask (no hay hardware Wi‑Fi).")

# Registro de controles
CONTROLS = [
    ("update_packages", "Actualizar paquetes", ctl_update_packages),
    ("unattended_upgrades", "Habilitar actualizaciones automáticas", ctl_unattended_upgrades),
    ("sshd_hardening", "Endurecer sshd (conservador)", ctl_sshd_hardening_safe),
    ("sudo_secure", "Ajustes de sudo (sin bloquear privilegios legítimos)", ctl_sudo_secure),
    ("uid0_only_root", "Sólo root con UID 0", ctl_uid0_only_root),
    ("sensitive_file_perms", "Permisos/ownership archivos sensibles", ctl_sensitive_file_perms),
    ("pam_pwquality", "Política de contraseñas (libpam-pwquality)", ctl_pam_pwquality),
    ("pam_pwhistory", "Historial de contraseñas (remember=5)", ctl_pam_pwhistory),
    ("pam_umask", "Habilitar pam_umask (UMASK 027)", ctl_pam_umask),
    ("login_defs", "Políticas /etc/login.defs (UMASK y caducidad)", ctl_login_defs),
    ("banners", "Banners legales /etc/issue (+permisos 644)", ctl_issue_banners),
    ("rsyslog", "Asegurar rsyslog + permisos conf", ctl_rsyslog_and_logrotate),
    ("journald_persistent", "journald persistente + compresión", ctl_journald_persistent),
    ("firewall", "Firewall (ufw|nftables|none)", ctl_firewall),
    ("blacklist_fs", "Blacklist FS poco comunes en modprobe", ctl_blacklist_fs_modules),
    ("blacklist_protocols", "Blacklist dccp/sctp/rds/tipc + usb-storage", ctl_blacklist_protocols),
    ("sysctl_net", "Sysctl de red y kernel conservador", ctl_sysctl_network_hardening),
    ("core_dumps_off", "Desactivar core dumps", ctl_core_dumps_off),
    ("sticky_dirs", "Sticky bit en directorios world-writable", ctl_sticky_world_writable_dirs),
    ("auditd_basic", "auditd con reglas ampliadas", ctl_auditd_basic),
    ("no_legacy_plus", "Eliminar entradas heredadas (+) en cuentas", ctl_find_legacy_entries),
    ("home_perms", "Permisos y ownership en /home de usuarios", ctl_home_dirs_ownership_perms),
    ("tmout", "Timeout de sesión (TMOUT=900)", ctl_tmout),
    ("services_desktop", "Deshabilitar servicios desktop si inactivos", ctl_services_desktop_disable_if_inactive),
    ("cron_at", "Cron/At allow/deny + permisos", ctl_cron_at_defaults),
    ("aide_install", "Instalar e inicializar AIDE", ctl_aide_install_init),
    ("aide_cron", "Tarea diaria de AIDE", ctl_aide_cron_daily),
    ("legacy_net_pkgs", "Auditar/purgar paquetes legacy inseguros", ctl_legacy_net_pkgs),
    ("dup_ids", "Informe de UIDs/GIDs duplicados", ctl_duplicate_ids_report),
    ("grub_cfg_perms", "Permisos de /boot/grub/grub.cfg", ctl_grub_cfg_perms),
    ("useradd_inactive", "INACTIVE=30 en useradd", ctl_useradd_inactive),
    ("wireless_disable", "Deshabilitar wpa_supplicant si no hay Wi‑Fi", ctl_wireless_disable_if_unused),
]

def parse_args():
    p = argparse.ArgumentParser(description="Hardening CIS L1 conservador para Ubuntu 22.04 - con backups y rollback")
    p.add_argument("--auto", action="store_true", help="Aplicar todos los controles sin preguntar")
    p.add_argument("--backup-dir", default=BASE_BACKUP_DIR, help="Directorio base para backups")
    p.add_argument("--log-dir", default=LOG_DIR, help="Directorio para logs")
    p.add_argument("--rollback", help="Rollback a backup (timestamp de carpeta)")
    p.add_argument("--list-backups", action="store_true", help="Listar backups disponibles")
    p.add_argument("--controls", nargs='*', help="Subconjunto de controles por nombre corto")
    p.add_argument("--firewall-backend", choices=["ufw","nftables","none"], default="ufw", help="Backend de firewall")
    return p.parse_args()

def setup_logging(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler(); console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger('').addHandler(console)
    logging.info(f"Log: {log_file}")

def main():
    require_root()
    args = parse_args()
    backup_root = os.path.join(args.backup_dir, TIMESTAMP)
    ensure_dirs(backup_root, args.log_dir)
    global LOG_FILE; LOG_FILE = os.path.join(args.log_dir, f"cis_hardening_{TIMESTAMP}.log")
    setup_logging(LOG_FILE)

    if args.list_backups:
        items = list_backups(args.backup_dir)
        print("Backups disponibles:" if items else "No hay backups.")
        for x in items: print(" -", x)
        return

    if args.rollback:
        logging.info(f"Iniciando rollback desde {args.rollback}")
        try:
            rollback(args.rollback)
            logging.info("Rollback finalizado")
        except Exception as e:
            logging.exception(f"Error en rollback: {e}")
        return

    if is_ssh_session():
        logging.warning("Sesión SSH detectada. Se intentará no interrumpir tu sesión.")

    if shutil.which("visudo") is None:
        logging.error("visudo no disponible; no se puede validar sudoers. Abortando.")
        print("ERROR: visudo no está disponible."); return

    selected = CONTROLS
    if args.controls:
        idx = {k:(k, d, f) for k,d,f in CONTROLS}
        selected = [idx[c] for c in args.controls if c in idx]
        unknown = [c for c in args.controls if c not in idx]
        for u in unknown: logging.warning(f"Control desconocido: {u}")

    logging.info(f"Inicio hardening (auto={args.auto}) - timestamp={TIMESTAMP}")
    for name, desc, fn in selected:
        logging.info(f"==> {name}: {desc}")
        try:
            if name == "firewall":
                fn(backup_root, auto=args.auto, firewall_backend=args.firewall_backend)
            else:
                fn(backup_root, auto=args.auto)
        except Exception as e:
            logging.exception(f"Error en control {name}: {e}")

    # Verificación final mínima
    if not validate_sudoers(): logging.error("El archivo sudoers tiene errores de sintaxis.")
    else: logging.info("sudoers válido (visudo OK).")
    if not validate_sshd_config("/etc/ssh/sshd_config"): logging.error("sshd_config inválido.")
    else: logging.info("sshd_config válido.")

    logging.info(f"Hardening finalizado. Backups en {backup_root}")
    print(f"Terminado. Backups en: {backup_root}\nLog: {LOG_FILE}")

if __name__ == "__main__":
    main()
