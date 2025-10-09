#!/usr/bin/env python3
import os
import tarfile
import datetime

# ===========================
#  ADVENS CIBERSECURITY
# ===========================
# Herramienta de copia de seguridad para el Hardening CIS L1 de Rocky Linux 9.x
# ===========================

BACKUP_DIR = "/root/pre-bastionado"
DATE_FORMAT = datetime.datetime.now().strftime("%Y-%m-%d")
BACKUP_FILE = os.path.join(BACKUP_DIR, f"pre-bastionado-{DATE_FORMAT}.tar.gz")
DIRS_TO_BACKUP = ["/etc", "/boot", "/var/log"]

def banner():
    print("=" * 70)
    print(" ADVENS CIBERSECURITY")
    print("=" * 70)
    print()
    print(" Herramienta de copia de seguridad para el Hardening CIS L1 de Rocky Linux 9.x")
    print("=" * 70)

def backup_local():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    print("-> Iniciando copia de seguridad local...")

    try:
        with tarfile.open(BACKUP_FILE, "w:gz") as tar:
            for d in DIRS_TO_BACKUP:
                if os.path.exists(d):
                    tar.add(d, recursive=True)
        print(f"OK: Copia creada en {BACKUP_FILE}")
    except Exception as e:
        print(f"ERROR: {e}")

def send_scp():
    if not os.path.exists(BACKUP_FILE):
        print("No se encontró el archivo local. Ejecute la opción 1 primero.")
        return

    remote_user = input("Usuario remoto: ").strip()
    remote_host = input("Host remoto: ").strip()
    remote_path = input("Ruta remota (ej. /home/usuario/backups): ").strip()

    cmd = f"scp -p {BACKUP_FILE} {remote_user}@{remote_host}:{remote_path}"
    print(f"-> Ejecutando: {cmd}")
    res = os.system(cmd)
    if res == 0:
        print("OK: Copia enviada correctamente.")
    else:
        print("ERROR: Fallo en el envío por SCP.")

def restore_backup():
    if not os.path.exists(BACKUP_DIR):
        print("No hay backups en", BACKUP_DIR)
        return

    backups = os.listdir(BACKUP_DIR)
    if not backups:
        print("No se encontraron archivos de backup.")
        return

    print("-> Archivos de copia disponibles:")
    for b in backups:
        print("  ", b)

    restore_file = input("Ingrese el nombre del archivo a restaurar: ").strip()
    full_path = os.path.join(BACKUP_DIR, restore_file)

    if os.path.exists(full_path):
        confirm = input("Esto sobrescribirá configuraciones actuales. ¿Está seguro? (s/n): ").lower()
        if confirm == "s":
            try:
                with tarfile.open(full_path, "r:gz") as tar:
                    tar.extractall("/")
                print("OK: Restauración completada. Se recomienda reiniciar.")
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print("Restauración cancelada.")
    else:
        print("ERROR: Archivo no encontrado.")

def main():
    banner()
    while True:
        print("\n==================== Menú de Opciones ====================")
        print("1. Crear copia de seguridad local")
        print("2. Enviar copia de seguridad por SCP")
        print("3. Restaurar copia de seguridad")
        print("4. Salir")
        print("==========================================================")
        option = input("Seleccione una opción: ").strip()

        if option == "1":
            backup_local()
        elif option == "2":
            send_scp()
        elif option == "3":
            restore_backup()
        elif option == "4":
            print("Saliendo.")
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Debe ejecutarse como root (use sudo).")
    else:
        main()
