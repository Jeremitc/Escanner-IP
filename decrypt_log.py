from cryptography.fernet import Fernet

# Ruta completa a la clave de encriptación
key_path = r"C:\Users\Usuario\Desktop\Proyectos para mi\Aplicacion escanear red\8.243.126.254\encryption_key.key"

# Ruta completa al archivo de log encriptado
encrypted_log_path = r"C:\Users\Usuario\Desktop\Proyectos para mi\Aplicacion escanear red\8.243.126.254\stealth_scan_96eece7de24c.encrypted.log"

# Leer la clave desde el archivo
with open(key_path, "rb") as key_file:
    key = key_file.read()

# Crear objeto Fernet con la clave
fernet = Fernet(key)

# Leer y desencriptar el archivo de log
with open(encrypted_log_path, "rb") as file:
    encrypted_data = file.read()

# Desencriptar cada línea del log
for line in encrypted_data.splitlines():
    try:
        decrypted_line = fernet.decrypt(line).decode()
        print(decrypted_line)
    except Exception as e:
        print(f"Error al desencriptar: {e}")