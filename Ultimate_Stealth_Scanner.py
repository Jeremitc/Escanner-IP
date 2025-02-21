import os
import sys
import codecs
sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, 'strict')
sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, 'strict')
import ctypes
import time
import random
import socket
import logging
import warnings
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from cryptography.fernet import Fernet
import json

class EnhancedStealthScanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.session_id = self._generate_session_id()
        self.discovered_hosts = []
        self.TIMEOUT = 5.0
        
        # Inicializar todo antes de empezar
        print(f"\nInicializando scanner para {target_ip}...")
        self._initialize_directories()
        self._setup_encryption()
        self._setup_logging()
        self.ttl_signatures = self._load_ttl_signatures()
        self._configure_scapy()
        print("Inicialización completada.\n")
    
    def _generate_session_id(self) -> str:
        """Genera un ID de sesión aleatorio basado en la fecha y un hash."""
        random_hash = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        return f"scan_{random_hash}"
    
    def _setup_encryption(self):
        """Configura la clave de cifrado y el cifrador Fernet."""
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        print("🔐 Cifrado inicializado correctamente.")
    
    def _configure_scapy(self):
        """Configura Scapy para mejorar el rendimiento y evitar advertencias innecesarias."""
        warnings.simplefilter("ignore", category=UserWarning)  # Ignorar advertencias de Scapy
        scapy.conf.verb = 0  # Desactiva la verbosidad para evitar spam en la consola

    def _initialize_directories(self):
        """Inicializar estructura de directorios"""
        try:
            self.base_dir = os.path.join(os.getcwd(), "scanner_results")
            self.scan_directory = os.path.join(self.base_dir, self.target_ip.replace('.', '_'))
            self.log_directory = os.path.join(self.scan_directory, "logs")
            
            for directory in [self.base_dir, self.scan_directory, self.log_directory]:
                os.makedirs(directory, exist_ok=True)
                print(f"Directorio creado/verificado: {directory}")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_file = os.path.join(self.log_directory, f'scan_{timestamp}.log')
            self.results_file = os.path.join(self.scan_directory, f'results_{timestamp}.json')
            
        except Exception as e:
            print(f"Error creando directorios: {e}")
            raise

    def _setup_logging(self):
        """Configurar logging mejorado"""
        try:
            # Configurar el logger principal
            self.logger = logging.getLogger(f'scanner_{self.session_id}')
            self.logger.setLevel(logging.DEBUG)
            
            # Asegurarse de que no haya handlers duplicados
            self.logger.handlers = []
            
            # Handler para archivo
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            
            # Handler para consola
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter('%(message)s')
            console_handler.setFormatter(console_formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
            
            self.logger.info("Sistema de logging iniciado correctamente")
            
        except Exception as e:
            print(f"Error configurando logging: {e}")
            raise
        
    def _load_ttl_signatures(self) -> Dict[int, str]:
        """Carga firmas de TTL para identificar sistemas operativos basados en valores TTL."""
        return {
            64: "Linux/Unix",
            128: "Windows",
            255: "Cisco/Router"
        }

    def _check_host_alive(self) -> bool:
        """Envía un paquete ICMP (ping) para verificar si el host está activo."""
        self.logger.info("Verificando si el host está activo...")
        try:
            pkt = IP(dst=self.target_ip) / ICMP()
            resp = scapy.sr1(pkt, timeout=self.TIMEOUT, verbose=False)
            if resp is None:
                self.logger.warning(f"🔴 {self.target_ip} no responde al ping.")
                return False
            else:
                self.logger.info(f"🟢 {self.target_ip} está activo.")
                return True
        except Exception as e:
            self.logger.error(f"Error al verificar el host: {e}")
            return False
        
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Escanea un puerto enviando un paquete SYN y analizando la respuesta."""
        try:
            src_port = random.randint(1024, 65535)  # Puerto de origen aleatorio
            pkt = IP(dst=self.target_ip) / TCP(sport=src_port, dport=port, flags="S")  # Paquete SYN
            response = scapy.sr1(pkt, timeout=1, verbose=False)

            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                scapy.send(IP(dst=self.target_ip) / TCP(sport=src_port, dport=port, flags="R"), verbose=False)  # Enviar RST
                return {"puerto": port, "state": "abierto", "servicio": self._get_service_name(port)}
            else:
                return {"puerto": port, "state": "cerrado"}
        except Exception as e:
            self.logger.error(f"Error escaneando puerto {port}: {e}")
            return None
    
    def scan_network(self):
        """Ejecuta el escaneo de puertos después de verificar la disponibilidad del host."""
        try:
            self.logger.info(f"\nIniciando escaneo de {self.target_ip}")
            self.logger.info("=" * 50)

        # Verificar si el host está activo
            self.logger.info("\nVerificando si el host está activo...")
            if not self._check_host_alive():
                self.logger.warning(f"El host {self.target_ip} parece estar inactivo o bloqueando las peticiones")
                input("\nPresione Enter para salir...")
                return

            self.logger.info("Host activo detectado. Iniciando escaneo de puertos...\n")

        # Escanear puertos comunes de manera concurrente
            common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
            results = []

            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {executor.submit(self.scan_port, port): port for port in common_ports}
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            if result['state'] == 'abierto':
                                self.logger.info(f"  ► Puerto {port} ({result['servicio']}): ABIERTO")
                            elif result['state'] == 'cerrado':
                                self.logger.info(f"  • Puerto {port}: cerrado")
                    except Exception as e:
                        self.logger.error(f"Error escaneando puerto {port}: {e}")

        # Guardar y mostrar resultados
            self._save_results(results)
            self._display_summary(results)

            self.logger.info("\nEscaneo completado. Presione Enter para salir...")
            input()

        except KeyboardInterrupt:
            self.logger.info("\n\nEscaneo interrumpido por el usuario.")
            input("\nPresione Enter para salir...")
        except Exception as e:
            self.logger.error(f"\nError durante el escaneo: {e}")
            input("\nPresione Enter para salir...")

    def _display_summary(self, results: List[Dict]):
        """Mostrar resumen de resultados"""
        self.logger.info("\n" + "=" * 50)
        self.logger.info("RESUMEN DEL ESCANEO")
        self.logger.info("=" * 50)
        
        puertos_abiertos = [r for r in results if r['state'] == 'abierto']
        puertos_cerrados = [r for r in results if r['state'] == 'cerrado']
        puertos_filtrados = [r for r in results if r['state'] == 'filtrado']
        
        self.logger.info(f"\nPuertos abiertos encontrados: {len(puertos_abiertos)}")
        for puerto in puertos_abiertos:
            self.logger.info(f"  • Puerto {puerto['port']} ({puerto['servicio']})")
        
        self.logger.info(f"\nPuertos cerrados: {len(puertos_cerrados)}")
        self.logger.info(f"Puertos filtrados: {len(puertos_filtrados)}")
        self.logger.info(f"\nResultados guardados en: {self.results_file}")

    def _save_results(self, results: dict):
        """Guarda los resultados en un archivo JSON dentro del directorio de logs."""
        try:
            results_path = os.path.join(self.scan_directory, "scan_results.json")
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4)
            self.logger.info(f"📁 Resultados guardados en {results_path}")
        except Exception as e:
            self.logger.error(f"Error guardando resultados: {e}")

def is_admin():
    """Verificar privilegios de administrador de manera segura"""
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/MacOS
            return os.getuid() == 0  # 0 es el ID de root
    except Exception as e:
        print(f"Error verificando privilegios de administrador: {e}")
        return False

def elevate_privileges():
    """Intentar elevar privilegios en Windows"""
    if os.name == 'nt':  # Solo para Windows
        try:
            if not is_admin():
                # Obtener el path del ejecutable de Python
                python_exe = sys.executable
                # Obtener el path del script actual
                script = os.path.abspath(sys.argv[0])
                # Elevar privilegios
                ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas", 
                    python_exe, 
                    f'"{script}"', 
                    None, 
                    1
                )
                return True
        except Exception as e:
            print(f"Error al elevar privilegios: {e}")
    return False

def main():
    """Función principal con mejor manejo de privilegios"""
    try:
        print("\n=== Scanner de Red Mejorado ===")
        
        # Verificar privilegios de administrador
        if not is_admin():
            print("\nSe requieren privilegios de administrador para ejecutar este programa.")
            print("Intentando elevar privilegios...")
            
            if elevate_privileges():
                sys.exit(0)  # Salir del proceso actual, el nuevo proceso elevado continuará
            else:
                print("\nNo se pudieron obtener privilegios de administrador.")
                print("Por favor, ejecute el script como administrador.")
                input("\nPresione Enter para salir...")
                sys.exit(1)
        
        # Si llegamos aquí, tenemos privilegios de administrador
        target_ip = input("\nIngrese la IP objetivo: ")
        scanner = EnhancedStealthScanner(target_ip)
        scanner.scan_network()
        
    except Exception as e:
        print(f"\nError crítico: {e}")
        input("\nPresione Enter para salir...")

if __name__ == "__main__":
    main()