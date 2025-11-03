"""
Módulo escáner de seguridad para GraphSec-IaC

Este módulo proporciona funcionalidad para ejecutar análisis de seguridad
usando múltiples escáneres (Checkov y Trivy) y generar reportes en formato SARIF.
"""

import subprocess
import json
import logging
import os
import sys
import asyncio
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Scanner(ABC):
    """Clase base abstracta para todos los escáneres de seguridad."""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    async def scan(self, directory_path: str, output_file: str) -> bool:
        """
        Ejecuta el escaneo de seguridad sobre un directorio.
        
        Args:
            directory_path (str): Ruta al directorio del proyecto Terraform.
            output_file (str): Ruta donde se guardará el archivo de resultados.
            
        Returns:
            bool: True si el escaneo es exitoso, False en caso contrario.
        """
        pass
    
    @abstractmethod
    def get_results_summary(self, results_file: str) -> dict:
        """
        Obtiene un resumen de los resultados del escaneo.
        
        Args:
            results_file (str): Ruta al archivo de resultados.
            
        Returns:
            dict: Diccionario con el resumen de los resultados.
        """
        pass


class CheckovScanner(Scanner):
    """Escáner de seguridad usando Checkov."""
    
    def __init__(self):
        super().__init__("Checkov")
        self.timeout = 300  # Timeout de 5 minutos
    
    def _find_python_executable(self) -> str:
        """
        Encuentra el intérprete de Python correcto.
        Prioriza el venv del proyecto, luego el intérprete actual.
        Compatible con Windows y Linux.
        """
        # Paso 1: Si ya estamos en un venv, usar el intérprete actual
        current_exec = os.path.abspath(sys.executable)
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.prefix != sys.base_prefix):
            # Estamos en un venv
            logger.info(f"Python ejecutándose en venv: {current_exec}")
            return current_exec
        
        # Paso 2: Buscar el venv del proyecto (compatible con Windows y Linux)
        module_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(module_dir)  # Subir un nivel desde modules/
        
        # Intentar Windows primero (venv/Scripts/python.exe)
        venv_python_windows = os.path.join(project_root, 'venv', 'Scripts', 'python.exe')
        if os.path.exists(venv_python_windows):
            logger.info(f"Usando Python del venv del proyecto (Windows): {venv_python_windows}")
            return os.path.abspath(venv_python_windows)
        
        # Intentar Linux/Mac (venv/bin/python)
        venv_python_unix = os.path.join(project_root, 'venv', 'bin', 'python')
        if os.path.exists(venv_python_unix):
            logger.info(f"Usando Python del venv del proyecto (Linux/Mac): {venv_python_unix}")
            return os.path.abspath(venv_python_unix)
        
        # Paso 3: Fallback: usar el intérprete actual (pero avisar)
        logger.warning(f"Venv del proyecto no encontrado, usando Python actual: {sys.executable}")
        return os.path.abspath(sys.executable)
    
    async def scan(self, directory_path: str, output_file: str) -> bool:
        """
        Ejecuta Checkov usando 'python -m checkov', que es agnóstico al SO.
        """
        # Obtener el ejecutable de Python correcto (el del venv o el global)
        python_exec = self._find_python_executable()
        
        # Verificar intérprete activo
        if not os.path.exists(python_exec):
            logger.error(f"Intérprete de Python no encontrado: {python_exec}")
            return False
        
        # Convertir a ruta absoluta
        directory_path = os.path.abspath(directory_path)
        
        # Verificar que el directorio existe
        if not os.path.exists(directory_path):
            logger.error(f"El directorio {directory_path} no existe")
            return False
        
        # Verificar que el directorio contiene archivos .tf
        tf_files = [f for f in os.listdir(directory_path) if f.endswith('.tf')]
        if not tf_files:
            logger.error(f"No se encontraron archivos .tf en {directory_path}")
            return False
        
        # Definir el directorio de salida (Checkov crea un subdirectorio)
        output_dir = os.path.abspath(output_file)
        # El archivo SARIF real estará dentro de este directorio
        actual_sarif_file = os.path.join(output_dir, "results_sarif.sarif")
        
        # Limpiar el directorio de salida si ya existe
        if os.path.exists(output_dir):
            import shutil
            shutil.rmtree(output_dir)
        
        # --- INICIO DEL NUEVO BLOQUE CMD ---
        # Esta lógica es agnóstica al SO.
        # 1. Intenta encontrar el 'python.exe'/'python' del venv
        venv_bin_dir = os.path.dirname(python_exec)
        
        # 2. El binario 'checkov' (sin extensión) o 'checkov.exe' (Windows)
        # debería estar en la misma carpeta que el python del venv.
        checkov_bin = os.path.join(venv_bin_dir, "checkov")
        if os.name == 'nt' and not os.path.exists(checkov_bin):
            checkov_bin = os.path.join(venv_bin_dir, "checkov.exe")
        
        cmd = []
        if os.path.exists(checkov_bin):
            # Modo VENV (Local/Windows): Llama al binario específico
            cmd = [checkov_bin]
        else:
            # Modo CI (Linux/PATH): Asume que 'checkov' está en el PATH
            # (instalado por el workflow)
            cmd = ["checkov"]
        
        cmd.extend([
            "--directory", directory_path,
            "--output", "sarif",
            "--output-file-path", actual_sarif_file
        ])
        # --- FIN DEL NUEVO BLOQUE CMD ---
        
        # Forzar UTF-8 para que Checkov lea ficheros correctamente
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        
        import time as time_module
        scan_start = time_module.time()
        logger.info(f"[{time_module.strftime('%H:%M:%S')}] Ejecutando escaneo de seguridad con {self.name}: {' '.join(cmd[:5])} ...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
            
            stdout_decoded = stdout.decode('utf-8', errors='ignore')
            stderr_decoded = stderr.decode('utf-8', errors='ignore')
            
            if process.returncode != 0 and process.returncode != 1:
                # Checkov devuelve código 1 cuando encuentra vulnerabilidades (normal)
                logger.error(f"Error al ejecutar {self.name}. Código de retorno: {process.returncode}")
                logger.error(f"Salida de Checkov: {stdout_decoded[-500:]}")
                logger.error(f"Error de Checkov: {stderr_decoded[-500:]}")
                return False
            
            # Verificar que el archivo SARIF se creó
            if not os.path.exists(actual_sarif_file):
                logger.error(f"Checkov se ejecutó pero el archivo SARIF no se encontró en: {actual_sarif_file}")
                logger.error(f"Logs de Checkov: {stdout_decoded[-500:]}")
                logger.error(f"Errores de Checkov: {stderr_decoded[-500:]}")
                return False
            
            # Verificar que el archivo no está vacío
            if os.path.getsize(actual_sarif_file) == 0:
                logger.error(f"El archivo SARIF {actual_sarif_file} está vacío")
                return False
            
            scan_elapsed = time_module.time() - scan_start
            logger.info(f"[{time_module.strftime('%H:%M:%S')}] ¡Éxito! Escaneo con {self.name} completado en {scan_elapsed:.2f}s. Informe guardado en {actual_sarif_file}")
            return True
            
        except asyncio.TimeoutError:
            logger.error(f"Timeout de {self.name} después de 300 segundos.")
            return False
        except Exception as e:
            logger.error(f"Error inesperado con {self.name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def get_results_summary(self, results_file: str) -> dict:
        """
        Obtiene un resumen del archivo SARIF generado por Checkov.
        
        Args:
            results_file (str): Ruta al archivo SARIF
            
        Returns:
            dict: Resumen con estadísticas del archivo SARIF
        """
        
        try:
            # Buscar el archivo SARIF en la ubicación correcta
            actual_sarif_file = results_file
            if not os.path.exists(results_file) or os.path.isdir(results_file):
                # Buscar en el subdirectorio
                potential_file = os.path.join(results_file, 'results_sarif.sarif')
                if os.path.exists(potential_file):
                    actual_sarif_file = potential_file
                else:
                    return {"error": "El archivo SARIF no existe"}
            
            with open(actual_sarif_file, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            # Extraer información del SARIF
            runs = sarif_data.get("runs", [])
            if not runs:
                return {"error": "No se encontraron runs en el archivo SARIF"}
            
            run = runs[0]
            results = run.get("results", [])
            tool = run.get("tool", {}).get("driver", {})
            
            summary = {
                "tool_name": tool.get("name", "unknown"),
                "tool_version": tool.get("version", "unknown"),
                "total_results": len(results),
                "rules_count": len(run.get("tool", {}).get("driver", {}).get("rules", [])),
                "files_analyzed": len(run.get("artifacts", [])),
                "scan_timestamp": run.get("invocations", [{}])[0].get("startTimeUtc", "unknown")
            }
            
            # Contar resultados por nivel de severidad
            severity_counts = {}
            for result in results:
                level = result.get("level", "unknown")
                severity_counts[level] = severity_counts.get(level, 0) + 1
            
            summary["severity_breakdown"] = severity_counts
            
            return summary
            
        except Exception as e:
            return {"error": f"Error al procesar archivo SARIF de {self.name}: {e}"}


class TrivyScanner(Scanner):
    """Escáner de seguridad usando Trivy."""
    
    def __init__(self):
        super().__init__("Trivy")
        self._find_trivy_executable()
    
    def _find_trivy_executable(self):
        """Encuentra el ejecutable de Trivy."""
        # Priorizar PATH del sistema para portabilidad
        possible_paths = [
            "trivy",  # Trivy está en el PATH del sistema (preferido para portabilidad)
            os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'trivy.cmd'),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\WinGet\\Packages\\AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe\\trivy.exe")
        ]
        
        for path in possible_paths:
            if path == "trivy":
                # Verificar que trivy está disponible en PATH
                try:
                    import subprocess
                    result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.trivy_cmd = path
                        logger.info(f"Trivy encontrado en PATH: {path}")
                        return
                except:
                    continue
            elif os.path.exists(path):
                self.trivy_cmd = path
                logger.info(f"Trivy encontrado en: {path}")
                return
        
        self.trivy_cmd = None
        logger.error("Trivy no encontrado. Asegúrate de que esté instalado y en el PATH del sistema.")
    
    async def scan(self, directory_path: str, output_file: str) -> bool:
        """
        Ejecuta un escaneo de seguridad usando Trivy sobre un directorio de Terraform
        y guarda los resultados en formato SARIF (asíncrono).
        
        Args:
            directory_path (str): Ruta al directorio que contiene los archivos de Terraform
            output_file (str): Ruta del archivo donde guardar el reporte SARIF
            
        Returns:
            bool: True si el escaneo es exitoso, False si falla
        """
        
        if not self.trivy_cmd:
            logger.error("Trivy no está disponible")
            return False
        
        # Convertir a ruta absoluta
        directory_path = os.path.abspath(directory_path)
        output_file = os.path.abspath(output_file)
        
        # Verificar que el directorio existe
        if not os.path.exists(directory_path):
            logger.error(f"El directorio {directory_path} no existe")
            return False
        
        # Verificar que el directorio contiene archivos .tf
        tf_files = [f for f in os.listdir(directory_path) if f.endswith('.tf')]
        if not tf_files:
            logger.error(f"No se encontraron archivos .tf en {directory_path}")
            return False
        
        # Construir el comando Trivy
        cmd = [
            self.trivy_cmd,
            "config",
            "--format", "sarif",
            "--output", output_file,
            directory_path
        ]
        
        logger.info(f"Comando Trivy construido: {' '.join(cmd)}")
        
        try:
            import time as time_module
            scan_start = time_module.time()
            logger.info(f"[{time_module.strftime('%H:%M:%S')}] Ejecutando escaneo de seguridad con {self.name}: {' '.join(cmd)}")
            
            # Ejecutar el comando de forma asíncrona usando asyncio.create_subprocess_exec
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(__file__)
            )
            
            # Esperar a que termine y capturar salida (con timeout)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # Timeout de 5 minutos
                )
            except asyncio.TimeoutError:
                logger.error(f"{self.name} excedió el timeout de 5 minutos")
                process.kill()
                await process.wait()
                return False
            
            # Decodificar salida
            stdout_text = stdout.decode('utf-8', errors='ignore')
            stderr_text = stderr.decode('utf-8', errors='ignore')
            
            # Crear un objeto similar a subprocess.run para compatibilidad
            class ProcessResult:
                def __init__(self, returncode, stdout, stderr):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr
            
            result = ProcessResult(process.returncode, stdout_text, stderr_text)
            
            # Trivy devuelve código de salida 1 cuando encuentra vulnerabilidades
            # Esto es normal, no es un error
            if result.returncode not in [0, 1]:
                logger.error(f"{self.name} falló con código de salida {result.returncode}")
                logger.error(f"Error: {result.stderr}")
                return False
            
            # Verificar que el archivo se creó
            if not os.path.exists(output_file):
                logger.error(f"El archivo de salida {output_file} no se creó")
                logger.error(f"Salida de {self.name}: {result.stdout}")
                logger.error(f"Error de {self.name}: {result.stderr}")
                return False
            
            # Verificar que el archivo no está vacío
            if os.path.getsize(output_file) == 0:
                logger.error(f"El archivo de salida {output_file} está vacío")
                return False
            
            scan_elapsed = time_module.time() - scan_start
            logger.info(f"[{time_module.strftime('%H:%M:%S')}] ¡Éxito! Escaneo de seguridad con {self.name} completado en {scan_elapsed:.2f}s. El informe se ha guardado en {output_file}")
            return True
            
        except FileNotFoundError:
            logger.error(f"{self.name} no está instalado o no se encuentra en el PATH")
            return False
            
        except subprocess.TimeoutExpired:
            logger.error(f"El comando {self.name} excedió el tiempo límite de 2 minutos")
            return False
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error al ejecutar {self.name}: {e}")
            logger.error(f"Salida: {e.stdout}")
            logger.error(f"Error: {e.stderr}")
            return False
            
        except Exception as e:
            logger.error(f"Error inesperado con {self.name}: {e}")
            return False
    
    def get_results_summary(self, results_file: str) -> dict:
        """
        Obtiene un resumen del archivo SARIF generado por Trivy.
        
        Args:
            results_file (str): Ruta al archivo SARIF
            
        Returns:
            dict: Resumen con estadísticas del archivo SARIF
        """
        
        try:
            with open(results_file, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            # Extraer información del SARIF
            runs = sarif_data.get("runs", [])
            if not runs:
                return {"error": "No se encontraron runs en el archivo SARIF"}
            
            run = runs[0]
            results = run.get("results", [])
            tool = run.get("tool", {}).get("driver", {})
            
            summary = {
                "tool_name": tool.get("name", "unknown"),
                "tool_version": tool.get("version", "unknown"),
                "total_results": len(results),
                "rules_count": len(run.get("tool", {}).get("driver", {}).get("rules", [])),
                "files_analyzed": len(run.get("artifacts", [])),
                "scan_timestamp": run.get("invocations", [{}])[0].get("startTimeUtc", "unknown")
            }
            
            # Contar resultados por nivel de severidad
            severity_counts = {}
            for result in results:
                level = result.get("level", "unknown")
                severity_counts[level] = severity_counts.get(level, 0) + 1
            
            summary["severity_breakdown"] = severity_counts
            
            return summary
            
        except Exception as e:
            return {"error": f"Error al procesar archivo SARIF de {self.name}: {e}"}


# Funciones de compatibilidad para mantener la API existente
def scan_for_issues(directory_path: str, output_file: str) -> bool:
    """
    Función de compatibilidad que usa CheckovScanner.
    Mantiene la API existente para no romper el código actual.
    """
    scanner = CheckovScanner()
    return scanner.scan(directory_path, output_file)


def get_sarif_summary(sarif_file: str) -> dict:
    """
    Función de compatibilidad que usa CheckovScanner.
    Mantiene la API existente para no romper el código actual.
    """
    scanner = CheckovScanner()
    return scanner.get_results_summary(sarif_file)