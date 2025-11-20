"""
Módulo para ejecutar análisis de seguridad con Checkov y Trivy.
"""

import subprocess
import json
import logging
import os
import sys
import asyncio
import shutil
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Scanner(ABC):
    """Clase base para escáneres de seguridad."""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    async def scan(self, directory_path: str, output_file: str) -> bool:
        """Ejecuta el escaneo de seguridad."""
        pass
    
    @abstractmethod
    def get_results_summary(self, results_file: str) -> dict:
        """Obtiene resumen de resultados."""
        pass


class CheckovScanner(Scanner):
    """Escáner de seguridad usando Checkov."""
    
    def __init__(self, timeout=300):
        super().__init__("Checkov")
        # Detectar y usar el intérprete correcto (priorizar venv del proyecto)
        self.python_exec = self._find_python_executable()
        self.timeout = timeout
    
    def _find_python_executable(self) -> str:
        """
        Encuentra el intérprete de Python correcto.
        Prioriza el venv del proyecto, luego el intérprete actual.
        Usa rutas absolutas para garantizar portabilidad después de reiniciar.
        """
        # Paso 1: Si ya estamos en un venv, verificar que sea el del proyecto
        current_exec = os.path.abspath(sys.executable)
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.prefix != sys.base_prefix):
            # Estamos en un venv, verificar si es el del proyecto
            module_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(module_dir)
            venv_scripts = os.path.join(project_root, 'venv', 'Scripts')
            venv_python = os.path.join(venv_scripts, 'python.exe')
            
            # Normalizar rutas para comparación
            if os.path.normpath(os.path.dirname(current_exec)) == os.path.normpath(venv_scripts):
                logger.info(f"Python ejecutándose en venv del proyecto: {current_exec}")
                return current_exec
        
        # Paso 2: Buscar el venv del proyecto usando rutas absolutas
        module_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(module_dir)  # Subir un nivel desde modules/
        venv_python = os.path.abspath(os.path.join(project_root, 'venv', 'Scripts', 'python.exe'))
        
        if os.path.exists(venv_python):
            logger.info(f"Usando Python del venv del proyecto: {venv_python}")
            return venv_python
        
        # Paso 3: Fallback: usar el intérprete actual (pero avisar)
        logger.warning(f"Venv del proyecto no encontrado en {venv_python}, usando Python actual: {sys.executable}")
        return os.path.abspath(sys.executable)
    
    async def scan(self, directory_path: str, output_file: str) -> bool:
        """
        Ejecuta Checkov usando el ejecutable 'checkov' directamente.
        Esto es universal para Windows (venv) y Linux (CI).
        Versión V16: Usar ejecutable checkov directamente.
        """
        # Intentar encontrar el ejecutable de checkov
        # Primero intentar 'checkov' directamente (instalado en PATH)
        checkov_cmd = "checkov"
        
        # Si estamos en Windows, intentar encontrar el ejecutable en Scripts
        if os.name == 'nt':
            python_exec = self._find_python_executable()
            venv_scripts = os.path.dirname(python_exec)
            checkov_exe = os.path.join(venv_scripts, "checkov.exe")
            checkov_bat = os.path.join(venv_scripts, "checkov.bat")
            if os.path.exists(checkov_exe):
                checkov_cmd = checkov_exe
            elif os.path.exists(checkov_bat):
                checkov_cmd = checkov_bat
        
        # 'output_file' ES el path COMPLETO del archivo SARIF final.
        actual_sarif_file = os.path.abspath(output_file)
        
        # El directorio donde se guardará el archivo
        output_dir = os.path.dirname(actual_sarif_file)
        # Asegurarse de que el directorio de salida exista
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Directorio de salida SARIF: {output_dir}")
        logger.info(f"Archivo SARIF esperado: {actual_sarif_file}")
        
        # Limpiar el *archivo* antiguo si existe, no el directorio
        if os.path.exists(actual_sarif_file):
            os.remove(actual_sarif_file)
        
        # Limpiar el directorio antiguo si existe (lógica antigua)
        old_dir_style = os.path.abspath(output_file)
        if os.path.isdir(old_dir_style):
            shutil.rmtree(old_dir_style)
        
        # CRÍTICO: Usar la ruta absoluta del directorio explícitamente
        # Esto asegura que Checkov genere rutas SARIF relativas desde el project_root correcto
        directory_path_abs = os.path.abspath(directory_path)
        
        # Usar ruta absoluta para el output-file-path
        cmd = [
            checkov_cmd,
            "--directory", directory_path_abs,  # <- Usar ruta absoluta explícita
            "--output", "sarif",
            "--output-file-path", actual_sarif_file,
            "--skip-path", ".git"
        ]
        logger.info(f"Comando Checkov completo: {' '.join(cmd)}")
        
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        
        import time as time_module
        scan_start = time_module.time()
        logger.info(f"[{time_module.strftime('%H:%M:%S')}] Ejecutando Checkov: {checkov_cmd} ...")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=directory_path_abs  # <-- Ejecutar desde el project_root (usar versión absoluta)
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
            
            stdout_decoded = stdout.decode('utf-8', errors='ignore')
            stderr_decoded = stderr.decode('utf-8', errors='ignore')
            
            # Checkov devuelve código 1 cuando encuentra vulnerabilidades (éxito)
            # Solo considerar error si el código es diferente de 0 y 1
            if process.returncode != 0 and process.returncode != 1:
                logger.error(f"Error al ejecutar Checkov. Código: {process.returncode}")
                logger.error(f"Error de Checkov (stderr): {stderr_decoded}")
                logger.error(f"Salida de Checkov (stdout): {stdout_decoded}")
                return False
            
            # Verificar si el archivo SARIF se creó (incluso si el código fue 1)
            if not os.path.exists(actual_sarif_file):
                logger.error(f"Checkov se ejecutó (código {process.returncode}) pero el SARIF no se encontró en: {actual_sarif_file}")
                logger.error(f"Logs de Checkov (stdout): {stdout_decoded}")
                logger.error(f"Logs de Checkov (stderr): {stderr_decoded}")
                # Debug: listar archivos en el directorio de salida
                if os.path.exists(output_dir):
                    logger.error(f"Archivos en directorio de salida: {os.listdir(output_dir)}")
                return False
            
            # Si llegamos aquí, Checkov tuvo éxito (código 0 o 1) y el archivo existe
            if process.returncode == 1:
                logger.info(f"Checkov encontró vulnerabilidades (código 1), pero el SARIF se generó correctamente")
            scan_elapsed = time_module.time() - scan_start
            logger.info(f"[{time_module.strftime('%H:%M:%S')}] ¡Éxito! Checkov completado en {scan_elapsed:.2f}s.")
            return True
        except Exception as e:
            logger.error(f"Error inesperado con Checkov: {e}")
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
            # CRÍTICO: Ejecutar desde directory_path para que las rutas en SARIF sean consistentes
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=directory_path  # <-- Ejecutar desde el project_root para rutas consistentes
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