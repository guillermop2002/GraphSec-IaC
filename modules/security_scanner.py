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
    def scan(self, directory_path: str, output_file: str) -> bool:
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
        # Detectar y usar el intérprete correcto (priorizar venv del proyecto)
        self.python_exec = self._find_python_executable()
    
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
    
    def scan(self, directory_path: str, output_file: str) -> bool:
        """
        Ejecuta un escaneo de seguridad usando Checkov sobre un directorio de Terraform
        y guarda los resultados en formato SARIF.
        
        Args:
            directory_path (str): Ruta al directorio que contiene los archivos de Terraform
            output_file (str): Ruta del archivo donde guardar el reporte SARIF
            
        Returns:
            bool: True si el escaneo es exitoso, False si falla
        """
        
        # Verificar intérprete activo
        if not os.path.exists(self.python_exec):
            logger.error("Intérprete de Python no encontrado.")
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
        
        # Construir el comando Checkov
        # Método más robusto: usar 'python -m checkov' que garantiza usar el módulo del venv correcto
        # Esto funciona incluso después de reiniciar porque usa rutas absolutas
        
        # Verificar primero si checkov está disponible como módulo
        venv_scripts_dir = os.path.dirname(self.python_exec)
        checkov_cmd_path = os.path.join(venv_scripts_dir, "checkov.exe")
        checkov_cmd_alt = os.path.join(venv_scripts_dir, "checkov.cmd")
        
        if os.path.exists(checkov_cmd_path):
            # Usar el ejecutable .exe directamente (más portable)
            cmd = [
                checkov_cmd_path,
                "--directory", directory_path,
                "--output", "sarif",
                "--output-file-path", output_file
            ]
            env = os.environ.copy()
            # Forzar UTF-8 en Python para que Checkov lea archivos correctamente
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
        elif os.path.exists(checkov_cmd_alt):
            # Usar el wrapper .cmd pero modificar PATH para que use nuestro Python
            cmd = [
                checkov_cmd_alt,
                "--directory", directory_path,
                "--output", "sarif",
                "--output-file-path", output_file
            ]
            # Modificar PATH para que checkov.cmd encuentre nuestro Python del venv primero
            env = os.environ.copy()
            env['PATH'] = venv_scripts_dir + os.pathsep + env.get('PATH', '')
            # Forzar UTF-8 en Python para que Checkov lea archivos correctamente
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
        else:
            # Fallback más robusto: usar 'python -m checkov' (recomendado)
            # Esto garantiza que use el módulo checkov del venv correcto
            cmd = [
                self.python_exec,
                "-m", "checkov",
                "--directory", directory_path,
                "--output", "sarif",
                "--output-file-path", output_file
            ]
            env = os.environ.copy()
            # Forzar UTF-8 en Python para que Checkov lea archivos correctamente
            env['PYTHONIOENCODING'] = 'utf-8'
            env['PYTHONUTF8'] = '1'
        
        try:
            logger.info(f"Ejecutando escaneo de seguridad con {self.name}: {' '.join(cmd[:3])} ...")
            
            # Ejecutar el comando y capturar la salida
            # Usar encoding='utf-8' y errors='ignore' para ser robusto ante caracteres especiales
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',  # Forzar UTF-8 para evitar problemas de encoding
                errors='ignore',   # Ignorar caracteres no decodificables (evita UnicodeDecodeError)
                cwd=os.path.dirname(__file__),  # Ejecutar desde la raíz del proyecto
                timeout=300,  # Timeout de 5 minutos para proyectos complejos (antes 180s)
                env=env
            )
            
            # Checkov devuelve código de salida 1 cuando encuentra vulnerabilidades
            # Esto es normal, no es un error
            if result.returncode not in [0, 1]:
                logger.error(f"{self.name} falló con código de salida {result.returncode}")
                logger.error(f"Error: {result.stderr}")
                return False
            
            # Checkov puede crear el archivo directamente o en un subdirectorio
            # Intentar varias ubicaciones posibles
            actual_output_file = None
            
            # 1. Buscar en el subdirectorio (comportamiento antiguo de Checkov)
            potential_dir_file = os.path.join(output_file, 'results_sarif.sarif')
            if os.path.exists(potential_dir_file):
                actual_output_file = potential_dir_file
            # 2. Buscar el archivo directamente (comportamiento nuevo de Checkov)
            elif os.path.exists(output_file):
                actual_output_file = output_file
            else:
                logger.error(f"El archivo de salida {output_file} no se creó")
                logger.error(f"Salida de {self.name}: {result.stdout[-500:] if result.stdout else '(sin salida)'}")
                logger.error(f"Error de {self.name}: {result.stderr[-500:] if result.stderr else '(sin errores)'}")
                return False
            
            # Verificar que el archivo no está vacío
            if os.path.getsize(actual_output_file) == 0:
                logger.error(f"El archivo de salida {actual_output_file} está vacío")
                return False
            
            # El archivo está en actual_output_file, que es la ubicación real donde Checkov lo guardó
            logger.info(f"¡Éxito! Escaneo de seguridad con {self.name} completado. El informe se ha guardado en {actual_output_file}")
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
    
    def scan(self, directory_path: str, output_file: str) -> bool:
        """
        Ejecuta un escaneo de seguridad usando Trivy sobre un directorio de Terraform
        y guarda los resultados en formato SARIF.
        
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
            logger.info(f"Ejecutando escaneo de seguridad con {self.name}: {' '.join(cmd)}")
            
            # Ejecutar el comando y capturar la salida
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',  # Forzar UTF-8 para evitar problemas de encoding
                errors='ignore',   # Ignorar caracteres no decodificables (evita UnicodeDecodeError)
                cwd=os.path.dirname(__file__),  # Ejecutar desde la raíz del proyecto
                timeout=300  # Timeout de 5 minutos para proyectos complejos (antes 120s)
            )
            
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
            
            logger.info(f"¡Éxito! Escaneo de seguridad con {self.name} completado. El informe se ha guardado en {output_file}")
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