"""
Módulo escáner de seguridad para GraphSec-IaC

Este módulo proporciona funcionalidad para ejecutar análisis de seguridad
usando múltiples escáneres (Checkov y Trivy) y generar reportes en formato SARIF.
"""

import subprocess
import json
import logging
import os
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
        self._find_checkov_executable()
    
    def _find_checkov_executable(self):
        """Encuentra el ejecutable de Checkov."""
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'checkov.cmd'),
            os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'checkov.exe'),
            os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'checkov'),
            "checkov"
        ]
        
        for path in possible_paths:
            if os.path.exists(path) or path == "checkov":
                self.checkov_cmd = path
                return
        
        self.checkov_cmd = None
        logger.error("Checkov no encontrado en ninguna ubicación esperada")
    
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
        
        if not self.checkov_cmd:
            logger.error("Checkov no está disponible")
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
        cmd = [
            self.checkov_cmd,
            "--directory", directory_path,
            "--output", "sarif",
            "--output-file-path", output_file
        ]
        
        try:
            logger.info(f"Ejecutando escaneo de seguridad con {self.name}: {' '.join(cmd)}")
            
            # Ejecutar el comando y capturar la salida
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(__file__),  # Ejecutar desde la raíz del proyecto
                timeout=120  # Timeout de 2 minutos
            )
            
            # Checkov devuelve código de salida 1 cuando encuentra vulnerabilidades
            # Esto es normal, no es un error
            if result.returncode not in [0, 1]:
                logger.error(f"{self.name} falló con código de salida {result.returncode}")
                logger.error(f"Error: {result.stderr}")
                return False
            
            # Checkov crea un directorio con el nombre del archivo
            # y dentro pone results_sarif.sarif
            actual_output_file = None
            
            # Buscar el archivo en el directorio creado por Checkov
            potential_file = os.path.join(output_file, 'results_sarif.sarif')
            if os.path.exists(potential_file):
                actual_output_file = potential_file
            else:
                logger.error(f"El archivo de salida {output_file} no se creó")
                logger.error(f"Salida de {self.name}: {result.stdout}")
                logger.error(f"Error de {self.name}: {result.stderr}")
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
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'trivy.cmd'),
            "trivy"  # Trivy está en el PATH del sistema
        ]
        
        for path in possible_paths:
            if os.path.exists(path) or path == "trivy":
                self.trivy_cmd = path
                logger.info(f"Trivy encontrado en: {path}")
                return
        
        self.trivy_cmd = None
        logger.error("Trivy no encontrado en ninguna ubicación esperada")
    
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
                cwd=os.path.dirname(__file__),  # Ejecutar desde la raíz del proyecto
                timeout=120  # Timeout de 2 minutos
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