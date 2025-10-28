"""
Módulo de análisis de seguridad para GraphSec-IaC

Este módulo proporciona funcionalidad para ejecutar análisis de seguridad
usando herramientas como Checkov sobre proyectos de Terraform.
"""

import subprocess
import json
import logging
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """Representa un hallazgo de seguridad individual."""
    check_id: str
    check_name: str
    severity: str
    resource: str
    file_path: str
    file_line_range: List[int]
    description: str
    guideline: str
    status: str  # "PASSED", "FAILED", "SKIPPED"


@dataclass
class SecurityReport:
    """Representa un reporte completo de análisis de seguridad."""
    total_checks: int
    passed_checks: int
    failed_checks: int
    skipped_checks: int
    findings: List[SecurityFinding]
    checkov_version: str
    scan_timestamp: str


def run_checkov_analysis(directory_path: str, output_format: str = "json") -> Optional[Dict]:
    """
    Ejecuta análisis de seguridad usando Checkov sobre un directorio de Terraform.
    
    Args:
        directory_path (str): Ruta al directorio que contiene los archivos de Terraform
        output_format (str): Formato de salida ('json', 'sarif', 'junit')
        
    Returns:
        Optional[Dict]: Diccionario con los resultados del análisis en formato JSON,
                       o None si ocurre algún error
    """
    
    # Convertir a ruta absoluta
    directory_path = os.path.abspath(directory_path)
    
    # Verificar que el directorio existe
    if not os.path.exists(directory_path):
        logger.error(f"El directorio {directory_path} no existe")
        return None
    
    # Verificar que el directorio contiene archivos .tf
    tf_files = [f for f in os.listdir(directory_path) if f.endswith('.tf')]
    if not tf_files:
        logger.error(f"No se encontraron archivos .tf en {directory_path}")
        return None
    
    # Construir el comando Checkov
    # Buscar checkov en el entorno virtual
    checkov_cmd = None
    possible_paths = [
        os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'checkov.cmd'),
        os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'checkov.exe'),
        os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'checkov'),
        "checkov"  # Intentar con PATH del sistema
    ]
    
    for path in possible_paths:
        if os.path.exists(path) or path == "checkov":
            checkov_cmd = path
            break
    
    if not checkov_cmd:
        logger.error("Checkov no encontrado en ninguna ubicación esperada")
        return None
    
    cmd = [
        checkov_cmd,
        "-d", directory_path,
        "--output", output_format,
        "--quiet"  # Reducir salida verbosa
    ]
    
    try:
        logger.info(f"Ejecutando análisis de seguridad: {' '.join(cmd)}")
        
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
            logger.error(f"Checkov falló con código de salida {result.returncode}")
            logger.error(f"Error: {result.stderr}")
            return None
        
        # Verificar que hay salida (puede estar en stdout o stderr)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            logger.error("Checkov no produjo ninguna salida")
            return None
        
        # Parsear la salida JSON
        try:
            analysis_data = json.loads(output)
            logger.info("Análisis de seguridad completado exitosamente")
            return analysis_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Error al parsear JSON de Checkov: {e}")
            logger.error(f"Salida recibida: {output[:200]}...")
            return None
            
    except FileNotFoundError:
        logger.error("Checkov no está instalado o no se encuentra en el PATH")
        return None
        
    except subprocess.TimeoutExpired:
        logger.error("El comando Checkov excedió el tiempo límite de 2 minutos")
        return None
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al ejecutar Checkov: {e}")
        return None
        
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        return None


def parse_checkov_results(checkov_data: Dict) -> SecurityReport:
    """
    Parsea los resultados de Checkov y los convierte en un SecurityReport estructurado.
    
    Args:
        checkov_data (Dict): Datos JSON de salida de Checkov
        
    Returns:
        SecurityReport: Reporte estructurado de análisis de seguridad
    """
    
    if not checkov_data or "results" not in checkov_data:
        logger.error("Datos de Checkov inválidos o vacíos")
        return SecurityReport(0, 0, 0, 0, [], "", "")
    
    results = checkov_data["results"]
    summary = checkov_data.get("summary", {})
    
    # Extraer estadísticas del resumen
    total_checks = summary.get("passed", 0) + summary.get("failed", 0) + summary.get("skipped", 0)
    passed_checks = summary.get("passed", 0)
    failed_checks = summary.get("failed", 0)
    skipped_checks = summary.get("skipped", 0)
    checkov_version = checkov_data.get("check_type", "unknown")
    
    # Procesar hallazgos de seguridad
    findings = []
    
    # Procesar checks fallidos (vulnerabilidades)
    for failed_check in results.get("failed_checks", []):
        finding = SecurityFinding(
            check_id=failed_check.get("check_id", "unknown"),
            check_name=failed_check.get("check_name", "unknown"),
            severity="HIGH",  # Los checks fallidos son de alta severidad
            resource=failed_check.get("resource", "unknown"),
            file_path=failed_check.get("file_path", "unknown"),
            file_line_range=failed_check.get("file_line_range", []),
            description=failed_check.get("check_name", "No description available"),
            guideline=failed_check.get("guideline", ""),
            status="FAILED"
        )
        findings.append(finding)
    
    # Procesar checks pasados (para referencia)
    for passed_check in results.get("passed_checks", []):
        finding = SecurityFinding(
            check_id=passed_check.get("check_id", "unknown"),
            check_name=passed_check.get("check_name", "unknown"),
            severity="INFO",
            resource=passed_check.get("resource", "unknown"),
            file_path=passed_check.get("file_path", "unknown"),
            file_line_range=passed_check.get("file_line_range", []),
            description=f"✓ {passed_check.get('check_name', 'Check passed')}",
            guideline=passed_check.get("guideline", ""),
            status="PASSED"
        )
        findings.append(finding)
    
    # Procesar checks omitidos
    for skipped_check in results.get("skipped_checks", []):
        finding = SecurityFinding(
            check_id=skipped_check.get("check_id", "unknown"),
            check_name=skipped_check.get("check_name", "unknown"),
            severity="INFO",
            resource=skipped_check.get("resource", "unknown"),
            file_path=skipped_check.get("file_path", "unknown"),
            file_line_range=skipped_check.get("file_line_range", []),
            description=f"⏭ {skipped_check.get('check_name', 'Check skipped')}",
            guideline=skipped_check.get("guideline", ""),
            status="SKIPPED"
        )
        findings.append(finding)
    
    return SecurityReport(
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        skipped_checks=skipped_checks,
        findings=findings,
        checkov_version=checkov_version,
        scan_timestamp=""
    )


def get_security_summary(report: SecurityReport) -> Dict:
    """
    Obtiene un resumen del análisis de seguridad.
    
    Args:
        report (SecurityReport): Reporte de análisis de seguridad
        
    Returns:
        Dict: Resumen con estadísticas del análisis
    """
    
    if not report:
        return {"error": "No hay datos del análisis de seguridad"}
    
    # Agrupar hallazgos por severidad
    severity_counts = {}
    resource_counts = {}
    
    for finding in report.findings:
        # Contar por severidad
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Contar por recurso
        resource = finding.resource
        resource_counts[resource] = resource_counts.get(resource, 0) + 1
    
    summary = {
        "total_checks": report.total_checks,
        "passed_checks": report.passed_checks,
        "failed_checks": report.failed_checks,
        "skipped_checks": report.skipped_checks,
        "severity_breakdown": severity_counts,
        "affected_resources": len(resource_counts),
        "checkov_version": report.checkov_version,
        "security_score": calculate_security_score(report)
    }
    
    return summary


def calculate_security_score(report: SecurityReport) -> float:
    """
    Calcula un puntaje de seguridad basado en los resultados del análisis.
    
    Args:
        report (SecurityReport): Reporte de análisis de seguridad
        
    Returns:
        float: Puntaje de seguridad (0-100)
    """
    
    if report.total_checks == 0:
        return 100.0
    
    # Puntaje base: porcentaje de checks pasados
    base_score = (report.passed_checks / report.total_checks) * 100
    
    # Penalización por checks fallidos
    failed_penalty = report.failed_checks * 5  # 5 puntos por vulnerabilidad
    
    # Calcular puntaje final
    final_score = max(0, base_score - failed_penalty)
    
    return round(final_score, 2)


def get_findings_by_resource(report: SecurityReport, resource_name: str) -> List[SecurityFinding]:
    """
    Obtiene todos los hallazgos de seguridad para un recurso específico.
    
    Args:
        report (SecurityReport): Reporte de análisis de seguridad
        resource_name (str): Nombre del recurso
        
    Returns:
        List[SecurityFinding]: Lista de hallazgos para el recurso
    """
    
    return [finding for finding in report.findings if resource_name in finding.resource]


def get_high_severity_findings(report: SecurityReport) -> List[SecurityFinding]:
    """
    Obtiene todos los hallazgos de alta severidad.
    
    Args:
        report (SecurityReport): Reporte de análisis de seguridad
        
    Returns:
        List[SecurityFinding]: Lista de hallazgos de alta severidad
    """
    
    return [finding for finding in report.findings if finding.severity == "HIGH"]
