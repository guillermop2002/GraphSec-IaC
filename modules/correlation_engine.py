"""
Motor de correlación para GraphSec-IaC

Este módulo proporciona funcionalidad para correlacionar hallazgos de seguridad
con recursos de infraestructura, creando un grafo enriquecido con información de riesgo.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_sarif_results(sarif_path: str) -> List[Dict[str, Any]]:
    """
    Carga y parsea los resultados de un archivo SARIF.
    
    Args:
        sarif_path (str): Ruta al archivo SARIF
        
    Returns:
        List[Dict[str, Any]]: Lista de hallazgos de seguridad simplificados
    """
    
    try:
        # Buscar el archivo SARIF en la ubicación correcta
        actual_sarif_file = sarif_path
        if not os.path.exists(sarif_path) or os.path.isdir(sarif_path):
            # Buscar en el subdirectorio
            potential_file = os.path.join(sarif_path, 'results_sarif.sarif')
            if os.path.exists(potential_file):
                actual_sarif_file = potential_file
            else:
                logger.error(f"El archivo SARIF no existe en {sarif_path}")
                return []
        
        # Cargar y parsear el archivo SARIF
        with open(actual_sarif_file, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
        
        # Extraer resultados del primer run
        runs = sarif_data.get("runs", [])
        if not runs:
            logger.error("No se encontraron runs en el archivo SARIF")
            return []
        
        run = runs[0]
        results = run.get("results", [])
        
        # Simplificar cada hallazgo
        simplified_findings = []
        for result in results:
            finding = {
                "rule_id": result.get("ruleId", "unknown"),
                "message": result.get("message", {}).get("text", "No message"),
                "level": result.get("level", "unknown"),
                "file_path": None,
                "start_line": None,
                "end_line": None
            }
            
            # Extraer información de ubicación
            locations = result.get("locations", [])
            if locations:
                physical_location = locations[0].get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                region = physical_location.get("region", {})
                
                finding["file_path"] = artifact_location.get("uri", "")
                finding["start_line"] = region.get("startLine", 0)
                finding["end_line"] = region.get("endLine", 0)
            
            simplified_findings.append(finding)
        
        logger.info(f"Cargados {len(simplified_findings)} hallazgos de seguridad desde SARIF")
        return simplified_findings
        
    except FileNotFoundError:
        logger.error(f"Archivo SARIF no encontrado: {sarif_path}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Error al parsear archivo SARIF: {e}")
        return []
    except Exception as e:
        logger.error(f"Error inesperado al cargar SARIF: {e}")
        return []


def correlate_findings_to_graph(graph_data: Dict[str, Any], sarif_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlaciona hallazgos de seguridad con nodos del grafo de infraestructura.
    
    Args:
        graph_data (Dict[str, Any]): Datos del grafo de infraestructura
        sarif_results (List[Dict[str, Any]]): Lista de hallazgos de seguridad
        
    Returns:
        Dict[str, Any]: Grafo enriquecido con información de seguridad
    """
    
    try:
        # Crear una copia del grafo para no modificar el original
        enriched_graph = graph_data.copy()
        
        # Inicializar lista de security_issues para cada nodo
        nodes = enriched_graph.get("nodes", [])
        for node in nodes:
            node["security_issues"] = []
        
        # Contador de correlaciones exitosas
        correlations_made = 0
        
        # Iterar sobre cada hallazgo de seguridad
        for finding in sarif_results:
            finding_file = finding.get("file_path", "")
            finding_start_line = finding.get("start_line", 0)
            
            # Iterar sobre cada nodo del grafo
            for node in nodes:
                node_file = node.get("file", "")
                node_line = node.get("line", 0)
                
                # Verificar si el hallazgo corresponde a este nodo
                if _is_finding_related_to_node(finding, node):
                    # Añadir el hallazgo al nodo
                    node["security_issues"].append(finding)
                    correlations_made += 1
                    
                    logger.debug(f"Correlacionado hallazgo '{finding['rule_id']}' con nodo '{node.get('id', 'unknown')}'")
        
        logger.info(f"Correlación completada: {correlations_made} hallazgos correlacionados con {len(nodes)} nodos")
        
        # Añadir metadatos de correlación al grafo
        enriched_graph["correlation_metadata"] = {
            "total_findings": len(sarif_results),
            "total_nodes": len(nodes),
            "correlations_made": correlations_made,
            "nodes_with_issues": len([n for n in nodes if n.get("security_issues")])
        }
        
        return enriched_graph
        
    except Exception as e:
        logger.error(f"Error durante la correlación: {e}")
        return graph_data


def _is_finding_related_to_node(finding: Dict[str, Any], node: Dict[str, Any]) -> bool:
    """
    Determina si un hallazgo de seguridad está relacionado con un nodo específico.
    
    Args:
        finding (Dict[str, Any]): Hallazgo de seguridad
        node (Dict[str, Any]): Nodo del grafo
        
    Returns:
        bool: True si el hallazgo está relacionado con el nodo
    """
    
    try:
        # Extraer información del hallazgo
        finding_file = finding.get("file_path", "")
        finding_start_line = finding.get("start_line", 0)
        
        # Extraer información del nodo
        node_id = node.get("id", "")
        node_label = node.get("label", "")
        node_simple_name = node.get("simple_name", "")
        node_type = node.get("type", "")
        
        # Si el nodo tiene información de archivo y línea, usar esa lógica
        node_file = node.get("file", "")
        node_line = node.get("line", 0)
        
        if node_file and node_line:
            # Lógica original basada en archivo y línea
            if not finding_file or not node_file:
                return False
            
            # Normalizar rutas de archivo para comparación
            finding_file_normalized = os.path.normpath(finding_file)
            node_file_normalized = os.path.normpath(node_file)
            
            # Verificar si los archivos coinciden
            if finding_file_normalized != node_file_normalized:
                return False
            
            # Verificar si la línea del hallazgo está dentro del rango del nodo
            if finding_start_line >= node_line:
                return True
            
            return False
        else:
            # Lógica alternativa basada en el tipo de recurso y ubicación del archivo
            # Verificar si el hallazgo está en el mismo archivo que el recurso
            if not finding_file:
                return False
            
            # Verificar si el tipo de recurso del nodo coincide con el tipo mencionado en el hallazgo
            # Los hallazgos de Checkov suelen mencionar el tipo de recurso en el mensaje
            finding_message = finding.get("message", "").lower()
            
            # Mapeo de tipos de recursos AWS
            resource_type_mapping = {
                "aws_s3_bucket": ["s3 bucket", "bucket"],
                "aws_s3_bucket_logging": ["s3 bucket logging", "bucket logging"],
                "aws_ec2_instance": ["ec2 instance", "instance"],
                "aws_security_group": ["security group", "sg"],
                "aws_iam_role": ["iam role", "role"],
                "aws_iam_policy": ["iam policy", "policy"]
            }
            
            # Verificar si el tipo de recurso del nodo está mencionado en el hallazgo
            if node_type in resource_type_mapping:
                for keyword in resource_type_mapping[node_type]:
                    if keyword in finding_message:
                        return True
            
            # Verificar si el ID del recurso está mencionado en el hallazgo
            if node_simple_name and node_simple_name.lower() in finding_message:
                return True
            
            # Verificar si el nombre del recurso está mencionado en el hallazgo
            if node_label and node_label.lower() in finding_message:
                return True
            
            return False
        
    except Exception as e:
        logger.debug(f"Error al verificar relación nodo-hallazgo: {e}")
        return False


def get_security_summary_for_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """
    Obtiene un resumen de seguridad para un nodo específico.
    
    Args:
        node (Dict[str, Any]): Nodo del grafo
        
    Returns:
        Dict[str, Any]: Resumen de seguridad del nodo
    """
    
    security_issues = node.get("security_issues", [])
    
    if not security_issues:
        return {
            "has_issues": False,
            "total_issues": 0,
            "severity_breakdown": {},
            "issues": []
        }
    
    # Contar por severidad
    severity_breakdown = {}
    for issue in security_issues:
        severity = issue.get("level", "unknown")
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
    
    # Crear lista simplificada de issues
    issues_list = []
    for issue in security_issues:
        issues_list.append({
            "rule_id": issue.get("rule_id", "unknown"),
            "message": issue.get("message", "No message"),
            "severity": issue.get("level", "unknown")
        })
    
    return {
        "has_issues": True,
        "total_issues": len(security_issues),
        "severity_breakdown": severity_breakdown,
        "issues": issues_list
    }


def print_node_security_summary(node: Dict[str, Any]) -> None:
    """
    Imprime un resumen de seguridad para un nodo específico.
    
    Args:
        node (Dict[str, Any]): Nodo del grafo
    """
    
    node_id = node.get("id", "unknown")
    node_type = node.get("type", "unknown")
    
    print(f"\nProblemas de seguridad encontrados para el recurso '{node_id}' ({node_type}):")
    
    security_issues = node.get("security_issues", [])
    
    if not security_issues:
        print("  ✅ No se encontraron problemas de seguridad")
        return
    
    for i, issue in enumerate(security_issues, 1):
        rule_id = issue.get("rule_id", "unknown")
        message = issue.get("message", "No message")
        severity = issue.get("level", "unknown")
        
        print(f"  {i}. {message}")
        print(f"     ID: {rule_id} (Severidad: {severity})")
    
    print(f"\n  Total: {len(security_issues)} problemas encontrados")
