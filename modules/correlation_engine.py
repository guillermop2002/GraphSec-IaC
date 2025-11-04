"""
Motor de correlación para GraphSec-IaC

Este módulo proporciona funcionalidad para correlacionar hallazgos de seguridad
con recursos de infraestructura, creando un grafo enriquecido con información de riesgo.
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional, Set, Tuple
import hashlib

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Eliminado RULE_MAPPING (normalizamos directamente a CIS)

# Mapeo adicional a un estándar común (CIS) para CFI
# Normalizamos reglas heterogéneas (Checkov/Trivy) a un control CIS cuando sea posible
RULE_CIS_MAP: Dict[str, str] = {
    # ===== S3 (CIS-AWS-2.1.x) =====
    # S3 Bucket Encryption
    "CKV_AWS_19": "CIS-AWS-2.1.1",
    "AVD-AWS-0088": "CIS-AWS-2.1.1",
    "CKV2_AWS_6": "CIS-AWS-2.1.1",
    # S3 Bucket Logging
    "CKV_AWS_18": "CIS-AWS-2.1.3",
    "AVD-AWS-0089": "CIS-AWS-2.1.3",
    "s3-bucket-logging": "CIS-AWS-2.1.3",
    # S3 Public Access Block
    "CKV_AWS_54": "CIS-AWS-2.1.5",
    "AVD-AWS-0092": "CIS-AWS-2.1.5",
    # S3 Public Read ACL (relacionado con 2.1.5)
    "CKV_AWS_20": "CIS-AWS-2.1.5-ACL",
    "AVD-AWS-0086": "CIS-AWS-2.1.5-ACL",
    # S3 Bucket Versioning
    "CKV2_AWS_19": "CIS-AWS-2.1.6",
    "AVD-AWS-0090": "CIS-AWS-2.1.6",
    
    # ===== CloudWatch Logs (CIS-AWS-3.2.x) =====
    # CloudWatch Log Group Encryption
    "CKV_AWS_158": "CIS-AWS-3.2.1",
    "AVD-AWS-0017": "CIS-AWS-3.2.1",
    # CloudWatch Log Retention
    "CKV_AWS_338": "CIS-AWS-3.2.2",
    "AVD-AWS-0166": "CIS-AWS-3.2.2",
    
    # ===== VPC (CIS-AWS-4.x) =====
    # Default VPC Usage
    "CKV_AWS_148": "CIS-AWS-4.1.1",
    "aws-vpc-no-default-vpc": "CIS-AWS-4.1.1",
    # VPC Flow Logs
    "CKV_AWS_126": "CIS-AWS-4.3",
    "AVD-AWS-0132": "CIS-AWS-4.3",
    # Security Groups - No Public Ingress
    "aws-vpc-no-public-ingress-acl": "CIS-AWS-4.2.1",
    "CKV_AWS_260": "CIS-AWS-4.2.1",
    "AVD-AWS-0107": "CIS-AWS-4.2.1",
    # Security Groups - No Excessive Port Access
    "aws-vpc-no-excessive-port-access": "CIS-AWS-4.2.2",
    "CKV_AWS_23": "CIS-AWS-4.2.2",
    "AVD-AWS-0103": "CIS-AWS-4.2.2",
    
    # ===== Secrets Manager (CIS-AWS-2.2.x) =====
    # Secrets Manager Encryption
    "CKV2_AWS_5": "CIS-AWS-2.2.1",
    "AVD-AWS-0094": "CIS-AWS-2.2.1",
    
    # ===== GuardDuty & Security Hub (CIS-AWS-3.x) =====
    # GuardDuty Enabled
    "CKV2_AWS_11": "CIS-AWS-3.1",
    "AVD-AWS-0022": "CIS-AWS-3.1",
    # Security Hub Enabled
    "CKV2_AWS_12": "CIS-AWS-3.2",
    "AVD-AWS-0099": "CIS-AWS-3.2",
    
    # ===== Auto Scaling =====
    # Auto Scaling Encryption at Rest
    "aws-autoscaling-enable-at-rest-encryption": "CIS-AWS-2.3.1",
    "CKV_AWS_8": "CIS-AWS-2.3.1",
    "AVD-AWS-0009": "CIS-AWS-2.3.1",
    
    # ===== RDS =====
    # RDS Encryption at Rest
    "CKV_AWS_16": "CIS-AWS-3.3.1",
    "AVD-AWS-0056": "CIS-AWS-3.3.1",
    # RDS Public Access
    "CKV_AWS_17": "CIS-AWS-3.3.2",
    "AVD-AWS-0057": "CIS-AWS-3.3.2",
    
    # ===== EBS =====
    # EBS Volume Encryption
    "CKV_AWS_3": "CIS-AWS-2.4.1",
    "AVD-AWS-0026": "CIS-AWS-2.4.1",
    
    # ===== IAM =====
    # IAM Password Policy
    "CKV_AWS_9": "CIS-AWS-1.5",
    "AVD-AWS-0062": "CIS-AWS-1.5",
    
    # ===== Terraform General =====
    # Terraform Backend Encryption
    "CKV_TF_1": "TF-BACKEND-1",
    
    # ===== IAM Policies (CIS-AWS-1.x) =====
    # IAM Policy No Wildcard Resource
    "CKV_AWS_79": "CIS-AWS-1.3.1",
    "AVD-AWS-0054": "CIS-AWS-1.3.1",
    # IAM Policy No Wildcard Actions
    "CKV_AWS_356": "CIS-AWS-1.3.2",
    "AVD-AWS-0055": "CIS-AWS-1.3.2",
    # IAM Policy No Write Access Without Constraints
    "CKV_AWS_341": "CIS-AWS-1.4.1",
    "AVD-AWS-0058": "CIS-AWS-1.4.1",
    
    # ===== Karpenter =====
    # Karpenter IAM Policy Issues
    "AVD-AWS-0342": "CIS-AWS-1.3.3",
    
    # ===== Auto Scaling Groups =====
    # Auto Scaling Encryption Issues
    "AVD-AWS-0038": "CIS-AWS-2.3.2",
    
    # ===== Security Groups =====
    # Security Group Public Egress
    "aws-vpc-no-public-egress-sgr": "CIS-AWS-4.2.3",
    # Security Group Rule Description (añadido desde build_rule_map.py)
    "aws-vpc-add-description-to-security-group-rule": "CIS-AWS-4.2.2-DESC",
    
    # ===== Kubernetes (CIS-K8S) =====
    # K8S Default Namespace
    "CKV_K8S_21": "CIS-K8S-5.7.1",
    "KSV110": "CIS-K8S-5.7.1",
    # K8S Memory Requests
    "CKV_K8S_12": "CIS-K8S-5.2.1",
    "KSV016": "CIS-K8S-5.2.1",
    # K8S Seccomp Profile
    "CKV_K8S_31": "CIS-K8S-5.7.3",
    "KSV030": "CIS-K8S-5.7.3",
}

# ... existing code ...


# Variable global para almacenar el directorio raíz del proyecto
_project_root: Optional[str] = None


def set_project_root(root_directory: str) -> None:
    """
    Establece el directorio raíz del proyecto para normalización de rutas.
    
    Args:
        root_directory: Ruta absoluta del directorio raíz del proyecto
    """
    global _project_root
    if root_directory:
        _project_root = os.path.abspath(os.path.normpath(root_directory))
        logger.debug(f"Directorio raíz del proyecto establecido: {_project_root}")


def normalize_file_path(file_path: str, project_root: Optional[str] = None) -> str:
    """
    Normaliza una ruta de archivo a ruta absoluta para comparación directa.
    
    ESTRATEGIA CAMBIADA: Usamos rutas absolutas como fuente única de verdad.
    Esto elimina problemas de normalización y permite comparación directa.
    
    Args:
        file_path: Ruta del archivo (absoluta, relativa, con subcarpetas)
        project_root: Directorio raíz del proyecto (ruta absoluta)
    
    Returns:
        Ruta absoluta normalizada del archivo
    """
    if not file_path:
        return ""
    
    # Usar el directorio raíz global o el pasado como parámetro
    root = project_root or _project_root
    
    if not root:
        # Sin raíz, intentar convertir a absoluta si es posible
        if os.path.isabs(file_path):
            return os.path.normpath(file_path)
        else:
            # Fallback: devolver tal cual (no podemos hacer nada)
            logger.warning(f"Sin raíz del proyecto para normalizar: '{file_path}'")
            return file_path
    
    try:
        # Si ya es absoluta, normalizarla y retornar
        if os.path.isabs(file_path):
            abs_file_path = os.path.normpath(file_path)
            logger.debug(f"Ruta ya absoluta: '{file_path}' -> '{abs_file_path}'")
            return abs_file_path
        
        # Si es relativa, puede venir en varios formatos:
        # - "main.tf" (relativa desde el directorio actual)
        # - "terraform-aws-eks/main.tf" (incluye el nombre del directorio raíz)
        
        # Eliminar el prefijo del directorio raíz si existe
        root_basename = os.path.basename(root)
        file_path_clean = file_path.replace("\\", "/")
        
        if file_path_clean.startswith(f"{root_basename}/"):
            file_path_clean = file_path_clean[len(root_basename) + 1:]
        elif file_path_clean.startswith(f"{root_basename}\\"):
            file_path_clean = file_path_clean[len(root_basename) + 1:]
        
        # Construir la ruta absoluta desde el directorio raíz
        abs_file_path = os.path.normpath(os.path.join(root, file_path_clean))
        
        logger.debug(f"Ruta normalizada a absoluta: '{file_path}' -> '{abs_file_path}'")
        return abs_file_path
            
    except Exception as e:
        logger.warning(f"Error al normalizar ruta '{file_path}': {e}")
        # Fallback: intentar construir desde root
        try:
            return os.path.normpath(os.path.join(root, file_path))
        except:
            return file_path


# Eliminado normalize_rule_id (sustituido por normalize_rule_to_cis)


def normalize_rule_to_cis(rule_id: str) -> str:
    """
    Normaliza un ID de regla heterogéneo (Checkov/Trivy) a un control CIS cuando sea posible.
    Si no hay mapeo, devuelve el propio rule_id.
    """
    return RULE_CIS_MAP.get(rule_id, rule_id)


# ... existing code ...


# ... existing code ...


def create_canonical_finding_identifier(finding: Dict[str, Any], resource_id: str) -> str:
    """
    Crea un Identificador Canónico de Hallazgo (CFI) estable:
    Prioriza partialFingerprints si existen; en su defecto, usa hash SHA-256 de
    (cis_id_normalizado, resource_id, archivo_normalizado, start_line).
    """
    # 1) Priorizar huella SARIF si está disponible
    sarif_fp = finding.get("fingerprint")
    if sarif_fp:
        key = f"sarif:{sarif_fp}:{resource_id}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    # 2) Fallback canónico propio basado en control CIS y ubicación
    rule_id = finding.get("rule_id", "unknown")
    cis_id = normalize_rule_to_cis(rule_id)
    normalized_file = normalize_file_path(finding.get("file_path", ""))
    start_line = str(finding.get("start_line", 0))
    composite_key = f"cis:{cis_id}:{resource_id}:{normalized_file}:{start_line}"
    return hashlib.sha256(composite_key.encode("utf-8")).hexdigest()

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
        try:
            with open(actual_sarif_file, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Fichero SARIF corrupto o con formato JSON inválido: {actual_sarif_file}. Error: {e}. Omitiendo.")
            return []
        
        # Validar estructura básica del archivo SARIF
        if not isinstance(sarif_data, dict):
            logger.warning(f"Fichero SARIF no es un objeto JSON válido: {actual_sarif_file}. Omitiendo.")
            return []
        
        # Extraer resultados del primer run
        runs = sarif_data.get("runs", [])
        if not runs or not isinstance(runs, list) or len(runs) == 0:
            logger.warning(f"Fichero SARIF inválido o vacío (sin runs): {actual_sarif_file}. Omitiendo.")
            return []
        
        run = runs[0]
        results = run.get("results", [])
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "unknown")
        
        # Simplificar cada hallazgo
        simplified_findings = []
        for result in results:
            finding = {
                "rule_id": result.get("ruleId", "unknown"),
                "message": result.get("message", {}).get("text", "No message"),
                "level": result.get("level", "unknown"),
                "file_path": None,
                "start_line": None,
                "end_line": None,
                "tool_name": tool_name,
                "fingerprint": None
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
            
            # Intentar extraer partialFingerprints si están presentes (SARIF estándar)
            partial_fps = result.get("partialFingerprints", {})
            # Heurística: tomar la primera huella disponible para deduplicación
            if isinstance(partial_fps, dict) and partial_fps:
                try:
                    finding["fingerprint"] = next(iter(partial_fps.values()))
                except Exception:
                    finding["fingerprint"] = None
            
            simplified_findings.append(finding)
        
        logger.info(f"Cargados {len(simplified_findings)} hallazgos de seguridad desde {tool_name}")
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


def load_multiple_sarif_results(sarif_paths: List[str]) -> List[Dict[str, Any]]:
    """
    Carga y combina los resultados de múltiples archivos SARIF.
    
    Args:
        sarif_paths (List[str]): Lista de rutas a archivos SARIF
        
    Returns:
        List[Dict[str, Any]]: Lista combinada de hallazgos de seguridad
    """
    
    all_findings = []
    
    for sarif_path in sarif_paths:
        findings = load_sarif_results(sarif_path)
        all_findings.extend(findings)
    
    logger.info(f"Total de hallazgos cargados de {len(sarif_paths)} archivos: {len(all_findings)}")
    return all_findings


# ... existing code ...


# ... existing code ...


# Eliminado: lógica antigua de correlación heurística


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
            "severity": issue.get("level", "unknown"),
            "tool": issue.get("tool_name", "unknown")
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
        tool = issue.get("tool_name", "unknown")
        
        print(f"  {i}. {message}")
        print(f"     ID: {rule_id} | Severidad: {severity} | Tool: {tool}")
    
    print(f"\n  Total: {len(security_issues)} problemas encontrados")


def _match_resource_id_by_filename(finding: Dict[str, Any], nodes: List[Dict[str, Any]], project_root: Optional[str] = None) -> str:
    """
    Intenta inferir el resource_id del nodo comparando el nombre del archivo del hallazgo
    con el nombre del archivo del nodo usando rutas absolutas normalizadas.
    
    ESTRATEGIA MEJORADA: Encuentra el nodo más cercano por distancia de líneas dentro del mismo archivo.
    
    Args:
        finding: Hallazgo completo con metadatos de ubicación (incluye file_path y start_line)
        nodes: Lista de nodos del grafo con metadatos de archivo y líneas
        project_root: Directorio raíz del proyecto para normalización
    """
    finding_file_path = finding.get("file_path", "") or ""
    if not finding_file_path:
        return "unknown_resource"
    
    # Normalizar ruta del hallazgo a absoluta
    finding_path_abs = normalize_file_path(finding_file_path, project_root)
    
    if not finding_path_abs:
        logger.debug(f"[Capa 2] No se pudo normalizar ruta del hallazgo: '{finding_file_path}'")
        return "unknown_resource"
    
    logger.debug(f"[Capa 2] Buscando match por filename: '{finding_file_path}' -> '{finding_path_abs}'")
    
    # Encontrar todos los nodos en el mismo archivo
    nodes_in_file = []
    for node in nodes:
        node_file_path = node.get("file", "") or ""
        if not node_file_path:
            continue
        
        # Normalizar ruta del nodo a absoluta (los nodos ya tienen rutas absolutas del parser)
        node_path_abs = normalize_file_path(node_file_path, project_root)
        
        if not node_path_abs:
            continue
        
        # Comparar rutas absolutas directamente
        if finding_path_abs == node_path_abs:
            nodes_in_file.append(node)
    
    if not nodes_in_file:
        logger.debug(f"[Capa 2] NO SE ENCONTRO MATCH para archivo '{finding_path_abs}'")
        return "unknown_resource"
    
    # Obtener la línea del hallazgo
    finding_line = int(finding.get("start_line", 0) or 0)
    
    # Inicializar variables para encontrar el nodo más cercano
    min_distance = float('inf')
    best_match_node = None
    
    # Iterar sobre todos los nodos en el mismo archivo para encontrar el más cercano
    for node in nodes_in_file:
        node_line = int(node.get("start_line", 0) or 0)
        
        # Si el nodo tiene línea válida, calcular distancia
        if node_line > 0:
            distance = abs(finding_line - node_line)
            
            # Actualizar si encontramos un nodo más cercano
            if distance < min_distance:
                min_distance = distance
                best_match_node = node
    
    # Verificar si encontramos un match válido
    if best_match_node:
        # Usar ID único en lugar de simple_name
        result = best_match_node.get("id", "unknown_resource")
        logger.debug(
            f"[Capa 2] Hallazgo en línea {finding_line} asignado al nodo más cercano "
            f"{result} (línea {best_match_node.get('start_line')}, distancia: {min_distance})"
        )
        return result
    else:
        # Ningún nodo tenía línea válida, devolver el primero como fallback
        if nodes_in_file:
            # Usar ID único en lugar de simple_name
            result = nodes_in_file[0].get("id", "unknown_resource")
            logger.debug(f"[Capa 2] Ningún nodo con línea válida, usando primer nodo: {result}")
            return result
    
    logger.debug(f"[Capa 2] NO SE ENCONTRO MATCH válido para archivo '{finding_path_abs}'")
    return "unknown_resource"


def _match_resource_id_by_semantics(finding: Dict[str, Any], nodes: List[Dict[str, Any]]) -> str:
    """
    Fallback semántico (Capa 3): asigna el hallazgo a un nodo cuyo tipo coincida con
    palabras clave del mensaje/regla. Útil cuando no hay metadatos de archivo.
    
    IMPORTANTE: Esta capa es CONSERVADORA. Solo asigna si hay UN SOLO candidato claro.
    Si hay múltiples nodos candidatos, se deja como "no asignado" para evitar falsos positivos.
    """
    message = (finding.get("message") or "").lower()
    rule_id = finding.get("rule_id", "").lower()
    cis = normalize_rule_to_cis(finding.get("rule_id", "unknown"))
    candidates = []
    
    # Estrategia 1: CIS mapping (más específico)
    if cis.startswith("CIS-AWS-2.1"):
        # Controles CIS 2.1.x suelen referirse a S3 bucket
        for node in nodes:
            if node.get("type") == "aws_s3_bucket":
                # Usar ID único en lugar de simple_name
                candidates.append(node.get("id", "unknown_resource"))
    
    # Estrategia 2: Palabras clave por tipo de recurso (si no hay candidatos CIS)
    if not candidates:
        type_keywords = {
            "aws_s3_bucket": ["s3", "bucket"],
            "aws_s3_bucket_logging": ["logging", "log"],
            "aws_security_group": ["security group", "sg"],
            "aws_ec2_instance": ["ec2", "instance"],
            "aws_iam_role": ["iam role", "role"],
            "aws_iam_policy": ["iam policy", "policy"],
        }
        for node in nodes:
            ntype = node.get("type", "")
            for kw in type_keywords.get(ntype, []):
                if kw in message or kw in rule_id:
                    # Usar ID único en lugar de simple_name
                    candidates.append(node.get("id", "unknown_resource"))
                    break  # Un match por nodo es suficiente
    
    # CONSERVADOR: Solo asignar si hay UN SOLO candidato claro
    if len(candidates) == 1:
        result = candidates[0]
        logger.debug(f"Capa 3 asignó hallazgo {finding.get('rule_id')} a {result} (1 candidato único)")
        return result
    elif len(candidates) > 1:
        # Múltiples candidatos: mejor dejar como "no asignado" que arriesgar falsos positivos
        logger.debug(f"Capa 3 rechazó asignación: {finding.get('rule_id')} tiene {len(candidates)} candidatos (múltiples)")
        return "unknown_resource"
    else:
        # No hay candidatos
        logger.debug(f"Capa 3: No se encontraron candidatos para {finding.get('rule_id')}")
        return "unknown_resource"


def _match_resource_id_by_range(finding: Dict[str, Any], nodes: List[Dict[str, Any]], margin: int = 0, project_root: Optional[str] = None) -> str:
    """
    Intenta inferir el resource_id del nodo comparando el rango de líneas del hallazgo
    con el rango de líneas del nodo (obtenido del parser) usando rutas absolutas.
    
    ESTRATEGIA CAMBIADA: Comparación directa de rutas absolutas.
    
    Args:
        finding: Hallazgo de seguridad con metadatos de ubicación
        nodes: Lista de nodos del grafo con metadatos de línea
        margin: Margen de líneas permitido para la correlación
        project_root: Directorio raíz del proyecto para normalización
    """
    finding_file_path = finding.get("file_path", "")
    finding_line = int(finding.get("start_line", 0) or 0)
    
    if not finding_file_path or not finding_line:
        logger.debug(f"Hallazgo sin metadatos de ubicación: file_path={finding_file_path}, line={finding_line}")
        return "unknown_resource"
    
    # Normalizar ruta del hallazgo a absoluta
    finding_path_abs = normalize_file_path(finding_file_path, project_root)
    
    if not finding_path_abs:
        logger.debug(f"No se pudo normalizar ruta del hallazgo: '{finding_file_path}'")
        return "unknown_resource"
    
    logger.debug(f"[Capa 1] Intentando match para hallazgo: rule_id={finding.get('rule_id')}, file='{finding_file_path}' -> '{finding_path_abs}', line={finding_line}")
    
    candidates = []
    nodes_checked = 0
    nodes_same_file = 0
    
    for node in nodes:
        node_file_path = node.get("file", "") or ""
        node_start = int(node.get("start_line", 0) or 0)
        node_end = int(node.get("end_line", 0) or 0)
        
        nodes_checked += 1
        
        if not node_file_path:
            continue
        
        # Normalizar ruta del nodo a absoluta (los nodos ya tienen rutas absolutas del parser)
        node_path_abs = normalize_file_path(node_file_path, project_root)
        
        if not node_path_abs:
            continue
        
        # Comparar rutas absolutas directamente
        if finding_path_abs != node_path_abs:
            # Log solo para debugging (reducir verbosidad)
            if nodes_checked <= 5:  # Solo log para los primeros 5 para no saturar
                logger.debug(f"[Capa 1] FALLO match ruta: hallazgo='{finding_path_abs}' != nodo='{node_path_abs}'")
            continue
        
        nodes_same_file += 1
        
        # Verificar rango de líneas
        if node_start > 0 and node_end > 0:
            if (node_start - margin) <= finding_line <= (node_end + margin):
                # Calcular distancia (preferir matches más cercanos al inicio del recurso)
                distance = abs(finding_line - node_start) + abs(node_end - finding_line)
                # Usar ID único en lugar de simple_name
                candidates.append((distance, node.get("id", "unknown_resource")))
                logger.debug(f"[Capa 1] MATCH encontrado: nodo={node.get('id')}, rango={node_start}-{node_end}, distancia={distance}")
            else:
                logger.debug(f"[Capa 1] FALLO match rango: hallazgo línea {finding_line} fuera de rango {node_start}-{node_end} (margen={margin})")
        else:
            logger.debug(f"[Capa 1] Nodo sin rango válido: {node.get('simple_name')}, start={node_start}, end={node_end}")
    
    if candidates:
        candidates.sort(key=lambda x: x[0])
        best_match = candidates[0][1]
        logger.debug(f"[Capa 1] MEJOR MATCH seleccionado: {best_match} (de {len(candidates)} candidatos, {nodes_same_file} nodos en mismo archivo de {nodes_checked} verificados)")
        return best_match
    else:
        logger.debug(f"[Capa 1] NO SE ENCONTRO MATCH: {nodes_same_file} nodos en mismo archivo '{finding_path_abs}', pero ninguno coincide en rango de líneas")
        return "unknown_resource"


def _should_filter_finding(finding: Dict[str, Any], project_root: Optional[str] = None) -> bool:
    """
    Determina si un hallazgo debe ser filtrado (ignorado) antes del procesamiento.
    
    Filtra hallazgos que están fuera del ámbito del módulo raíz:
    - Hallazgos en /examples/ (son proyectos separados)
    - Hallazgos en archivos .yml/.yaml (Kubernetes, GitHub Actions - no tienen nodos Terraform)
    - Hallazgos en /tests/ (no son parte del módulo principal)
    
    Args:
        finding: Hallazgo de seguridad
        project_root: Directorio raíz del proyecto
    
    Returns:
        True si el hallazgo debe ser filtrado (ignorado), False si debe procesarse
    """
    file_path = finding.get("file_path", "")
    if not file_path:
        return False  # Sin ruta, no podemos filtrar
    
    # Normalizar a ruta absoluta para análisis
    file_path_abs = normalize_file_path(file_path, project_root)
    
    # Verificar si el archivo existe físicamente (CRÍTICO para módulos remotos)
    # Los escáneres pueden reportar hallazgos en módulos de Terraform Registry que están en cache
    # pero no existen en el código fuente del usuario
    if file_path_abs and project_root:
        if not os.path.exists(file_path_abs):
            # El archivo no existe físicamente - probablemente es un módulo remoto en cache
            logger.debug(f"Filtrando hallazgo en archivo inexistente (módulo remoto/cache): {file_path}")
            return True
    
    # Normalizar separadores para comparación
    file_path_normalized = file_path_abs.replace("\\", "/").lower() if file_path_abs else ""
    
    # Filtrar archivos YAML
    if file_path_normalized.endswith((".yml", ".yaml")):
        logger.debug(f"Filtrando hallazgo en archivo YAML: {file_path}")
        return True
    
    # Filtrar directorios de ejemplos y tests
    if "/examples/" in file_path_normalized or "\\examples\\" in file_path_normalized:
        logger.debug(f"Filtrando hallazgo en directorio examples/: {file_path}")
        return True
    
    if "/tests/" in file_path_normalized or "\\tests\\" in file_path_normalized:
        logger.debug(f"Filtrando hallazgo en directorio tests/: {file_path}")
        return True
    
    # Filtrar módulos remotos de Terraform Registry (están en cache pero no en el proyecto)
    # Estos aparecen como terraform-aws-modules/... pero no existen físicamente
    # COMENTADO: Este filtro estaba eliminando hallazgos válidos
    # if "terraform-aws-modules/" in file_path_normalized:
    #     logger.debug(f"Filtrando hallazgo en módulo remoto terraform-aws-modules/: {file_path}")
    #     return True
    
    # Filtrar directorio de cache de Terraform
    if "/.terraform/" in file_path_normalized or "\\.terraform\\" in file_path_normalized:
        logger.debug(f"Filtrando hallazgo en cache .terraform/: {file_path}")
        return True
    
    return False


def process_and_deduplicate_findings(findings: List[Dict[str, Any]], graph_data: Dict[str, Any], project_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Procesa hallazgos en bruto, genera CFIs por recurso (nodo) y de-duplica por CFI.
    Devuelve la lista de hallazgos únicos enriquecidos y el número de duplicados eliminados.
    
    ANTES del procesamiento, filtra hallazgos que están fuera del ámbito del módulo raíz
    (ejemplos, tests, archivos YAML) para evitar ruido.
    
    Args:
        findings: Lista de hallazgos de seguridad en bruto
        graph_data: Grafo con nodos y aristas
        project_root: Directorio raíz del proyecto para normalización de rutas
    """
    nodes = graph_data.get("nodes", [])
    total_original = len(findings)
    
    # Establecer el directorio raíz global si se proporciona
    if project_root:
        set_project_root(project_root)
        logger.info(f"Directorio raíz del proyecto establecido para correlación: {project_root}")

    # FILTRAR HALLAZGOS: Eliminar ruido antes del procesamiento
    filtered_findings = []
    filtered_count = 0
    for finding in findings:
        if _should_filter_finding(finding, project_root):
            filtered_count += 1
            continue
        filtered_findings.append(finding)
    
    logger.info(f"Filtrado de hallazgos: {filtered_count} hallazgos ignorados (examples/, tests/, .yml), {len(filtered_findings)} procesados")

    # Por CFI global (independiente del nodo) no forzamos dedup; el CFI incluye resource_id
    seen_cfi: Set[str] = set()
    unique_findings: List[Dict[str, Any]] = []
    
    # Estadísticas de correlación por capa
    layer_stats = {1: 0, 2: 0, 3: 0, 0: 0}

    for finding in filtered_findings:
        # 1) Rango de líneas + filename (Capa 1: más precisa)
        resource_id = _match_resource_id_by_range(finding, nodes, margin=0, project_root=project_root)
        correlation_layer = 1
        layer_reason = "rango de líneas + filename"
        
        # 2) Filename simple (Capa 2: fallback mejorado - nodo más cercano)
        if resource_id == "unknown_resource":
            resource_id = _match_resource_id_by_filename(finding, nodes, project_root=project_root)
            correlation_layer = 2
            layer_reason = "filename simple (nodo más cercano)"
        
        # 3) Semántica (Capa 3: último recurso, conservadora)
        if resource_id == "unknown_resource":
            resource_id = _match_resource_id_by_semantics(finding, nodes)
            correlation_layer = 3 if resource_id != "unknown_resource" else 0
            layer_reason = "semántica/CIS" if correlation_layer == 3 else "no asignado"
        
        # Contar por capa
        layer_stats[correlation_layer] = layer_stats.get(correlation_layer, 0) + 1
        
        # Logging para auditoría (solo si no es Capa 1, que es la mayoría)
        if correlation_layer != 1:
            logger.info(
                f"Hallazgo {finding.get('rule_id')} asignado por Capa {correlation_layer} "
                f"({layer_reason}) -> {resource_id}"
            )
        cfi = create_canonical_finding_identifier(finding, resource_id)
        if cfi in seen_cfi:
            continue
        seen_cfi.add(cfi)
        unique_findings.append({
            "cfi": cfi,
            "rule_id": finding.get("rule_id", "unknown"),
            "normalized_cis": normalize_rule_to_cis(finding.get("rule_id", "unknown")),
            "resource_id": resource_id,
            "message": finding.get("message", "No message"),
            "level": finding.get("level", "unknown"),
            "file_path": finding.get("file_path", ""),
            "start_line": finding.get("start_line", 0),
            "tool_name": finding.get("tool_name", "unknown"),
            "sources": [finding.get("tool_name", "unknown")],
            "correlation_layer": correlation_layer,  # Track qué capa se usó
        })

    duplicates_removed = total_original - len(unique_findings)
    logger.info(
        f"De-duplicación (CFI) completada: {total_original} -> {len(unique_findings)} (eliminados {duplicates_removed})"
    )
    logger.info(
        f"Distribución por capas: Capa 1={layer_stats[1]}, Capa 2={layer_stats[2]}, Capa 3={layer_stats[3]}, No asignados={layer_stats[0]}"
    )

    return {
        "unique_findings": unique_findings,
        "duplicates_removed": duplicates_removed,
        "layer_stats": layer_stats,  # Incluir estadísticas de capas
    }


def attach_findings_to_graph(graph_data: Dict[str, Any], unique_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Adjunta hallazgos únicos (ya de-duplicados) a los nodos del grafo usando resource_id.
    Ahora resource_id es el ID único del nodo (no simple_name).
    """
    enriched_graph = graph_data.copy()
    nodes = enriched_graph.get("nodes", [])
    # Usar ID único como clave (no simple_name)
    nodes_by_id = {n.get("id", ""): n for n in nodes}
    for node in nodes:
        node["security_issues"] = []

    for uf in unique_findings:
        rid = uf.get("resource_id")
        if rid in nodes_by_id:
            nodes_by_id[rid]["security_issues"].append(uf)

    # Calcular asignados y no asignados
    assigned_count = sum(len(n.get("security_issues", [])) for n in nodes)
    unassigned = [uf for uf in unique_findings if uf.get("resource_id") not in nodes_by_id]
    
    # Calcular nodos vulnerables (nodos que tienen al menos 1 hallazgo)
    nodes_with_issues_count = sum(1 for n in nodes if len(n.get("security_issues", [])) > 0)
    
    enriched_graph["unassigned_findings"] = unassigned
    enriched_graph["correlation_metadata"] = {
        "assigned_findings": assigned_count,
        "unassigned_findings_count": len(unassigned),
        "nodes_with_issues_count": nodes_with_issues_count,  # Nodos que tienen al menos 1 hallazgo
        "total_unique_findings": len(unique_findings)
    }

    return enriched_graph