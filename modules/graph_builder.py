"""
Construcción/enriquecimiento del grafo a partir del parser propio.

Este módulo proporciona:
1. Enriquecimiento de nodos existentes con metadatos del parser
2. Construcción de aristas (edges) mediante análisis de dependencias en Terraform
"""

from typing import Dict, Any, List
import re
import logging

logger = logging.getLogger(__name__)


def enrich_graph_nodes_with_parsed(graph_data: Dict[str, Any], parsed_resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Devuelve un grafo con nodos enriquecidos con `file`, `line` (start) y `end_line`.
    Empareja por `simple_name`.
    """
    if not graph_data:
        return graph_data

    nodes: List[Dict[str, Any]] = graph_data.get("nodes", [])
    # Índice por simple_name del parser
    parsed_index = {r.get("simple_name"): r for r in parsed_resources}

    for node in nodes:
        sname = node.get("simple_name") or node.get("id") or node.get("label")
        if not sname:
            continue
        match = parsed_index.get(sname)
        if not match:
            continue
        # Enriquecer sin romper estructura
        # Guardar tanto 'line' (compatibilidad) como 'start_line' (para correlación)
        node["file"] = match.get("file")
        node["line"] = match.get("start_line")
        node["start_line"] = match.get("start_line")  # CRÍTICO: Necesario para _match_resource_id_by_range
        node["end_line"] = match.get("end_line")

    return graph_data


def build_edges(parsed_resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Construye las aristas (edges) del grafo analizando dependencias en Terraform.
    
    Usa expresiones regulares para encontrar interpolaciones de Terraform (${resource.type.name})
    y construye las relaciones de dependencia entre recursos.
    
    Args:
        parsed_resources: Lista de recursos parseados con metadatos y raw_block_text
    
    Returns:
        Lista de diccionarios representando aristas: [{"from": "resource1", "to": "resource2"}, ...]
    """
    if not parsed_resources:
        logger.warning("Lista de recursos vacía, no se pueden construir aristas")
        return []
    
    # Crear mapa de recursos para búsqueda rápida
    resource_map = {r.get('simple_name'): r for r in parsed_resources}
    logger.debug(f"Construyendo aristas desde {len(parsed_resources)} recursos")
    
    edges = []
    
    # Patrón RegEx para encontrar dependencias de Terraform
    # Terraform permite dos formas de referenciar recursos:
    # 1. Con interpolación: ${aws_vpc.main.id} o "prefix_${aws_s3_bucket.my_bucket.arn}_suffix"
    # 2. Sin interpolación (nueva sintaxis): aws_vpc.main.id (en asignaciones directas)
    # El patrón captura el resource.type.name (ej: aws_vpc.main de ${aws_vpc.main.id} o aws_vpc.main.id)
    # También debemos capturar var.name, data.source.name, etc.
    
    # Patrón para interpolaciones: ${resource.type.name.attribute}
    pattern_interpolation = re.compile(
        r'\$\{([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_]+)*\}'
    )
    
    # Patrón para referencias directas (sin ${}): resource.type.name.attribute
    # Debe estar al inicio de línea, después de =, o dentro de comillas
    # Evitar capturar cuando está dentro de strings que ya tienen ${}
    pattern_direct = re.compile(
        r'(?:^|\s|=|\()([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_]+)*'
    )
    
    dependencies_found = 0
    dependencies_valid = 0
    
    for resource in parsed_resources:
        resource_name = resource.get('simple_name', '')
        if not resource_name:
            continue
        
        raw_block_text = resource.get('raw_block_text', '')
        if not raw_block_text:
            logger.debug(f"Recurso {resource_name} sin raw_block_text, saltando análisis de dependencias")
            continue
        
        # Buscar dependencias con ambos patrones
        matches_interpolation = pattern_interpolation.findall(raw_block_text)
        matches_direct = pattern_direct.findall(raw_block_text)
        
        # Combinar y eliminar duplicados
        # Filtrar matches_direct que no sean recursos (evitar variables comunes, funciones, etc.)
        # Solo considerar si el primer token parece un tipo de recurso (no var, data, local, etc.)
        all_matches = list(matches_interpolation)
        for match in matches_direct:
            # Excluir variables, locals, data sources comunes que no son recursos
            first_token = match.split('.')[0] if '.' in match else match
            if first_token not in ['var', 'local', 'module', 'terraform']:
                all_matches.append(match)
        
        # Convertir a set para eliminar duplicados
        unique_dependencies = set(all_matches)
        
        for dep_name in unique_dependencies:
            dependencies_found += 1
            
            # Verificar que la dependencia existe en nuestro mapa de recursos
            # Puede ser un recurso (aws_vpc.main), una variable (var.name), o un data (data.aws_ami.main)
            # Solo creamos aristas para recursos reales (que empiezan con aws_, google_, etc.)
            if dep_name in resource_map:
                dependencies_valid += 1
                # La dirección correcta: resource_name depende de dep_name
                # Por lo tanto: from = resource_name (el que depende), to = dep_name (el del que depende)
                # Esto significa: resource_name -> dep_name (resource_name apunta a su dependencia)
                edges.append({
                    "from": resource_name,  # El recurso que tiene la dependencia (el que apunta)
                    "to": dep_name,  # El recurso del que depende (al que apunta)
                    "source": resource_name,
                    "target": dep_name,
                })
                logger.debug(f"Arista encontrada: {resource_name} -> {dep_name}")
            else:
                # Es una variable, data source, o recurso que no está en nuestro grafo
                logger.debug(f"Dependencia '{dep_name}' no encontrada en resource_map (puede ser var, data, o recurso externo)")
    
    logger.info(f"Construidas {len(edges)} aristas desde {len(parsed_resources)} recursos "
                f"({dependencies_valid} dependencias válidas de {dependencies_found} encontradas)")
    
    return edges


