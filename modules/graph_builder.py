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


def build_edges(parsed_resources: List[Dict[str, Any]], name_to_id_map: Dict[str, list], project_root: str, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Construye las aristas (edges) del grafo analizando dependencias."""
    
    edges = []
    pattern_direct = re.compile(r'([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_]+)*')
    
    # Crear un mapa de (file, start_line) -> unique_id
    # Esto nos permite encontrar el ID único exacto de un recurso
    node_lookup = {(n['file'], n['start_line']): n['id'] for n in nodes}
    
    for resource in parsed_resources:
        # Encontrar el ID 'from' (el ID único de este recurso)
        resource_id = node_lookup.get((resource.get('file'), resource.get('start_line')))
        if not resource_id:
            continue  # Este recurso no tiene un nodo (raro, pero posible)
        
        raw_block_text = resource.get('raw_block_text', '')
        dependencies_found = set(pattern_direct.findall(raw_block_text))
        
        for dep_name in dependencies_found:
            # Filtrar dependencias no deseadas
            if dep_name.startswith("var.") or dep_name.startswith("local.") or \
               dep_name.startswith("each.") or dep_name.startswith("count."):
                continue
            
            # Verificar si la dependencia es un recurso real
            dep_unique_ids = name_to_id_map.get(dep_name)
            if dep_unique_ids:
                # Éxito: Encontrada una dependencia
                # Crear aristas a TODOS los IDs únicos para ese nombre
                for dep_id in dep_unique_ids:
                    edges.append({
                        "from": resource_id,  # El ID único del recurso que depende
                        "to": dep_id,  # El ID único del recurso del que depende
                        "arrows": "to"
                    })
                    logger.debug(f"Arista encontrada: {resource_id} -> {dep_id}")
    
    return edges


