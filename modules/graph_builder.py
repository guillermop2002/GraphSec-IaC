"""
Construcción/enriquecimiento del grafo a partir del parser propio.

Este módulo proporciona:
1. Enriquecimiento de nodos existentes con metadatos del parser
2. Construcción de aristas (edges) mediante análisis de dependencias en Terraform
"""

from typing import Dict, Any, List
from collections import defaultdict
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
    
    # Crear un mapa de simple_name -> lista de nodos
    nodes_by_simple_name = defaultdict(list)
    for n in nodes:
        nodes_by_simple_name[n['simple_name']].append(n)
    
    for resource_node in nodes:
        resource_id = resource_node.get('id')  # ID ÚNICO (ej. 'aws_iam_role.this_0')
        resource_simple_name = resource_node.get('simple_name')
        if not resource_id:
            continue
        
        # Encontrar el 'parsed_resource' original
        # Esta es una búsqueda ineficiente, pero necesaria por el refactor
        parsed_resource = next((p for p in parsed_resources if p['file'] == resource_node['file'] and p['start_line'] == resource_node['start_line']), None)
        if not parsed_resource:
            continue
        
        raw_block_text = parsed_resource.get('raw_block_text', '')
        dependencies_found = set(pattern_direct.findall(raw_block_text))
        
        for dep_name in dependencies_found:
            if dep_name.startswith("var.") or dep_name.startswith("local.") or \
               dep_name.startswith("each.") or dep_name.startswith("count."):
                continue
            
            # Verificar si la dependencia es un recurso real
            dep_unique_ids = name_to_id_map.get(dep_name)
            if dep_unique_ids:
                # Éxito: Encontrada una dependencia
                for dep_id in dep_unique_ids:
                    edges.append({
                        "from": resource_id,
                        "to": dep_id,
                        "arrows": "to"
                    })
                    logger.debug(f"Arista encontrada: {resource_id} -> {dep_id}")
    
    return edges


