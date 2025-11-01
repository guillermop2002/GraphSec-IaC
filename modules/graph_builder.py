"""
Construcción/enriquecimiento del grafo a partir del parser propio.

Objetivo Fase 2: enriquecer nodos existentes (de blast-radius) con metadatos
de archivo y rango de líneas obtenidos del parser, sin tocar edges.
"""

from typing import Dict, Any, List


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



