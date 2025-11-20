"""
Construcción del grafo y análisis de dependencias en Terraform.
"""

from typing import Dict, Any, List
import re
import logging

logger = logging.getLogger(__name__)


def enrich_graph_nodes_with_parsed(graph_data: Dict[str, Any], parsed_resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Enriquece nodos del grafo con metadatos de archivo y línea."""
    if not graph_data:
        return graph_data

    nodes: List[Dict[str, Any]] = graph_data.get("nodes", [])
    parsed_index = {r.get("simple_name"): r for r in parsed_resources}

    for node in nodes:
        sname = node.get("simple_name") or node.get("id") or node.get("label")
        if not sname:
            continue
        match = parsed_index.get(sname)
        if not match:
            continue
        
        node["file"] = match.get("file")
        node["line"] = match.get("start_line")
        node["start_line"] = match.get("start_line")
        node["end_line"] = match.get("end_line")

    return graph_data


def build_edges(parsed_resources: List[Dict[str, Any]], name_to_id_map: Dict[str, list], project_root: str, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Construye las aristas (edges) del grafo analizando dependencias.
    
    Soporta dependencias hacia bloques 'resource' y 'data':
    - resource: aws_vpc.main
    - data: data.aws_iam_policy_document.my_policy
    """
    
    edges = []
    edges_set = set()  # Para evitar duplicados
    # Regex mejorada para capturar dependencias hacia resource, data, y module blocks
    # Captura:
    # - aws_vpc.main (resource)
    # - data.aws_iam_policy_document.my_policy (data)
    # - module.my_module (module)
    # El (?:data\.|module\.)? hace que los prefijos 'data.' y 'module.' sean opcionales
    pattern_direct = re.compile(r'((?:data\.|module\.)?[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_]+)*')
    
    # Crear un mapa de (file, start_line) -> unique_id
    node_lookup = {(n['file'], n['start_line']): n['id'] for n in nodes}
    
    stats = {
        "resources_processed": 0,
        "resources_without_id": 0,
        "dependencies_found": 0,
        "dependencies_filtered": 0,
        "dependencies_matched": 0,
        "dependencies_data_matched": 0,  # Contar dependencias hacia bloques data
        "dependencies_module_matched": 0,  # Contar dependencias hacia módulos
        "dependencies_not_found": 0,
        "edges_added": 0,
        "edges_duplicates": 0
    }
    
    # Log de diagnóstico: mostrar cuántos recursos hay en name_to_id_map
    total_resources_in_map = sum(len(ids) for ids in name_to_id_map.values())
    logger.info(f"[DIAGNÓSTICO] build_edges: name_to_id_map contiene {len(name_to_id_map)} nombres únicos, {total_resources_in_map} recursos totales")
    
    dependencies_not_found_samples = []  # Para logging de ejemplos
    
    for resource in parsed_resources:
        # Encontrar el ID 'from' (el ID único de este recurso)
        resource_id = node_lookup.get((resource.get('file'), resource.get('start_line')))
        if not resource_id:
            stats["resources_without_id"] += 1
            continue
        
        stats["resources_processed"] += 1
        raw_block_text = resource.get('raw_block_text', '')
        dependencies_found = set(pattern_direct.findall(raw_block_text))
        stats["dependencies_found"] += len(dependencies_found)
        
        for dep_name in dependencies_found:
            # Filtro: Ignorar var y local (aunque ahora los parseamos, no creamos aristas hacia ellos
            # porque son referencias indirectas, no dependencias de recursos)
            # NOTA: Los módulos (module.*) SÍ se incluyen como dependencias
            if dep_name.startswith("var.") or dep_name.startswith("local."):
                stats["dependencies_filtered"] += 1
                continue
            
            # Para módulos, normalizar dependencias como module.my_module.output a module.my_module
            # porque el nodo en name_to_id_map es module.my_module, no module.my_module.output
            # NOTA: Maneja también casos de módulos anidados (module.mi_app.module.mi_vpc.output)
            # aunque en Terraform los módulos anidados están en archivos diferentes,
            # la normalización debe ser robusta para cualquier caso
            if dep_name.startswith("module."):
                # Extraer el nombre base del módulo
                # Caso simple: module.my_module.output -> module.my_module
                # Caso anidado: module.mi_app.module.mi_vpc.output -> module.mi_app.module.mi_vpc
                parts = dep_name.split('.')
                if len(parts) >= 2:
                    # Buscar el patrón module.nombre.module.nombre... hasta el último módulo
                    # pero limitar a 2 niveles para evitar falsos positivos
                    # En Terraform real, los módulos anidados están en archivos diferentes,
                    # pero normalizamos hasta el último módulo completo para ser robustos
                    if len(parts) >= 4 and parts[2] == 'module':
                        # Caso anidado: module.nombre1.module.nombre2
                        dep_name = '.'.join(parts[:4])  # module.nombre1.module.nombre2
                    else:
                        # Caso simple: module.nombre
                        dep_name = f"{parts[0]}.{parts[1]}"  # module.nombre
            
            dep_unique_ids = name_to_id_map.get(dep_name)
            if dep_unique_ids:
                stats["dependencies_matched"] += len(dep_unique_ids)
                # Contar dependencias hacia bloques data y módulos (para logging)
                if dep_name.startswith("data."):
                    stats["dependencies_data_matched"] += len(dep_unique_ids)
                elif dep_name.startswith("module."):
                    stats["dependencies_module_matched"] += len(dep_unique_ids)
                for dep_id in dep_unique_ids:
                    edge_key = (resource_id, dep_id)
                    if edge_key not in edges_set:
                        edges_set.add(edge_key)
                        edges.append({
                            "from": resource_id,
                            "to": dep_id,
                            "arrows": "to"
                        })
                        stats["edges_added"] += 1
                        logger.debug(f"Arista encontrada: {resource_id} -> {dep_id} (dependencia: {dep_name})")
                    else:
                        stats["edges_duplicates"] += 1
            else:
                stats["dependencies_not_found"] += 1
                if len(dependencies_not_found_samples) < 10:
                    dependencies_not_found_samples.append(dep_name)
    
    logger.info(f"[DIAGNÓSTICO] build_edges: {stats['resources_processed']} bloques procesados, {stats['resources_without_id']} sin ID")
    logger.info(
        f"[DIAGNÓSTICO] build_edges: {stats['dependencies_found']} dependencias encontradas, "
        f"{stats['dependencies_filtered']} filtradas (var/local), "
        f"{stats['dependencies_matched']} coincidieron "
        f"(data: {stats['dependencies_data_matched']}, module: {stats['dependencies_module_matched']}), "
        f"{stats['dependencies_not_found']} NO encontradas en name_to_id_map"
    )
    if dependencies_not_found_samples:
        logger.info(f"[DIAGNÓSTICO] build_edges: Ejemplos de dependencias NO encontradas: {dependencies_not_found_samples[:10]}")
    logger.info(f"[DIAGNÓSTICO] build_edges: {stats['edges_added']} aristas añadidas, {stats['edges_duplicates']} duplicadas ignoradas")
    
    return edges


