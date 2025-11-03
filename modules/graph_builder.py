"""
Construcción/enriquecimiento del grafo a partir del parser propio.

Este módulo proporciona:
1. Enriquecimiento de nodos existentes con metadatos del parser
2. Construcción de aristas (edges) mediante análisis de dependencias en Terraform
"""

from typing import Dict, Any, List
import os
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


def build_edges(parsed_resources: List[Dict[str, Any]], name_to_id_map: Dict[str, list] = None, project_root: str = None) -> List[Dict[str, Any]]:
    """
    Construye las aristas (edges) del grafo analizando dependencias en Terraform.
    
    Usa expresiones regulares para encontrar interpolaciones de Terraform (${resource.type.name})
    y construye las relaciones de dependencia entre recursos.
    
    Args:
        parsed_resources: Lista de recursos parseados con metadatos y raw_block_text
        name_to_id_map: Diccionario que mapea simple_name -> [lista de unique_ids]. 
                        Si se proporciona, se usarán los unique_ids en las aristas.
                        Si no se proporciona, se usarán simple_name (comportamiento legacy).
        project_root: Directorio raíz del proyecto (opcional, para calcular rutas relativas)
    
    Returns:
        Lista de diccionarios representando aristas: [{"from": "unique_id1", "to": "unique_id2"}, ...]
    """
    if not parsed_resources:
        logger.warning("Lista de recursos vacía, no se pueden construir aristas")
        return []
    
    # Crear mapa de recursos para búsqueda rápida
    resource_map = {r.get('simple_name'): r for r in parsed_resources}
    
    # Calcular project_root si no se proporciona (usar el directorio común de los archivos)
    if not project_root and parsed_resources:
        first_file = parsed_resources[0].get('file', '')
        if first_file:
            # Intentar encontrar el directorio común
            project_root = os.path.dirname(os.path.abspath(first_file))
    
    # Función helper para obtener el ID correcto (unique_id o simple_name)
    def get_id_for_name(name: str, resource_file: str) -> str:
        if name_to_id_map and name in name_to_id_map:
            # Si hay múltiples IDs para el mismo nombre, usar el que corresponda al mismo archivo
            ids = name_to_id_map[name]
            if len(ids) == 1:
                return ids[0]
            
            # Si hay múltiples, intentar encontrar el que corresponda al mismo archivo
            # Comparar usando la ruta relativa completa
            if project_root and resource_file:
                try:
                    rel_path = os.path.relpath(os.path.abspath(resource_file), os.path.abspath(project_root)).replace("\\", "/")
                    target_suffix = f"_{rel_path}"
                    for uid in ids:
                        if uid.endswith(target_suffix):
                            return uid
                except ValueError:
                    # Fallback si las rutas están en discos diferentes
                    pass
            
            # Fallback: usar el nombre del archivo
            file_name = os.path.basename(resource_file)
            for uid in ids:
                if uid.endswith(f"_{file_name}"):
                    return uid
            
            # Si no se encuentra coincidencia, usar el primero
            return ids[0]
        return name
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
        resource_file = resource.get('file', '')
        if not resource_name:
            continue
        
        # Obtener el ID único para este recurso
        resource_id = get_id_for_name(resource_name, resource_file)
        
        raw_block_text = resource.get('raw_block_text', '')
        if not raw_block_text:
            logger.debug(f"Recurso {resource_name} sin raw_block_text, saltando análisis de dependencias")
            continue
        
        # Buscar dependencias con ambos patrones
        matches_interpolation = pattern_interpolation.findall(raw_block_text)
        matches_direct = pattern_direct.findall(raw_block_text)
        
        # Combinar y eliminar duplicados
        # Incluir todos los matches (interpolación y directos)
        all_matches = list(matches_interpolation)
        all_matches.extend(matches_direct)
        
        # Convertir a set para eliminar duplicados
        unique_dependencies = set(all_matches)
        
        for dep_name in unique_dependencies:
            dependencies_found += 1
            
            # Filtrar dependencias (ignorar 'var.', 'local.', 'each.', 'count.')
            if dep_name.startswith("var.") or \
               dep_name.startswith("local.") or \
               dep_name.startswith("each.") or \
               dep_name.startswith("count."):
                continue
            
            # Verificar que la dependencia existe en nuestro mapa de recursos
            # Puede ser un recurso (aws_vpc.main), un módulo (module.my_module), o un data (data.aws_ami.main)
            if dep_name in resource_map:
                dependencies_valid += 1
                dep_resource = resource_map[dep_name]
                # La dependencia puede tener múltiples instancias (mismo nombre en diferentes archivos)
                # Crear aristas a TODOS los IDs únicos para ese nombre
                dep_file = dep_resource.get('file', '')
                dep_id = get_id_for_name(dep_name, dep_file)
                
                # Si hay múltiples IDs, crear aristas a todos ellos
                if name_to_id_map and dep_name in name_to_id_map:
                    for dep_unique_id in name_to_id_map[dep_name]:
                        edges.append({
                            "from": resource_id,  # El recurso que tiene la dependencia (el que apunta) - usando unique_id
                            "to": dep_unique_id,  # El recurso del que depende (al que apunta) - usando unique_id
                            "source": resource_id,
                            "target": dep_unique_id,
                        })
                        logger.debug(f"Arista encontrada: {resource_id} -> {dep_unique_id}")
                else:
                    # Fallback: usar el ID calculado
                    edges.append({
                        "from": resource_id,
                        "to": dep_id,
                        "source": resource_id,
                        "target": dep_id,
                    })
                    logger.debug(f"Arista encontrada: {resource_id} -> {dep_id}")
            else:
                # Es una variable, data source, o recurso que no está en nuestro grafo
                logger.debug(f"Dependencia '{dep_name}' no encontrada en resource_map (puede ser var, data, o recurso externo)")
    
    logger.info(f"Construidas {len(edges)} aristas desde {len(parsed_resources)} recursos "
                f"({dependencies_valid} dependencias válidas de {dependencies_found} encontradas)")
    
    return edges


