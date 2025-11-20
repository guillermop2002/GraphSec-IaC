"""
Parser de Terraform usando python-hcl2.
"""
from typing import List, Dict, Any
import os
import hcl2
import logging

logger = logging.getLogger(__name__)


def _iter_tf_files(root_dir: str) -> List[str]:
    """Itera sobre archivos .tf en un directorio."""
    files: List[str] = []
    root_dir_abs = os.path.abspath(os.path.normpath(root_dir))
    logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Explorando desde: {root_dir_abs}")
    
    # Verificar si existe terraform-aws-modules/ o .terraform/modules/
    terraform_modules_path = os.path.join(root_dir_abs, 'terraform-aws-modules')
    terraform_dot_modules_path = os.path.join(root_dir_abs, '.terraform', 'modules')
    
    if os.path.exists(terraform_modules_path):
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorio terraform-aws-modules/ EXISTE: {terraform_modules_path}")
        tf_count = sum(1 for root, _, filenames in os.walk(terraform_modules_path) for f in filenames if f.endswith('.tf'))
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Archivos .tf en terraform-aws-modules/: {tf_count}")
    else:
        logger.warning(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorio terraform-aws-modules/ NO EXISTE: {terraform_modules_path}")
    
    if os.path.exists(terraform_dot_modules_path):
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorio .terraform/modules/ EXISTE: {terraform_dot_modules_path}")
        tf_count = sum(1 for root, _, filenames in os.walk(terraform_dot_modules_path) for f in filenames if f.endswith('.tf'))
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Archivos .tf en .terraform/modules/: {tf_count}")
        # Listar algunos subdirectorios para ver la estructura
        try:
            subdirs = [d for d in os.listdir(terraform_dot_modules_path) if os.path.isdir(os.path.join(terraform_dot_modules_path, d))][:5]
            logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Subdirectorios en .terraform/modules/: {subdirs}")
        except Exception as e:
            logger.warning(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Error listando .terraform/modules/: {e}")
    else:
        logger.warning(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorio .terraform/modules/ NO EXISTE: {terraform_dot_modules_path}")
    
    directories_visited = []
    for dirpath, dirnames, filenames in os.walk(root_dir_abs):
        dirpath_abs = os.path.abspath(os.path.normpath(dirpath))
        directories_visited.append(dirpath_abs)
        tf_in_dir = [f for f in filenames if f.endswith('.tf')]
        if tf_in_dir:
            logger.debug(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorio '{dirpath_abs}' contiene {len(tf_in_dir)} archivos .tf")
        for fname in filenames:
            if fname.endswith('.tf'):
                files.append(os.path.join(dirpath, fname))
    
    logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Total directorios visitados: {len(directories_visited)}")
    logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Total archivos .tf encontrados: {len(files)}")
    
    # Verificar si se visitaron directorios de módulos
    modules_dirs = [d for d in directories_visited if 'terraform-aws-modules' in d]
    terraform_dirs = [d for d in directories_visited if '.terraform' in d]
    
    if modules_dirs:
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorios que contienen 'terraform-aws-modules': {len(modules_dirs)}")
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Ejemplos: {modules_dirs[:5]}")
    else:
        logger.warning(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Ningún directorio visitado contiene 'terraform-aws-modules'")
    
    if terraform_dirs:
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Directorios que contienen '.terraform': {len(terraform_dirs)}")
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Ejemplos: {terraform_dirs[:5]}")
    else:
        logger.warning(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Ningún directorio visitado contiene '.terraform'")
    
    # Verificar si hay archivos .tf en rutas de módulos
    files_in_modules = [f for f in files if 'terraform-aws-modules' in f or '.terraform' in f]
    if files_in_modules:
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Archivos .tf en rutas de módulos: {len(files_in_modules)}")
        logger.info(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Ejemplos: {files_in_modules[:5]}")
    else:
        logger.warning(f"[DIAGNÓSTICO PARSER] _iter_tf_files: Ningún archivo .tf encontrado en rutas de módulos")
    
    return files


def _extract_blocks_from_parsed(parsed: Dict[str, Any], block_type: str, content: str, file_path: str, file_path_abs: str) -> List[Dict[str, Any]]:
    """
    Extrae bloques de un tipo específico del AST parseado de hcl2.
    
    Soporta: 'resource', 'data', 'variable', 'module', 'locals'
    
    Args:
        parsed: AST parseado por hcl2.loads()
        block_type: Tipo de bloque a extraer
        content: Contenido completo del archivo (para fallback y extracción de texto)
        file_path: Ruta del archivo (para logging)
        file_path_abs: Ruta absoluta del archivo (para el objeto retornado)
    
    Returns:
        Lista de diccionarios con la estructura de bloques parseados
    """
    blocks: List[Dict[str, Any]] = []
    
    # LOGGING DETALLADO: Para archivos problemáticos
    is_problematic_file = 'terraform-aws-modules' in file_path_abs
    
    if block_type not in parsed:
        if is_problematic_file and block_type == 'resource':
            logger.debug(f"[DIAGNÓSTICO PARSER] Bloque '{block_type}' no encontrado en AST de {os.path.basename(file_path)}")
        return blocks
    
    if not isinstance(parsed[block_type], list):
        if is_problematic_file and block_type == 'resource':
            logger.warning(f"[DIAGNÓSTICO PARSER] Bloque '{block_type}' existe pero no es una lista en {os.path.basename(file_path)}")
            logger.warning(f"[DIAGNÓSTICO PARSER]   Tipo real: {type(parsed[block_type])}")
        return blocks
    
    # Estructuras diferentes según el tipo de bloque:
    # resource/data: {'resource': [{'resource_type': {'resource_name': {...}}}, ...]}
    # variable/module: {'variable': [{'variable_name': {...}}], ...]}
    # locals: {'locals': [{'local_key1': value1, 'local_key2': value2, ...}]}
    
    if block_type == 'locals':
        # Caso especial: locals es un solo bloque con múltiples claves
        for block_item in parsed[block_type]:
            if not isinstance(block_item, dict):
                continue
            
            # Obtener metadatos de línea del bloque locals completo
            start_line = block_item.get('__start_line__')
            end_line = block_item.get('__end_line__')
            
            # Extraer cada clave local como un "bloque" separado
            for local_key, local_value in block_item.items():
                if local_key.startswith('__'):  # Ignorar metadatos internos
                    continue
                
                # Para locals, usar el rango del bloque completo o buscar la línea específica
                if start_line and end_line:
                    # Intentar encontrar la línea específica de esta clave local
                    local_start_line, local_end_line = _find_block_lines_fallback(
                        content, 'locals', None, local_key
                    )
                    if not local_start_line:
                        # Fallback: usar el rango del bloque completo
                        local_start_line = start_line
                        local_end_line = end_line
                else:
                    local_start_line, local_end_line = _find_block_lines_fallback(
                        content, 'locals', None, local_key
                    )
                
                if local_start_line and local_end_line:
                    raw_block_text = _extract_block_text(content, local_start_line, local_end_line)
                    # En Terraform, locals se referencian como 'local.key'
                    simple_name = f'local.{local_key}'
                    
                    blocks.append({
                        'type': 'local',  # Tipo fijo para todas las claves locals
                        'name': local_key,
                        'simple_name': simple_name,
                        'block_type': 'locals',
                        'file': file_path_abs,
                        'start_line': local_start_line,
                        'end_line': local_end_line,
                        'raw_block_text': raw_block_text,
                    })
    
    elif block_type in ['variable', 'module']:
        # Caso: variable y module tienen estructura similar
        # {'variable': [{'variable_name': {...}}], ...]}
        for block_item in parsed[block_type]:
            if not isinstance(block_item, dict):
                continue
            
            for block_name, block_data in block_item.items():
                if not isinstance(block_data, dict):
                    continue
                
                # Extraer metadatos de línea del AST
                start_line = block_data.get('__start_line__')
                end_line = block_data.get('__end_line__')
                
                # Si no hay metadatos de línea, usar fallback
                if start_line is None or end_line is None:
                    start_line, end_line = _find_block_lines_fallback(
                        content, block_type, None, block_name
                    )
                
                if start_line and end_line:
                    raw_block_text = _extract_block_text(content, start_line, end_line)
                    
                    # Generar simple_name como se referencia en Terraform
                    if block_type == 'variable':
                        simple_name = f'var.{block_name}'  # En Terraform: var.my_var
                    elif block_type == 'module':
                        simple_name = f'module.{block_name}'  # En Terraform: module.my_module
                    else:
                        simple_name = f'{block_type}.{block_name}'
                    
                    blocks.append({
                        'type': block_type,  # 'variable' o 'module'
                        'name': block_name,
                        'simple_name': simple_name,
                        'block_type': block_type,
                        'file': file_path_abs,
                        'start_line': start_line,
                        'end_line': end_line,
                        'raw_block_text': raw_block_text,
                    })
                else:
                    logger.warning(
                        f"No se pudieron obtener líneas para {block_type} {block_name} en {file_path}"
                    )
    
    else:
        # Caso: resource y data (estructura con tipo intermedio)
        # {'resource': [{'resource_type': {'resource_name': {...}}}, ...]}
        blocks_in_ast = len(parsed[block_type])
        if is_problematic_file and block_type == 'resource' and blocks_in_ast > 0:
            logger.info(f"[DIAGNÓSTICO PARSER] Procesando {blocks_in_ast} bloques '{block_type}' en {os.path.basename(file_path)}")
        
        for block_item in parsed[block_type]:
            if not isinstance(block_item, dict):
                if is_problematic_file and block_type == 'resource':
                    logger.warning(f"[DIAGNÓSTICO PARSER] Bloque item no es dict: {type(block_item)}")
                continue
                
            for block_resource_type, block_instances in block_item.items():
                if not isinstance(block_instances, dict):
                    if is_problematic_file and block_type == 'resource':
                        logger.warning(f"[DIAGNÓSTICO PARSER] Instancias de {block_resource_type} no es dict: {type(block_instances)}")
                    continue
                    
                for block_name, block_data in block_instances.items():
                    # Extraer metadatos de línea del AST
                    start_line = block_data.get('__start_line__')
                    end_line = block_data.get('__end_line__')
                    
                    # LOGGING DETALLADO: Para recursos problemáticos
                    if is_problematic_file and block_type == 'resource':
                        logger.debug(f"[DIAGNÓSTICO PARSER]   Procesando {block_type} {block_resource_type}.{block_name}")
                        logger.debug(f"[DIAGNÓSTICO PARSER]     Metadatos línea: start={start_line}, end={end_line}")
                    
                    # Si no hay metadatos de línea, usar fallback
                    if start_line is None or end_line is None:
                        if is_problematic_file and block_type == 'resource':
                            logger.warning(f"[DIAGNÓSTICO PARSER]     Sin metadatos de línea, usando fallback para {block_resource_type}.{block_name}")
                        start_line, end_line = _find_block_lines_fallback(
                            content, block_type, block_resource_type, block_name
                        )
                        if is_problematic_file and block_type == 'resource':
                            logger.debug(f"[DIAGNÓSTICO PARSER]     Fallback resultó: start={start_line}, end={end_line}")
                    
                    if start_line and end_line:
                        # Extraer el bloque de texto crudo
                        raw_block_text = _extract_block_text(content, start_line, end_line)
                        
                        # Generar simple_name con prefijo apropiado
                        # Para resource: 'aws_vpc.main'
                        # Para data: 'data.aws_iam_policy_document.my_policy'
                        if block_type == 'data':
                            simple_name = f'data.{block_resource_type}.{block_name}'
                        else:
                            simple_name = f'{block_resource_type}.{block_name}'
                        
                        blocks.append({
                            'type': block_resource_type,
                            'name': block_name,
                            'simple_name': simple_name,
                            'block_type': block_type,  # 'resource' o 'data'
                            'file': file_path_abs,
                            'start_line': start_line,
                            'end_line': end_line,
                            'raw_block_text': raw_block_text,
                        })
                        
                        if is_problematic_file and block_type == 'resource':
                            logger.info(f"[DIAGNÓSTICO PARSER]     Extraído: {simple_name} (líneas {start_line}-{end_line})")
                    else:
                        logger.warning(
                            f"No se pudieron obtener líneas para {block_type} {block_resource_type}.{block_name} en {file_path}"
                        )
                        if is_problematic_file and block_type == 'resource':
                            logger.warning(f"[DIAGNÓSTICO PARSER]     NO SE PUDO EXTRAER: {block_resource_type}.{block_name}")
        
        if is_problematic_file and block_type == 'resource':
            logger.info(f"[DIAGNÓSTICO PARSER] Total extraído: {len(blocks)} bloques '{block_type}' de {blocks_in_ast} encontrados en AST")
    
    return blocks


def parse_terraform(directory: str) -> List[Dict[str, Any]]:
    """Parsea archivos Terraform y extrae bloques con metadatos."""
    resources: List[Dict[str, Any]] = []
    tf_files = _iter_tf_files(directory)
    
    # Asegurar que directory es una ruta absoluta
    directory_abs = os.path.abspath(os.path.normpath(directory))
    
    # Tipos de bloques a parsear
    # Fase 4: Añadir soporte para variable, locals, module
    BLOCK_TYPES = ['resource', 'data', 'variable', 'locals', 'module']
    
    # LOGGING: Contar archivos problemáticos antes de procesar
    # Usar rutas absolutas para la detección porque las rutas relativas pueden no contener el path completo
    problematic_files = [f for f in tf_files if 'terraform-aws-modules' in os.path.abspath(os.path.normpath(f))]
    logger.info(f"[DIAGNÓSTICO PARSER] Total archivos .tf encontrados: {len(tf_files)}")
    logger.info(f"[DIAGNÓSTICO PARSER] Archivos problemáticos detectados: {len(problematic_files)}")
    if problematic_files:
        logger.info(f"[DIAGNÓSTICO PARSER] Primeros archivos problemáticos: {[os.path.basename(f) for f in problematic_files[:5]]}")
        logger.info(f"[DIAGNÓSTICO PARSER] Ejemplo ruta completa: {os.path.abspath(os.path.normpath(problematic_files[0])) if problematic_files else 'N/A'}")
    else:
        logger.warning(f"[DIAGNÓSTICO PARSER] NO se detectaron archivos problemáticos.")
        logger.warning(f"[DIAGNÓSTICO PARSER] Ejemplo de nombres de archivo: {[os.path.basename(f) for f in tf_files[:5]]}")
        logger.warning(f"[DIAGNÓSTICO PARSER] Ejemplo de rutas relativas: {tf_files[:5]}")
        logger.warning(f"[DIAGNÓSTICO PARSER] Ejemplo de rutas absolutas: {[os.path.abspath(os.path.normpath(f)) for f in tf_files[:5]]}")
        # Buscar manualmente archivos que deberían contener 'terraform-aws-modules' usando rutas absolutas
        potential_problematic = [f for f in tf_files if 'terraform-aws-modules' in os.path.abspath(os.path.normpath(f))]
        if potential_problematic:
            logger.warning(f"[DIAGNÓSTICO PARSER] Archivos potencialmente problemáticos encontrados (absolutas): {[os.path.abspath(os.path.normpath(f)) for f in potential_problematic[:5]]}")
    
    for file_path in tf_files:
        try:
            # ESTRATEGIA CAMBIADA: Guardar ruta absoluta en lugar de relativa
            # Esto permite comparación directa en el motor de correlación
            file_path_abs = os.path.abspath(os.path.normpath(file_path))
            
            # LOGGING DETALLADO: Para archivos problemáticos (ANTES de parsear)
            is_problematic_file = 'terraform-aws-modules' in file_path_abs
            if is_problematic_file:
                logger.info(f"[DIAGNÓSTICO PARSER] ════════════════════════════════════════════════════════════")
                logger.info(f"[DIAGNÓSTICO PARSER] Archivo problemático detectado: {file_path_abs}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parsear con hcl2
            try:
                parsed = hcl2.loads(content)
            except Exception as e:
                if is_problematic_file:
                    logger.error(f"[DIAGNÓSTICO PARSER] Error al parsear archivo problemático: {e}")
                logger.warning(f"Error al parsear {file_path} con hcl2: {e}")
                continue
            
            # Logging detallado para archivos problemáticos (después de parsear)
            if is_problematic_file:
                logger.info(f"[DIAGNÓSTICO PARSER] Claves en el AST parseado: {list(parsed.keys())}")
                
                # Contar bloques por tipo en el AST
                for key in parsed.keys():
                    if isinstance(parsed[key], list):
                        logger.info(f"[DIAGNÓSTICO PARSER]   {key}: {len(parsed[key])} bloques encontrados en AST")
                        # Para resource, mostrar estructura de ejemplo
                        if key == 'resource' and parsed[key]:
                            first_resource = parsed[key][0]
                            if isinstance(first_resource, dict):
                                logger.info(f"[DIAGNÓSTICO PARSER]     Ejemplo estructura resource: {list(first_resource.keys())[:3]}")
                    elif isinstance(parsed[key], dict):
                        logger.info(f"[DIAGNÓSTICO PARSER]   {key}: {len(parsed[key])} elementos")
            
            # Extraer bloques de todos los tipos soportados
            blocks_found_in_file = 0
            for block_type in BLOCK_TYPES:
                blocks = _extract_blocks_from_parsed(parsed, block_type, content, file_path, file_path_abs)
                blocks_found_in_file += len(blocks)
                resources.extend(blocks)
            
            # Logging detallado si un archivo problemático no produjo bloques
            if is_problematic_file:
                logger.info(f"[DIAGNÓSTICO PARSER] Bloques extraídos de este archivo: {blocks_found_in_file}")
                if blocks_found_in_file == 0:
                    logger.warning(f"[DIAGNÓSTICO PARSER] ARCHIVO PROBLEMÁTICO SIN BLOQUES: {file_path_abs}")
                    logger.warning(f"[DIAGNÓSTICO PARSER]   El AST tiene {len(parsed)} claves pero no se extrajeron bloques")
                    logger.warning(f"[DIAGNÓSTICO PARSER]   Esto puede indicar un problema en la lógica de extracción")
                logger.info(f"[DIAGNÓSTICO PARSER] ════════════════════════════════════════════════════════════")
                                        
        except FileNotFoundError:
            logger.warning(f"Archivo no encontrado: {file_path}")
            continue
        except Exception as e:
            logger.error(f"Error inesperado al procesar {file_path}: {e}")
            continue
    
    # Contar por tipo de bloque
    resource_count = sum(1 for r in resources if r.get('block_type') == 'resource')
    data_count = sum(1 for r in resources if r.get('block_type') == 'data')
    variable_count = sum(1 for r in resources if r.get('block_type') == 'variable')
    locals_count = sum(1 for r in resources if r.get('block_type') == 'locals')
    module_count = sum(1 for r in resources if r.get('block_type') == 'module')
    
    logger.info(
        f"Parseados {len(resources)} bloques desde {len(tf_files)} archivos usando hcl2 "
        f"(resources: {resource_count}, data: {data_count}, variable: {variable_count}, "
        f"locals: {locals_count}, module: {module_count})"
    )
    return resources


def _extract_block_text(content: str, start_line: int, end_line: int) -> str:
    """Extrae texto del bloque entre líneas."""
    lines = content.split('\n')
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    return '\n'.join(lines[start_idx:end_idx])


def _find_block_lines_fallback(content: str, block_type: str, block_resource_type: str | None, block_name: str) -> tuple[int | None, int | None]:
    """Fallback para encontrar líneas si hcl2 no da metadatos."""
    lines = content.split('\n')
    
    # Construir el patrón según el tipo de bloque
    if block_type in ['resource', 'data']:
        # resource "aws_vpc" "main" { o data "aws_iam_policy_document" "my_policy" {
        pattern = f'{block_type} "{block_resource_type}" "{block_name}"'
    elif block_type in ['variable', 'module']:
        # variable "my_var" { o module "my_module" {
        pattern = f'{block_type} "{block_name}"'
    elif block_type == 'locals':
        # Para locals, buscar la clave dentro del bloque locals
        # Patrón: locals { ... my_local = ...
        pattern = f'{block_name}\\s*='
        # Buscar primero el bloque locals
        locals_start = None
        for i, line in enumerate(lines, 1):
            if 'locals' in line and '{' in line:
                locals_start = i
                break
        
        if locals_start:
            # Buscar la clave específica dentro del bloque locals
            for i in range(locals_start, len(lines)):
                if pattern in lines[i]:
                    start_line = i
                    # Para locals, el bloque completo termina cuando se cierra el bloque locals
                    # Buscar el cierre del bloque locals
                    brace_depth = 0
                    j = locals_start - 1
                    while j < len(lines):
                        brace_depth += lines[j].count('{')
                        brace_depth -= lines[j].count('}')
                        if brace_depth == 0 and j >= i:
                            end_line = j + 1
                            return start_line, end_line
                        j += 1
                    return start_line, len(lines)
        return None, None
    else:
        return None, None
    
    # Buscar el patrón en el contenido
    for i, line in enumerate(lines, 1):
        if pattern in line and '{' in line:
            start_line = i
            # Calcular end_line por balanceo de llaves
            brace_depth = 0
            j = i - 1  # Convertir a índice 0-based
            
            while j < len(lines):
                brace_depth += lines[j].count('{')
                brace_depth -= lines[j].count('}')
                
                if brace_depth == 0:
                    end_line = j + 1  # Convertir de vuelta a 1-based
                    return start_line, end_line
                j += 1
            
            # Si no se encuentra el cierre, devolver la línea actual
            return start_line, len(lines)
    
    return None, None

