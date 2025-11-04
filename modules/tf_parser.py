"""
Parser robusto de Terraform usando python-hcl2.

Esta implementación usa python-hcl2, un parser oficial de HCL que maneja
correctamente todos los casos edge (comentarios, strings, bloques dinámicos, etc.)
y proporciona metadatos de línea precisos.
"""

from typing import List, Dict, Any
import os
import hcl2
import logging

logger = logging.getLogger(__name__)


def _iter_tf_files(root_dir: str) -> List[str]:
    """Itera sobre todos los archivos .tf en un directorio."""
    files: List[str] = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.endswith('.tf'):
                files.append(os.path.join(dirpath, fname))
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
    
    if block_type not in parsed or not isinstance(parsed[block_type], list):
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
        for block_item in parsed[block_type]:
            if not isinstance(block_item, dict):
                continue
                
            for block_resource_type, block_instances in block_item.items():
                if not isinstance(block_instances, dict):
                    continue
                    
                for block_name, block_data in block_instances.items():
                    # Extraer metadatos de línea del AST
                    start_line = block_data.get('__start_line__')
                    end_line = block_data.get('__end_line__')
                    
                    # Si no hay metadatos de línea, usar fallback
                    if start_line is None or end_line is None:
                        start_line, end_line = _find_block_lines_fallback(
                            content, block_type, block_resource_type, block_name
                        )
                    
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
                    else:
                        logger.warning(
                            f"No se pudieron obtener líneas para {block_type} {block_resource_type}.{block_name} en {file_path}"
                        )
    
    return blocks


def parse_terraform(directory: str) -> List[Dict[str, Any]]:
    """
    Parsea archivos Terraform usando python-hcl2 y extrae múltiples tipos de bloques con metadatos de línea.
    
    Soporta: 'resource', 'data', 'variable', 'locals', 'module'
    
    Las rutas de archivo se normalizan como rutas absolutas
    para facilitar la correlación con hallazgos de seguridad.
    
    Args:
        directory: Directorio raíz donde buscar archivos .tf (ruta absoluta)
        
    Returns:
        Lista de diccionarios con la estructura:
        {
            'type': 'aws_s3_bucket' o 'variable' o 'local' o 'module',  # Tipo del bloque
            'name': 'my_bucket' o 'my_var' o 'my_local' o 'my_module',  # Nombre del bloque
            'simple_name': 'aws_s3_bucket.my_bucket' (resource),
                          'data.aws_iam_policy_document.my_policy' (data),
                          'var.my_var' (variable),
                          'local.my_local' (locals),
                          'module.my_module' (module),
            'block_type': 'resource' | 'data' | 'variable' | 'locals' | 'module',  # Tipo de bloque Terraform
            'file': 'C:\\...\\main.tf',  # Ruta absoluta
            'start_line': 13,
            'end_line': 16,
            'raw_block_text': 'resource "aws_s3_bucket" "my_bucket" {...}'  # Texto crudo del bloque
        }
    """
    resources: List[Dict[str, Any]] = []
    tf_files = _iter_tf_files(directory)
    
    # Asegurar que directory es una ruta absoluta
    directory_abs = os.path.abspath(os.path.normpath(directory))
    
    # Tipos de bloques a parsear
    # Fase 4: Añadir soporte para variable, locals, module
    BLOCK_TYPES = ['resource', 'data', 'variable', 'locals', 'module']
    
    for file_path in tf_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parsear con hcl2
            try:
                parsed = hcl2.loads(content)
            except Exception as e:
                logger.warning(f"Error al parsear {file_path} con hcl2: {e}")
                continue
            
            # ESTRATEGIA CAMBIADA: Guardar ruta absoluta en lugar de relativa
            # Esto permite comparación directa en el motor de correlación
            file_path_abs = os.path.abspath(os.path.normpath(file_path))
            
            # Extraer bloques de todos los tipos soportados
            for block_type in BLOCK_TYPES:
                blocks = _extract_blocks_from_parsed(parsed, block_type, content, file_path, file_path_abs)
                resources.extend(blocks)
                                        
        except FileNotFoundError:
            logger.warning(f"Archivo no encontrado: {file_path}")
            continue
        except Exception as e:
            logger.error(f"Error inesperado al procesar {file_path}: {e}")
            continue
    
    # Actualizar logging para mostrar distribución por tipo de bloque
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
    """
    Extrae el bloque de texto crudo entre start_line y end_line.
    
    Args:
        content: Contenido completo del archivo
        start_line: Línea de inicio del bloque (1-based)
        end_line: Línea de fin del bloque (1-based)
    
    Returns:
        String con el texto del bloque
    """
    lines = content.split('\n')
    # Convertir a índices 0-based
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    return '\n'.join(lines[start_idx:end_idx])


def _find_block_lines_fallback(content: str, block_type: str, block_resource_type: str | None, block_name: str) -> tuple[int | None, int | None]:
    """
    Fallback para encontrar líneas si hcl2 no proporciona metadatos.
    Busca el patrón del bloque según su tipo y calcula el rango por balanceo.
    
    Args:
        content: Contenido completo del archivo
        block_type: Tipo de bloque ('resource', 'data', 'variable', 'module', 'locals')
        block_resource_type: Tipo del recurso/data (ej: 'aws_vpc', 'aws_iam_policy_document')
                           None para variable, module, locals
        block_name: Nombre del bloque (ej: 'main', 'my_policy', 'my_var', 'my_module', 'my_local')
    
    Returns:
        Tupla (start_line, end_line) en formato 1-based, o (None, None) si no se encuentra
    """
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

