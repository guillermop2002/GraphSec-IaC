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


def parse_terraform(directory: str) -> List[Dict[str, Any]]:
    """
    Parsea archivos Terraform usando python-hcl2 y extrae recursos con metadatos de línea.
    
    Las rutas de archivo se normalizan como rutas relativas desde el directorio raíz
    para facilitar la correlación con hallazgos de seguridad.
    
    Args:
        directory: Directorio raíz donde buscar archivos .tf (ruta absoluta)
        
    Returns:
        Lista de diccionarios con la estructura:
        {
            'type': 'aws_s3_bucket',
            'name': 'my_bucket',
            'simple_name': 'aws_s3_bucket.my_bucket',
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
            
            # Extraer recursos del AST parseado
            # La estructura de hcl2 es: {'resource': [{'resource_type': {'resource_name': {...}}}, ...]}
            if 'resource' in parsed and isinstance(parsed['resource'], list):
                for resource_item in parsed['resource']:
                    if isinstance(resource_item, dict):
                        for resource_type, resource_instances in resource_item.items():
                            if isinstance(resource_instances, dict):
                                for resource_name, resource_data in resource_instances.items():
                                    # Extraer metadatos de línea
                                    start_line = resource_data.get('__start_line__')
                                    end_line = resource_data.get('__end_line__')
                                    
                                    # Si no hay metadatos de línea, intentar buscar en el contenido del archivo
                                    if start_line is None or end_line is None:
                                        # Fallback: buscar manualmente en el archivo
                                        start_line, end_line = _find_resource_lines_fallback(
                                            content, resource_type, resource_name
                                        )
                                    
                                    if start_line and end_line:
                                        # Extraer el bloque de texto crudo del recurso
                                        raw_block_text = _extract_resource_block_text(content, start_line, end_line)
                                        
                                        resources.append({
                                            'type': resource_type,
                                            'name': resource_name,
                                            'simple_name': f'{resource_type}.{resource_name}',
                                            'file': file_path_abs,  # Ruta absoluta para comparación directa
                                            'start_line': start_line,
                                            'end_line': end_line,
                                            'raw_block_text': raw_block_text,  # Texto crudo para análisis de dependencias
                                        })
                                    else:
                                        logger.warning(
                                            f"No se pudieron obtener líneas para {resource_type}.{resource_name} en {file_path}"
                                        )
                                        
        except FileNotFoundError:
            logger.warning(f"Archivo no encontrado: {file_path}")
            continue
        except Exception as e:
            logger.error(f"Error inesperado al procesar {file_path}: {e}")
            continue
    
    logger.info(f"Parseados {len(resources)} recursos desde {len(tf_files)} archivos usando hcl2")
    return resources


def _extract_resource_block_text(content: str, start_line: int, end_line: int) -> str:
    """
    Extrae el bloque de texto crudo de un recurso entre start_line y end_line.
    
    Args:
        content: Contenido completo del archivo
        start_line: Línea de inicio del recurso (1-based)
        end_line: Línea de fin del recurso (1-based)
    
    Returns:
        String con el texto del bloque del recurso
    """
    lines = content.split('\n')
    # Convertir a índices 0-based
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    return '\n'.join(lines[start_idx:end_idx])


def _find_resource_lines_fallback(content: str, resource_type: str, resource_name: str) -> tuple[int | None, int | None]:
    """
    Fallback para encontrar líneas si hcl2 no proporciona metadatos.
    Busca el patrón 'resource "type" "name" {' y calcula el rango por balanceo.
    """
    lines = content.split('\n')
    pattern = f'resource "{resource_type}" "{resource_name}"'
    
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

