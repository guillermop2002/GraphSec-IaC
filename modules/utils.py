"""
Utilidades generales para GraphSec-IaC.
"""

import hashlib
import os
from typing import List


def generate_hash_for_files(file_paths: List[str]) -> str:
    """
    Genera un hash SHA256 del contenido de uno o más archivos.
    
    Útil para detectar cambios en archivos y invalidar caché.
    
    Args:
        file_paths: Lista de rutas a archivos para incluir en el hash
    
    Returns:
        String hexadecimal del hash SHA256
    """
    sha256 = hashlib.sha256()
    
    # Ordenar las rutas para garantizar consistencia
    sorted_paths = sorted(file_paths)
    
    for file_path in sorted_paths:
        if not os.path.exists(file_path):
            # Si el archivo no existe, incluir la ruta en el hash para detectar cambios
            sha256.update(file_path.encode('utf-8'))
            continue
        
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
                sha256.update(file_content)
                # También incluir la ruta para evitar colisiones si dos archivos tienen el mismo contenido
                sha256.update(file_path.encode('utf-8'))
        except Exception as e:
            # Si hay un error al leer el archivo, incluir solo la ruta
            sha256.update(file_path.encode('utf-8'))
            sha256.update(str(e).encode('utf-8'))
    
    return sha256.hexdigest()


