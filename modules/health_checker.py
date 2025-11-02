"""
Módulo de verificación de salud para GraphSec-IaC

Proporciona funciones para verificar que las dependencias externas
están correctamente instaladas y disponibles en el sistema.
"""

import shutil
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def check_binary(command: str) -> Dict[str, Any]:
    """
    Verifica si un binario existe en el PATH del sistema.
    
    Args:
        command: Nombre del comando/binario a verificar
        
    Returns:
        Dict con status "ok" o "error" y path o mensaje de error
    """
    path = shutil.which(command)
    if path:
        return {
            "status": "ok",
            "path": path,
            "command": command
        }
    else:
        return {
            "status": "error",
            "message": f"'{command}' no encontrado en el PATH del sistema.",
            "command": command
        }

