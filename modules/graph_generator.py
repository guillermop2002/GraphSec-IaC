"""
Módulo generador de grafos para GraphSec-IaC

Este módulo proporciona funcionalidad para generar grafos de infraestructura
usando blast-radius sobre proyectos de Terraform.
"""

import subprocess
import json
import logging
import os
from typing import Dict, Optional

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_graph(directory_path: str) -> Optional[Dict]:
    """
    Genera un grafo de infraestructura usando blast-radius sobre un directorio de Terraform.
    
    Args:
        directory_path (str): Ruta al directorio que contiene los archivos de Terraform
        
    Returns:
        Optional[Dict]: Diccionario con la estructura del grafo en formato JSON,
                       o None si ocurre algún error
    """
    
    # Verificar que el directorio existe
    if not os.path.exists(directory_path):
        logger.error(f"El directorio {directory_path} no existe")
        return None
    
    # Verificar que el directorio contiene archivos .tf
    tf_files = [f for f in os.listdir(directory_path) if f.endswith('.tf')]
    if not tf_files:
        logger.error(f"No se encontraron archivos .tf en {directory_path}")
        return None
    
    # Construir el comando blast-radius
    # Usar el launcher .cmd que creamos para evitar problemas de PATH
    blast_radius_cmd = os.path.join(os.path.dirname(__file__), '..', 'venv', 'Scripts', 'blast-radius.cmd')
    
    # Verificar que blast-radius está disponible
    if not os.path.exists(blast_radius_cmd):
        logger.error(f"blast-radius no encontrado en {blast_radius_cmd}")
        return None
    
    # Usar el método que sabemos que funciona: terraform graph | blast-radius --json
    terraform_cmd = ['terraform', 'graph']
    blast_radius_cmd_full = [blast_radius_cmd, '--json']
    
    try:
        logger.info("Ejecutando terraform graph | blast-radius --json...")
        
        # Ejecutar terraform graph
        terraform_process = subprocess.Popen(
            terraform_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=directory_path
        )
        
        # Ejecutar blast-radius con la salida de terraform como entrada
        blast_radius_process = subprocess.Popen(
            blast_radius_cmd_full,
            stdin=terraform_process.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.dirname(__file__)
        )
        
        # Cerrar el stdout de terraform para que blast-radius pueda leerlo
        terraform_process.stdout.close()
        
        # Esperar a que ambos procesos terminen
        terraform_stdout, terraform_stderr = terraform_process.communicate()
        blast_radius_stdout, blast_radius_stderr = blast_radius_process.communicate()
        
        # Verificar si terraform falló
        if terraform_process.returncode != 0:
            logger.error(f"terraform graph falló con código {terraform_process.returncode}")
            logger.error(f"Error: {terraform_stderr}")
            return None
        
        # Verificar si blast-radius falló
        if blast_radius_process.returncode != 0:
            logger.error(f"blast-radius falló con código {blast_radius_process.returncode}")
            logger.error(f"Error: {blast_radius_stderr}")
            return None
        
        # Usar la salida de blast-radius
        result_stdout = blast_radius_stdout
        result_stderr = blast_radius_stderr
        
    except Exception as e:
        logger.error(f"Error al ejecutar el pipeline: {e}")
        return None
    
    # Verificar que hay salida
    if not result_stdout.strip():
        logger.error("blast-radius no produjo ninguna salida")
        return None
    
    # Parsear la salida JSON
    try:
        graph_data = json.loads(result_stdout)
        logger.info("Grafo generado exitosamente")
        return graph_data
        
    except json.JSONDecodeError as e:
        logger.error(f"Error al parsear JSON: {e}")
        logger.error(f"Salida recibida: {result_stdout[:200]}...")
        return None


def get_graph_summary(graph_data: Dict) -> Dict:
    """
    Obtiene un resumen del grafo generado.
    
    Args:
        graph_data (Dict): Datos del grafo en formato JSON
        
    Returns:
        Dict: Resumen con estadísticas del grafo
    """
    if not graph_data:
        return {"error": "No hay datos del grafo"}
    
    summary = {
        "total_nodes": len(graph_data.get("nodes", [])),
        "total_edges": len(graph_data.get("edges", [])),
        "node_types": list(set(node.get("type", "unknown") for node in graph_data.get("nodes", []))),
        "has_metadata": "metadata" in graph_data
    }
    
    return summary
