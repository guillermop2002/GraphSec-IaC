#!/usr/bin/env python3
"""
Script para probar el pipeline localmente con logging detallado.
Clona terraform-aws-vpc si no existe y ejecuta el análisis.
"""

import os
import subprocess
import sys
import logging
import asyncio
from pathlib import Path

# Configurar logging para ver todos los mensajes de diagnóstico
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Directorio donde clonar el proyecto
VPC_DIR = "./terraform-aws-vpc"
PROJECT_NAME = "vpc_local_test"

def clone_vpc_repo():
    """Clona el repositorio terraform-aws-vpc si no existe."""
    if os.path.exists(VPC_DIR):
        logger.info(f"El directorio {VPC_DIR} ya existe, omitiendo clonado")
        return True
    
    logger.info("Clonando terraform-aws-vpc...")
    try:
        result = subprocess.run(
            ["git", "clone", "https://github.com/terraform-aws-modules/terraform-aws-vpc.git", "--depth", "1", VPC_DIR],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info("Repositorio clonado exitosamente")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al clonar: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.error("Git no está instalado. Por favor instálalo primero.")
        return False

def init_terraform():
    """Inicializa Terraform en el directorio del proyecto."""
    logger.info("Inicializando Terraform...")
    try:
        result = subprocess.run(
            ["terraform", "init", "-backend=false"],
            cwd=VPC_DIR,
            capture_output=True,
            text=True,
            check=True
        )
        logger.info("Terraform inicializado exitosamente")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al inicializar Terraform: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.error("Terraform no está instalado. Por favor instálalo primero.")
        return False

def run_pipeline():
    """Ejecuta el pipeline de análisis."""
    logger.info("=" * 80)
    logger.info("INICIANDO PIPELINE DE ANÁLISIS")
    logger.info("=" * 80)
    
    # Importar aquí para que los logs se configuren primero
    from run_pipeline import run_analysis_pipeline
    
    # Ejecutar el pipeline
    try:
        result = asyncio.run(run_analysis_pipeline(VPC_DIR, PROJECT_NAME))
        
        # Mostrar resumen
        logger.info("=" * 80)
        logger.info("RESUMEN DE RESULTADOS")
        logger.info("=" * 80)
        
        metadata = result.get("api_metadata", {})
        correlation = metadata.get("correlation_metadata", {})
        
        logger.info(f"Nodos Totales: {metadata.get('total_nodes')}")
        logger.info(f"Aristas Totales: {metadata.get('total_edges')}")
        logger.info(f"Hallazgos Únicos: {metadata.get('total_findings_unique')}")
        logger.info(f"Nodos Vulnerables: {correlation.get('nodes_with_issues_count', 0)}")
        logger.info(f"Duplicados Eliminados: {metadata.get('duplicates_removed', 0)}")
        logger.info(f"Escáneres Usados: {metadata.get('scanners_used', 0)}")
        logger.info(f"No Asignados: {metadata.get('unassigned_findings_count', 0)}")
        
        # Guardar resultado
        output_file = "graph_data_local.json"
        import json
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
        logger.info(f"\nResultados guardados en: {output_file}")
        
        return True
    except Exception as e:
        logger.error(f"Error al ejecutar el pipeline: {e}", exc_info=True)
        return False

def main():
    """Función principal."""
    logger.info("Script de prueba local para GraphSec-IaC")
    logger.info(f"Directorio de trabajo: {os.getcwd()}")
    
    # Paso 1: Clonar repositorio
    if not clone_vpc_repo():
        logger.error("No se pudo clonar el repositorio")
        return 1
    
    # Paso 2: Inicializar Terraform
    if not init_terraform():
        logger.error("No se pudo inicializar Terraform")
        return 1
    
    # Paso 3: Ejecutar pipeline
    if not run_pipeline():
        logger.error("El pipeline falló")
        return 1
    
    logger.info("\n" + "=" * 80)
    logger.info("✅ PRUEBA LOCAL COMPLETADA EXITOSAMENTE")
    logger.info("=" * 80)
    return 0

if __name__ == "__main__":
    sys.exit(main())

