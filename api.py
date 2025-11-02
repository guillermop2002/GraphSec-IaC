"""
API FastAPI para GraphSec-IaC

Este módulo proporciona una API RESTful para exponer la funcionalidad
de análisis de infraestructura y seguridad a través de endpoints web.
"""

import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Dict, Any

# Importar funciones de los módulos existentes
from modules.health_checker import check_binary

# Importar el pipeline desde run_pipeline.py
from run_pipeline import run_analysis_pipeline

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear instancia de FastAPI
app = FastAPI(
    title="GraphSec-IaC API",
    description="API para análisis de infraestructura y seguridad",
    version="1.0.0"
)

# Montar archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configuración de directorios de proyectos
TEST_DIRECTORY = "./test_infra"
TERRAFORM_VPC_DIRECTORY = "./terraform-aws-vpc"
TERRAFORM_EKS_DIRECTORY = "./terraform-aws-eks"


# Las funciones get_cached_or_generate_graph y get_cached_or_run_scanner
# ahora están en run_pipeline.py y se usan internamente por run_analysis_pipeline

@app.get("/")
async def read_index():
    """Servir la página principal."""
    return FileResponse("static/index.html")


# La función run_analysis_pipeline ahora está en run_pipeline.py y se importa arriba
# Esta función se mantiene en api.py como wrapper para manejar HTTPException
async def run_analysis_pipeline_wrapper(directory: str, project_name: str) -> Dict[str, Any]:
    """
    Wrapper para run_analysis_pipeline que convierte PipelineError en HTTPException.
    
    Args:
        directory: Directorio del proyecto Terraform a analizar
        project_name: Nombre del proyecto
    
    Returns:
        Dict con el grafo enriquecido y metadatos del análisis
    
    Raises:
        HTTPException: Si hay errores durante el análisis
    """
    try:
        from run_pipeline import PipelineError
        return await run_analysis_pipeline(directory, project_name)
    except PipelineError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Error inesperado en el pipeline: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")


@app.get("/api/graph")
async def get_enriched_graph(project: str = None):
    """
    Endpoint principal. Analiza un proyecto basado en el parámetro 'project'.
    
    - ?project=vpc -> Analiza terraform-aws-vpc
    - ?project=eks -> Analiza terraform-aws-eks
    - (por defecto) -> Analiza test_infra
    
    Args:
        project: Nombre del proyecto a analizar ('vpc', 'eks', o None para test_infra)
    
    Returns:
        Dict[str, Any]: Grafo enriquecido con información de seguridad
    """
    if project == "vpc":
        directory = TERRAFORM_VPC_DIRECTORY
        project_name = "vpc"
    elif project == "eks":
        directory = TERRAFORM_EKS_DIRECTORY
        project_name = "eks"
    else:
        directory = TEST_DIRECTORY
        project_name = "test"
    
    logger.info(f"Iniciando análisis para proyecto: {project_name} (Directorio: {directory})")
    
    # Verificar que el directorio existe antes de continuar
    if not os.path.exists(directory):
        logger.error(f"El directorio del proyecto no existe: {directory}")
        raise HTTPException(status_code=404, detail=f"Directorio no encontrado: {directory}")
    
    return await run_analysis_pipeline_wrapper(directory, project_name)




@app.get("/api/health")
async def health_check():
    """
    Verifica que todas las dependencias binarias (terraform, checkov, trivy) estén disponibles.
    
    Returns:
        Dict con el estado del servicio y verificación de dependencias externas
    """
    dependencies = {
        "terraform": check_binary("terraform"),
        "checkov": check_binary("checkov"),
        "trivy": check_binary("trivy")
    }
    
    # Determinar el estado general del servicio
    all_ok = all(dep.get("status") == "ok" for dep in dependencies.values())
    overall_status = "healthy" if all_ok else "degraded"
    
    return {
        "status": overall_status,
        "service": "GraphSec-IaC API",
        "version": "1.0.0",
        "dependencies": dependencies
    }


