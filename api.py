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
from modules.graph_generator import generate_graph, get_graph_summary
from modules.security_scanner import scan_for_issues, get_sarif_summary
from modules.correlation_engine import load_sarif_results, correlate_findings_to_graph

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

# Configuración
TEST_DIRECTORY = "./test_infra"
SARIF_OUTPUT_FILE = "checkov_results.sarif"


@app.get("/")
async def read_index():
    """Servir la página principal."""
    return FileResponse("static/index.html")


@app.get("/api/graph")
async def get_enriched_graph():
    """
    Endpoint principal que ejecuta todo el pipeline y devuelve el grafo enriquecido.
    
    Returns:
        Dict[str, Any]: Grafo enriquecido con información de seguridad
    """
    try:
        logger.info("Iniciando pipeline completo de análisis...")
        
        # ===== ETAPA 1: GENERACIÓN DEL GRAFO =====
        logger.info("Ejecutando Etapa 1: Generación del grafo...")
        graph_data = generate_graph(TEST_DIRECTORY)
        
        if graph_data is None:
            raise HTTPException(
                status_code=500, 
                detail="Error: No se pudo generar el grafo de infraestructura"
            )
        
        logger.info("Grafo generado exitosamente")
        
        # ===== ETAPA 2: ANÁLISIS DE SEGURIDAD =====
        logger.info("Ejecutando Etapa 2: Análisis de seguridad...")
        scan_success = scan_for_issues(TEST_DIRECTORY, SARIF_OUTPUT_FILE)
        
        if not scan_success:
            raise HTTPException(
                status_code=500,
                detail="Error: No se pudo ejecutar el análisis de seguridad"
            )
        
        logger.info("Análisis de seguridad completado exitosamente")
        
        # ===== ETAPA 3: CORRELACIÓN =====
        logger.info("Ejecutando Etapa 3: Correlación de hallazgos...")
        
        # Cargar hallazgos de seguridad desde SARIF
        sarif_findings = load_sarif_results(SARIF_OUTPUT_FILE)
        
        if not sarif_findings:
            raise HTTPException(
                status_code=500,
                detail="Error: No se pudieron cargar los hallazgos de seguridad"
            )
        
        logger.info(f"Cargados {len(sarif_findings)} hallazgos de seguridad")
        
        # Correlacionar hallazgos con el grafo
        enriched_graph = correlate_findings_to_graph(graph_data, sarif_findings)
        
        # Añadir metadatos adicionales para la API
        enriched_graph["api_metadata"] = {
            "status": "success",
            "message": "Pipeline completado exitosamente",
            "total_findings": len(sarif_findings),
            "total_nodes": len(enriched_graph.get("nodes", [])),
            "total_edges": len(enriched_graph.get("edges", []))
        }
        
        logger.info("Pipeline completado exitosamente")
        return enriched_graph
        
    except HTTPException:
        # Re-lanzar excepciones HTTP
        raise
    except Exception as e:
        logger.error(f"Error inesperado en el pipeline: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )


@app.get("/api/health")
async def health_check():
    """Endpoint de verificación de salud del servicio."""
    return {
        "status": "healthy",
        "service": "GraphSec-IaC API",
        "version": "1.0.0"
    }


@app.get("/api/summary")
async def get_analysis_summary():
    """
    Endpoint que devuelve un resumen del análisis sin ejecutar el pipeline completo.
    
    Returns:
        Dict[str, Any]: Resumen del análisis
    """
    try:
        # Verificar que los archivos necesarios existen
        if not os.path.exists(TEST_DIRECTORY):
            raise HTTPException(
                status_code=404,
                detail=f"Directorio de prueba no encontrado: {TEST_DIRECTORY}"
            )
        
        # Verificar archivo SARIF
        sarif_exists = os.path.exists(SARIF_OUTPUT_FILE) or os.path.exists(f"{SARIF_OUTPUT_FILE}/results_sarif.sarif")
        
        return {
            "test_directory": TEST_DIRECTORY,
            "sarif_file_exists": sarif_exists,
            "sarif_file_path": SARIF_OUTPUT_FILE,
            "status": "ready"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en health check: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
