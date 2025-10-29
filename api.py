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
from modules.security_scanner import CheckovScanner, TrivyScanner
from modules.correlation_engine import load_multiple_sarif_results, correlate_findings_to_graph

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
CHECKOV_OUTPUT_FILE = "checkov_results.sarif"
TRIVY_OUTPUT_FILE = "trivy_results.sarif"


@app.get("/")
async def read_index():
    """Servir la página principal."""
    return FileResponse("static/index.html")


@app.get("/api/graph")
async def get_enriched_graph():
    """
    Endpoint principal que ejecuta todo el pipeline con múltiples escáneres y devuelve el grafo enriquecido.
    
    Returns:
        Dict[str, Any]: Grafo enriquecido con información de seguridad de múltiples fuentes
    """
    try:
        logger.info("Iniciando pipeline completo de análisis con múltiples escáneres...")
        
        # ===== ETAPA 1: GENERACIÓN DEL GRAFO =====
        logger.info("Ejecutando Etapa 1: Generación del grafo...")
        graph_data = generate_graph(TEST_DIRECTORY)
        
        if graph_data is None:
            raise HTTPException(
                status_code=500, 
                detail="Error: No se pudo generar el grafo de infraestructura"
            )
        
        logger.info("Grafo generado exitosamente")
        
        # ===== ETAPA 2: ANÁLISIS DE SEGURIDAD CON MÚLTIPLES ESCÁNERES =====
        logger.info("Ejecutando Etapa 2: Análisis de seguridad con Checkov y Trivy...")
        
        # Inicializar escáneres
        checkov_scanner = CheckovScanner()
        trivy_scanner = TrivyScanner()
        
        # Ejecutar Checkov
        logger.info("Ejecutando escaneo con Checkov...")
        checkov_success = checkov_scanner.scan(TEST_DIRECTORY, CHECKOV_OUTPUT_FILE)
        
        if not checkov_success:
            logger.warning("Checkov falló, continuando solo con Trivy...")
        
        # Ejecutar Trivy
        logger.info("Ejecutando escaneo con Trivy...")
        trivy_success = trivy_scanner.scan(TEST_DIRECTORY, TRIVY_OUTPUT_FILE)
        
        if not trivy_success:
            logger.warning("Trivy falló, continuando solo con Checkov...")
        
        # Verificar que al menos un escáner funcionó
        if not checkov_success and not trivy_success:
            raise HTTPException(
                status_code=500,
                detail="Error: Ambos escáneres fallaron"
            )
        
        logger.info("Análisis de seguridad completado exitosamente")
        
        # ===== ETAPA 3: CARGA Y COMBINACIÓN DE RESULTADOS =====
        logger.info("Ejecutando Etapa 3: Carga y combinación de resultados...")
        
        # Cargar resultados de ambos escáneres
        sarif_paths = []
        if checkov_success:
            sarif_paths.append(CHECKOV_OUTPUT_FILE)
        if trivy_success:
            sarif_paths.append(TRIVY_OUTPUT_FILE)
        
        # Cargar y combinar hallazgos de seguridad
        combined_findings = load_multiple_sarif_results(sarif_paths)
        
        if not combined_findings:
            raise HTTPException(
                status_code=500,
                detail="Error: No se pudieron cargar los hallazgos de seguridad"
            )
        
        logger.info(f"Cargados {len(combined_findings)} hallazgos combinados de {len(sarif_paths)} escáneres")
        
        # ===== ETAPA 4: CORRELACIÓN CON DE-DUPLICACIÓN =====
        logger.info("Ejecutando Etapa 4: Correlación con de-duplicación...")
        
        # Correlacionar hallazgos con el grafo (incluye de-duplicación automática)
        enriched_graph = correlate_findings_to_graph(graph_data, combined_findings)
        
        # Añadir metadatos adicionales para la API
        correlation_metadata = enriched_graph.get("correlation_metadata", {})
        enriched_graph["api_metadata"] = {
            "status": "success",
            "message": "Pipeline completado exitosamente con múltiples escáneres",
            "scanners_used": len(sarif_paths),
            "checkov_success": checkov_success,
            "trivy_success": trivy_success,
            "total_findings_original": correlation_metadata.get("total_findings_original", 0),
            "total_findings_unique": correlation_metadata.get("total_findings_unique", 0),
            "duplicates_removed": correlation_metadata.get("duplicates_removed", 0),
            "total_nodes": len(enriched_graph.get("nodes", [])),
            "total_edges": len(enriched_graph.get("edges", []))
        }
        
        logger.info("Pipeline completado exitosamente con múltiples escáneres")
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
        
        # Verificar archivos SARIF
        checkov_exists = os.path.exists(CHECKOV_OUTPUT_FILE) or os.path.exists(f"{CHECKOV_OUTPUT_FILE}/results_sarif.sarif")
        trivy_exists = os.path.exists(TRIVY_OUTPUT_FILE)
        
        return {
            "test_directory": TEST_DIRECTORY,
            "checkov_file_exists": checkov_exists,
            "trivy_file_exists": trivy_exists,
            "checkov_file_path": CHECKOV_OUTPUT_FILE,
            "trivy_file_path": TRIVY_OUTPUT_FILE,
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
