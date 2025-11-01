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
from modules.correlation_engine import load_sarif_results, process_and_deduplicate_findings, attach_findings_to_graph
from modules.tf_parser import parse_terraform
from modules.graph_builder import enrich_graph_nodes_with_parsed

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
TERRAFORM_VPC_DIRECTORY = "./terraform-aws-vpc"
TERRAFORM_EKS_DIRECTORY = "./terraform-aws-eks"
CHECKOV_OUTPUT_FILE = "checkov_results.sarif"
TRIVY_OUTPUT_FILE = "trivy_results.sarif"
CHECKOV_OUTPUT_FILE_VPC = "checkov_results_vpc.sarif"
TRIVY_OUTPUT_FILE_VPC = "trivy_results_vpc.sarif"
CHECKOV_OUTPUT_FILE_EKS = "checkov_results_eks.sarif"
TRIVY_OUTPUT_FILE_EKS = "trivy_results_eks.sarif"


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
        all_raw_findings = []
        scanners_used = 0
        
        if checkov_success:
            checkov_findings = load_sarif_results(CHECKOV_OUTPUT_FILE)
            all_raw_findings.extend(checkov_findings)
            scanners_used += 1
            logger.info(f"Cargados {len(checkov_findings)} hallazgos desde Checkov")
        
        if trivy_success:
            trivy_findings = load_sarif_results(TRIVY_OUTPUT_FILE)
            all_raw_findings.extend(trivy_findings)
            scanners_used += 1
            logger.info(f"Cargados {len(trivy_findings)} hallazgos desde Trivy")
        
        if not all_raw_findings:
            raise HTTPException(
                status_code=500,
                detail="Error: No se pudieron cargar los hallazgos de seguridad"
            )
        
        logger.info(f"Total de hallazgos cargados: {len(all_raw_findings)} desde {scanners_used} escáneres")
        
        # ===== ETAPA 4: DE-DUPLICACIÓN Y CORRELACIÓN =====
        logger.info("Ejecutando Etapa 4: Procesado y de-duplicación (CFI)...")
        
        # Pasar el directorio raíz del proyecto para normalización de rutas
        project_root = os.path.abspath(TEST_DIRECTORY)
        dedup_results = process_and_deduplicate_findings(all_raw_findings, graph_data, project_root=project_root)
        unique_findings = dedup_results.get("unique_findings", [])
        duplicates_removed = dedup_results.get("duplicates_removed", 0)
        
        logger.info(f"De-duplicación (CFI) completada: {len(all_raw_findings)} -> {len(unique_findings)} hallazgos únicos ({duplicates_removed} duplicados eliminados)")
        
        # ===== ETAPA 5: ADJUNTO AL GRAFO =====
        logger.info("Ejecutando Etapa 5: Adjuntando hallazgos al grafo...")
        
        enriched_graph = attach_findings_to_graph(graph_data, unique_findings)
        
        # Añadir metadatos adicionales para la API
        correlation_metadata = enriched_graph.get("correlation_metadata", {})
        enriched_graph["api_metadata"] = {
            "status": "success",
            "message": "Pipeline completado exitosamente con múltiples escáneres",
            "scanners_used": scanners_used,
            "checkov_success": checkov_success,
            "trivy_success": trivy_success,
            "total_findings_original": len(all_raw_findings),
            "total_findings_unique": len(unique_findings),
            "duplicates_removed": duplicates_removed,
            "deduplication_method": "CFI_CIS+SARIF_FP",
            "total_nodes": len(enriched_graph.get("nodes", [])),
            "total_edges": len(enriched_graph.get("edges", [])),
            "correlation_metadata": correlation_metadata,
            "unassigned_findings_count": correlation_metadata.get("unassigned_findings_count", 0)
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


@app.get("/api/graph-vpc")
async def get_enriched_graph_vpc():
    """
    Endpoint para analizar terraform-aws-vpc.
    
    Este endpoint ejecuta el pipeline completo sobre terraform-aws-vpc.
    """
    try:
        logger.info("Iniciando pipeline completo de análisis con terraform-aws-vpc...")
        
        # ===== ETAPA 1: GENERACIÓN DEL GRAFO =====
        logger.info("Ejecutando Etapa 1: Generación del grafo...")
        graph_data = generate_graph(TERRAFORM_VPC_DIRECTORY)
        
        if graph_data is None:
            raise HTTPException(
                status_code=500, 
                detail="Error: No se pudo generar el grafo de infraestructura"
            )
        
        logger.info("Grafo generado exitosamente")
        
        # ===== ETAPA 1.5: ENRIQUECER NODOS CON PARSER =====
        try:
            parsed = parse_terraform(TERRAFORM_VPC_DIRECTORY)
            graph_data = enrich_graph_nodes_with_parsed(graph_data, parsed)
            logger.info(f"Nodos enriquecidos con metadatos de archivo/líneas ({len(parsed)} recursos)")
        except Exception as e:
            logger.warning(f"No se pudo enriquecer nodos con parser propio: {e}")

        # ===== ETAPA 2: ANÁLISIS DE SEGURIDAD =====
        logger.info("Ejecutando Etapa 2: Análisis de seguridad con Checkov y Trivy...")
        
        checkov_scanner = CheckovScanner()
        trivy_scanner = TrivyScanner()
        
        logger.info("Ejecutando escaneo con Checkov...")
        checkov_success = checkov_scanner.scan(TERRAFORM_VPC_DIRECTORY, CHECKOV_OUTPUT_FILE_VPC)
        
        if not checkov_success:
            logger.warning("Checkov falló, continuando solo con Trivy...")
        
        logger.info("Ejecutando escaneo con Trivy...")
        trivy_success = trivy_scanner.scan(TERRAFORM_VPC_DIRECTORY, TRIVY_OUTPUT_FILE_VPC)
        
        if not trivy_success:
            logger.warning("Trivy falló, continuando solo con Checkov...")
        
        if not checkov_success and not trivy_success:
            raise HTTPException(
                status_code=500,
                detail="Error: Ambos escáneres fallaron"
            )
        
        # ===== ETAPA 3: CARGA Y COMBINACIÓN =====
        logger.info("Ejecutando Etapa 3: Carga y combinación de resultados...")
        
        all_raw_findings = []
        scanners_used = 0
        
        if checkov_success:
            checkov_findings = load_sarif_results(CHECKOV_OUTPUT_FILE_VPC)
            all_raw_findings.extend(checkov_findings)
            scanners_used += 1
            logger.info(f"Cargados {len(checkov_findings)} hallazgos desde Checkov")
        
        if trivy_success:
            trivy_findings = load_sarif_results(TRIVY_OUTPUT_FILE_VPC)
            all_raw_findings.extend(trivy_findings)
            scanners_used += 1
            logger.info(f"Cargados {len(trivy_findings)} hallazgos desde Trivy")
        
        if not all_raw_findings:
            raise HTTPException(
                status_code=500,
                detail="Error: No se pudieron cargar los hallazgos de seguridad"
            )
        
        logger.info(f"Total de hallazgos cargados: {len(all_raw_findings)} desde {scanners_used} escáneres")
        
        # ===== ETAPA 4: DE-DUPLICACIÓN Y CORRELACIÓN =====
        logger.info("Ejecutando Etapa 4: Procesado y de-duplicación (CFI)...")
        
        # Pasar el directorio raíz del proyecto para normalización de rutas
        project_root = os.path.abspath(TERRAFORM_VPC_DIRECTORY)
        dedup_results = process_and_deduplicate_findings(all_raw_findings, graph_data, project_root=project_root)
        unique_findings = dedup_results.get("unique_findings", [])
        duplicates_removed = dedup_results.get("duplicates_removed", 0)
        
        logger.info(f"De-duplicación (CFI) completada: {len(all_raw_findings)} -> {len(unique_findings)} hallazgos únicos ({duplicates_removed} duplicados eliminados)")
        
        # ===== ETAPA 5: ADJUNTO AL GRAFO =====
        logger.info("Ejecutando Etapa 5: Adjuntando hallazgos al grafo...")
        
        enriched_graph = attach_findings_to_graph(graph_data, unique_findings)
        
        correlation_metadata = enriched_graph.get("correlation_metadata", {})
        enriched_graph["api_metadata"] = {
            "status": "success",
            "message": "Pipeline completado exitosamente con terraform-aws-vpc",
            "scanners_used": scanners_used,
            "checkov_success": checkov_success,
            "trivy_success": trivy_success,
            "total_findings_original": len(all_raw_findings),
            "total_findings_unique": len(unique_findings),
            "duplicates_removed": duplicates_removed,
            "deduplication_method": "CFI_CIS+SARIF_FP",
            "total_nodes": len(enriched_graph.get("nodes", [])),
            "total_edges": len(enriched_graph.get("edges", [])),
            "correlation_metadata": correlation_metadata,
            "unassigned_findings_count": correlation_metadata.get("unassigned_findings_count", 0)
        }
        
        logger.info("Pipeline completado exitosamente con terraform-aws-vpc")
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


@app.get("/api/graph-eks")
async def get_enriched_graph_eks():
    """
    Endpoint para analizar terraform-aws-eks (prueba de estrés - módulo EKS).
    
    Este endpoint ejecuta el pipeline completo sobre terraform-aws-eks, un módulo
    extremadamente complejo que usa bloques dinámicos anidados, lógica de fusión
    compleja y strings con interpolación.
    """
    try:
        logger.info("Iniciando pipeline completo de análisis con terraform-aws-eks (PRUEBA DE ESTRÉS)...")
        
        # ===== ETAPA 1: GENERACIÓN DEL GRAFO =====
        logger.info("Ejecutando Etapa 1: Generación del grafo...")
        graph_data = generate_graph(TERRAFORM_EKS_DIRECTORY)
        
        if graph_data is None:
            raise HTTPException(
                status_code=500, 
                detail="Error: No se pudo generar el grafo de infraestructura"
            )
        
        logger.info("Grafo generado exitosamente")
        
        # ===== ETAPA 1.5: ENRIQUECER NODOS CON PARSER =====
        try:
            parsed = parse_terraform(TERRAFORM_EKS_DIRECTORY)
            graph_data = enrich_graph_nodes_with_parsed(graph_data, parsed)
            logger.info(f"Nodos enriquecidos con metadatos de archivo/líneas ({len(parsed)} recursos)")
        except Exception as e:
            logger.warning(f"No se pudo enriquecer nodos con parser propio: {e}")

        # ===== ETAPA 2: ANÁLISIS DE SEGURIDAD =====
        logger.info("Ejecutando Etapa 2: Análisis de seguridad con Checkov y Trivy...")
        
        checkov_scanner = CheckovScanner()
        trivy_scanner = TrivyScanner()
        
        logger.info("Ejecutando escaneo con Checkov...")
        checkov_success = checkov_scanner.scan(TERRAFORM_EKS_DIRECTORY, CHECKOV_OUTPUT_FILE_EKS)
        
        if not checkov_success:
            logger.warning("Checkov falló, continuando solo con Trivy...")
        
        logger.info("Ejecutando escaneo con Trivy...")
        trivy_success = trivy_scanner.scan(TERRAFORM_EKS_DIRECTORY, TRIVY_OUTPUT_FILE_EKS)
        
        if not trivy_success:
            logger.warning("Trivy falló, continuando solo con Checkov...")
        
        if not checkov_success and not trivy_success:
            raise HTTPException(
                status_code=500,
                detail="Error: Ambos escáneres fallaron"
            )
        
        # ===== ETAPA 3: CARGA Y COMBINACIÓN =====
        logger.info("Ejecutando Etapa 3: Carga y combinación de resultados...")
        
        all_raw_findings = []
        scanners_used = 0
        
        if checkov_success:
            checkov_findings = load_sarif_results(CHECKOV_OUTPUT_FILE_EKS)
            all_raw_findings.extend(checkov_findings)
            scanners_used += 1
            logger.info(f"Cargados {len(checkov_findings)} hallazgos desde Checkov")
        
        if trivy_success:
            trivy_findings = load_sarif_results(TRIVY_OUTPUT_FILE_EKS)
            all_raw_findings.extend(trivy_findings)
            scanners_used += 1
            logger.info(f"Cargados {len(trivy_findings)} hallazgos desde Trivy")
        
        if not all_raw_findings:
            raise HTTPException(
                status_code=500,
                detail="Error: No se pudieron cargar los hallazgos de seguridad"
            )
        
        logger.info(f"Total de hallazgos cargados: {len(all_raw_findings)} desde {scanners_used} escáneres")
        
        # ===== ETAPA 4: DE-DUPLICACIÓN Y CORRELACIÓN =====
        logger.info("Ejecutando Etapa 4: Procesado y de-duplicación (CFI)...")
        
        # Pasar el directorio raíz del proyecto para normalización de rutas
        project_root = os.path.abspath(TERRAFORM_EKS_DIRECTORY)
        dedup_results = process_and_deduplicate_findings(all_raw_findings, graph_data, project_root=project_root)
        unique_findings = dedup_results.get("unique_findings", [])
        duplicates_removed = dedup_results.get("duplicates_removed", 0)
        
        logger.info(f"De-duplicación (CFI) completada: {len(all_raw_findings)} -> {len(unique_findings)} hallazgos únicos ({duplicates_removed} duplicados eliminados)")
        
        # ===== ETAPA 5: ADJUNTO AL GRAFO =====
        logger.info("Ejecutando Etapa 5: Adjuntando hallazgos al grafo...")
        
        enriched_graph = attach_findings_to_graph(graph_data, unique_findings)
        
        correlation_metadata = enriched_graph.get("correlation_metadata", {})
        enriched_graph["api_metadata"] = {
            "status": "success",
            "message": "Pipeline completado exitosamente con terraform-aws-eks (prueba de estrés)",
            "scanners_used": scanners_used,
            "checkov_success": checkov_success,
            "trivy_success": trivy_success,
            "total_findings_original": len(all_raw_findings),
            "total_findings_unique": len(unique_findings),
            "duplicates_removed": duplicates_removed,
            "deduplication_method": "CFI_CIS+SARIF_FP",
            "total_nodes": len(enriched_graph.get("nodes", [])),
            "total_edges": len(enriched_graph.get("edges", [])),
            "correlation_metadata": correlation_metadata,
            "unassigned_findings_count": correlation_metadata.get("unassigned_findings_count", 0)
        }
        
        logger.info("Pipeline completado exitosamente con terraform-aws-eks")
        return enriched_graph
        
    except HTTPException:
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
