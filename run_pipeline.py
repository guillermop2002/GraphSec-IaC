"""
Script CLI para ejecutar el pipeline de análisis de GraphSec-IaC.

Este script puede ser ejecutado desde la línea de comandos o desde una GitHub Action.
"""

import os  # Módulo necesario para operaciones del sistema de archivos
import json
import shutil
import logging
import asyncio
import argparse
import time
from typing import Dict, Any, Tuple

# Importar funciones de los módulos existentes
from modules.security_scanner import CheckovScanner, TrivyScanner
from modules.correlation_engine import load_sarif_results, process_and_deduplicate_findings, attach_findings_to_graph
from modules.tf_parser import parse_terraform, _iter_tf_files
from modules.graph_builder import build_edges
from modules.utils import generate_hash_for_files

# Configurar logging
logger = logging.getLogger(__name__)

# Directorio de caché
CACHE_DIR = ".graphsec_cache"
os.makedirs(CACHE_DIR, exist_ok=True)


class PipelineError(Exception):
    """Excepción personalizada para errores del pipeline."""
    pass


def get_cached_or_generate_graph(directory: str, project_name: str) -> Dict[str, Any]:
    """
    Obtiene el grafo desde caché o lo genera si no existe.
    
    Args:
        directory: Directorio del proyecto Terraform
        project_name: Nombre del proyecto (para identificar caché)
    
    Returns:
        Dict con nodos y edges del grafo
    
    Raises:
        PipelineError: Si no se encuentran archivos .tf o recursos
    """
    project_root = os.path.abspath(directory)
    
    # Obtener lista de archivos .tf
    tf_files = _iter_tf_files(project_root)
    
    if not tf_files:
        raise PipelineError("Error: No se encontraron archivos .tf para analizar")
    
    # Generar hash de todos los archivos .tf
    graph_hash = generate_hash_for_files(tf_files)
    
    # Definir archivo de caché
    cache_file_graph = os.path.join(CACHE_DIR, f"{project_name}_graph_{graph_hash}.json")
    
    # Intentar cargar desde caché
    if os.path.exists(cache_file_graph):
        logger.info(f"Cargando grafo desde caché para {project_name}...")
        try:
            with open(cache_file_graph, 'r', encoding='utf-8') as f:
                graph_data = json.load(f)
            logger.info(f"Grafo cargado desde caché: {len(graph_data.get('nodes', []))} nodos, {len(graph_data.get('edges', []))} aristas")
            return graph_data
        except Exception as e:
            logger.warning(f"Error al cargar caché, regenerando grafo: {e}")
    
    # Generar grafo (no hay caché o falló)
    logger.info(f"Generando grafo para {project_name} (no hay caché)...")
    parsed_resources = parse_terraform(project_root)
    
    if not parsed_resources:
        raise PipelineError("Error: No se encontraron recursos Terraform para analizar")
    
    # Crear nodos con IDs únicos primero (para evitar duplicados en vis.js)
    nodes = []
    # Mapa de simple_name -> unique_id para usar en build_edges
    name_to_id_map = {}
    
    for resource in parsed_resources:
        # Crear un ID único basado en el nombre Y el fichero,
        # para diferenciar recursos con el mismo nombre en distintos ficheros.
        file_name = os.path.basename(resource.get('file', ''))
        simple_name = resource.get('simple_name', '')
        unique_id = f"{simple_name}_{file_name}" if file_name else simple_name
        
        # Guardar mapeo para usar en build_edges
        if simple_name not in name_to_id_map:
            name_to_id_map[simple_name] = []
        name_to_id_map[simple_name].append(unique_id)
        
        node = {
            "id": unique_id,  # ID único para vis.js
            "simple_name": simple_name,  # Nombre real
            "label": simple_name,
            "type": resource.get('type'),
            "file": resource.get('file'),
            "start_line": resource.get('start_line'),
            "end_line": resource.get('end_line'),
        }
        nodes.append(node)
    
    # Construir aristas usando los IDs únicos
    edges = build_edges(parsed_resources, name_to_id_map)
    
    graph_data = {"nodes": nodes, "edges": edges}
    
    # Guardar en caché
    try:
        with open(cache_file_graph, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2)
        logger.info(f"Grafo guardado en caché: {len(nodes)} nodos, {len(edges)} aristas")
    except Exception as e:
        logger.warning(f"Error al guardar en caché: {e}")
    
    return graph_data


async def get_cached_or_run_scanner(scanner, directory: str, output_file: str, project_name: str, scanner_name: str) -> Tuple[bool, str]:
    """
    Obtiene resultados del escáner desde caché o lo ejecuta si no existe (asíncrono).
    
    Args:
        scanner: Instancia del escáner (CheckovScanner o TrivyScanner)
        directory: Directorio a escanear
        output_file: Archivo de salida del escáner
        project_name: Nombre del proyecto
        scanner_name: Nombre del escáner ("checkov" o "trivy")
    
    Returns:
        Tupla (success: bool, output_file_path: str)
    """
    project_root = os.path.abspath(directory)
    
    # Obtener lista de archivos .tf y .tfvars para el hash
    tf_files = _iter_tf_files(project_root)
    # También incluir archivos .tfvars si existen
    tfvars_files = []
    for root, _, files in os.walk(project_root):
        for file in files:
            if file.endswith('.tfvars'):
                tfvars_files.append(os.path.join(root, file))
    
    all_files = tf_files + tfvars_files
    
    if not all_files:
        logger.warning(f"No se encontraron archivos para generar hash, ejecutando escáner...")
        success = await scanner.scan(directory, output_file)
        return success, output_file
    
    # Generar hash de todos los archivos relevantes
    scanner_hash = generate_hash_for_files(all_files)
    
    # Definir archivo de caché (usar directorio de caché, pero mantener formato SARIF)
    if scanner_name == "checkov":
        # Checkov guarda en un subdirectorio, usar ese formato
        cache_dir_scanner = os.path.join(CACHE_DIR, f"{scanner_name}_{project_name}_{scanner_hash}")
        cache_file_scanner = os.path.join(cache_dir_scanner, "results_sarif.sarif")
    else:
        # Trivy guarda directamente en un archivo
        cache_file_scanner = os.path.join(CACHE_DIR, f"{scanner_name}_{project_name}_{scanner_hash}.sarif")
    
    # Intentar cargar desde caché
    if os.path.exists(cache_file_scanner):
        logger.info(f"Resultados de {scanner_name} encontrados en caché para {project_name}...")
        # Retornar la ruta del caché como si fuera el output_file original
        return True, cache_file_scanner
    
    # Ejecutar escáner (no hay caché)
    logger.info(f"Ejecutando {scanner_name} para {project_name} (no hay caché)...")
    success = await scanner.scan(directory, output_file)
    
    if success:
        # Copiar resultado a caché
        try:
            if scanner_name == "checkov":
                # Checkov guarda en un subdirectorio
                source_dir = output_file
                if os.path.isdir(source_dir):
                    source_file = os.path.join(source_dir, "results_sarif.sarif")
                    if os.path.exists(source_file):
                        os.makedirs(os.path.dirname(cache_file_scanner), exist_ok=True)
                        shutil.copy2(source_file, cache_file_scanner)
                        logger.info(f"Resultados de {scanner_name} guardados en caché")
            else:
                # Trivy guarda directamente en un archivo
                if os.path.exists(output_file):
                    os.makedirs(os.path.dirname(cache_file_scanner), exist_ok=True)
                    shutil.copy2(output_file, cache_file_scanner)
                    logger.info(f"Resultados de {scanner_name} guardados en caché")
        except Exception as e:
            logger.warning(f"Error al guardar en caché: {e}")
    
    return success, output_file


async def run_analysis_pipeline(directory: str, project_name: str) -> Dict[str, Any]:
    """
    Ejecuta el pipeline completo de análisis de seguridad en un directorio dado.
    
    Args:
        directory: Directorio del proyecto Terraform a analizar (ruta absoluta)
        project_name: Nombre del proyecto (para identificarlo en caché y logs)
    
    Returns:
        Dict con el grafo enriquecido y metadatos del análisis
    
    Raises:
        PipelineError: Si hay errores durante el análisis
    """
    try:
        logger.info(f"Iniciando pipeline completo de análisis para proyecto '{project_name}' en '{directory}'...")
        
        # ===== ETAPA 1: GENERACIÓN DEL GRAFO (CON CACHÉ) =====
        logger.info("Ejecutando Etapa 1: Generación del grafo (con caché)...")
        graph_data = get_cached_or_generate_graph(directory, project_name)
        
        # ===== ETAPA 2: ANÁLISIS DE SEGURIDAD (EN PARALELO) =====
        logger.info("Ejecutando Etapa 2: Análisis de seguridad con Checkov y Trivy (en paralelo)...")
        
        checkov_scanner = CheckovScanner()
        trivy_scanner = TrivyScanner()
        
        # Generar nombres únicos de archivos de salida basados en el nombre del proyecto
        checkov_output_file = f"checkov_results_{project_name}.sarif"
        trivy_output_file = f"trivy_results_{project_name}.sarif"
        
        # Crear tareas para ejecutar los escáneres en paralelo
        stage2_start = time.time()
        logger.info("Iniciando tareas de escáner en paralelo...")
        
        checkov_task = get_cached_or_run_scanner(
            checkov_scanner, directory, checkov_output_file, project_name, "checkov"
        )
        trivy_task = get_cached_or_run_scanner(
            trivy_scanner, directory, trivy_output_file, project_name, "trivy"
        )
        
        # Esperar a que ambas tareas terminen simultáneamente
        results = await asyncio.gather(checkov_task, trivy_task, return_exceptions=True)
        
        stage2_elapsed = time.time() - stage2_start
        logger.info(f"Etapa 2 completada en {stage2_elapsed:.2f} segundos (tiempo de los escáneres en paralelo)")
        
        # Procesar resultados
        checkov_result = results[0]
        trivy_result = results[1]
        
        # Manejar si una tarea falló (lanzó una excepción)
        if isinstance(checkov_result, Exception):
            logger.error(f"Checkov falló catastróficamente: {checkov_result}")
            checkov_success = False
            checkov_output_path = None
        else:
            checkov_success, checkov_output_path = checkov_result
        
        if isinstance(trivy_result, Exception):
            logger.error(f"Trivy falló catastróficamente: {trivy_result}")
            trivy_success = False
            trivy_output_path = None
        else:
            trivy_success, trivy_output_path = trivy_result
        
        # Loguear advertencias si un escáner específico falló
        if not checkov_success:
            logger.warning("Checkov falló o no se ejecutó, continuando solo con Trivy...")
        if not trivy_success:
            logger.warning("Trivy falló o no se ejecutó, continuando solo con Checkov...")
        
        if not checkov_success and not trivy_success:
            raise PipelineError("Error: Ambos escáneres fallaron")
        
        # ===== ETAPA 3: CARGA Y COMBINACIÓN =====
        logger.info("Ejecutando Etapa 3: Carga y combinación de resultados...")
        
        all_raw_findings = []
        scanners_used = 0
        
        if checkov_success and checkov_output_path:
            # Si checkov_output_path es un directorio (formato antiguo de Checkov), buscar el archivo SARIF dentro
            if os.path.isdir(checkov_output_path):
                checkov_sarif_file = os.path.join(checkov_output_path, "results_sarif.sarif")
            else:
                checkov_sarif_file = checkov_output_path
            
            if os.path.exists(checkov_sarif_file):
                checkov_findings = load_sarif_results(checkov_sarif_file)
                all_raw_findings.extend(checkov_findings)
                scanners_used += 1
                logger.info(f"Cargados {len(checkov_findings)} hallazgos desde Checkov")
            else:
                logger.warning(f"Archivo SARIF de Checkov no encontrado: {checkov_sarif_file}")
        
        if trivy_success and trivy_output_path:
            if os.path.exists(trivy_output_path):
                trivy_findings = load_sarif_results(trivy_output_path)
                all_raw_findings.extend(trivy_findings)
                scanners_used += 1
                logger.info(f"Cargados {len(trivy_findings)} hallazgos desde Trivy")
            else:
                logger.warning(f"Archivo SARIF de Trivy no encontrado: {trivy_output_path}")
        
        if not all_raw_findings:
            raise PipelineError("Error: No se pudieron cargar los hallazgos de seguridad")
        
        logger.info(f"Total de hallazgos cargados: {len(all_raw_findings)} desde {scanners_used} escáneres")
        
        # ===== ETAPA 4: DE-DUPLICACIÓN Y CORRELACIÓN =====
        logger.info("Ejecutando Etapa 4: Procesado y de-duplicación (CFI)...")
        
        project_root = os.path.abspath(directory)
        dedup_results = process_and_deduplicate_findings(all_raw_findings, graph_data, project_root=project_root)
        unique_findings = dedup_results.get("unique_findings", [])
        duplicates_removed = dedup_results.get("duplicates_removed", 0)
        
        logger.info(f"De-duplicación (CFI) completada: {len(all_raw_findings)} -> {len(unique_findings)} hallazgos únicos ({duplicates_removed} duplicados eliminados)")
        
        # ===== ETAPA 5: ADJUNTO AL GRAFO =====
        logger.info("Ejecutando Etapa 5: Adjuntando hallazgos al grafo...")
        
        enriched_graph = attach_findings_to_graph(graph_data, unique_findings)
        
        correlation_metadata = enriched_graph.get("correlation_metadata", {})
        
        # Incluir layer_stats en correlation_metadata para que esté disponible en el informe
        layer_stats = dedup_results.get("layer_stats", {})
        correlation_metadata["layer_stats"] = layer_stats
        
        enriched_graph["api_metadata"] = {
            "status": "success",
            "message": f"Pipeline completado exitosamente para proyecto '{project_name}'",
            "project_name": project_name,
            "project_directory": directory,
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
        
        logger.info(f"Pipeline completado exitosamente para proyecto '{project_name}'")
        return enriched_graph
        
    except PipelineError:
        # Re-lanzar excepciones del pipeline
        raise
    except Exception as e:
        logger.error(f"Error inesperado en el pipeline: {e}")
        raise PipelineError(f"Error interno del pipeline: {str(e)}") from e


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GraphSec-IaC Analysis Pipeline")
    parser.add_argument("-d", "--directory", required=True, help="Directorio del proyecto Terraform a analizar")
    parser.add_argument("-p", "--project", required=True, help="Nombre del proyecto (para el caché)")
    parser.add_argument("-o", "--output", default="graph_data.json", help="Fichero JSON de salida")
    
    args = parser.parse_args()
    
    # Configurar logging básico
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    print(f"Iniciando análisis para: {args.directory}")
    
    try:
        # Ejecutar el pipeline
        graph_data = asyncio.run(run_analysis_pipeline(args.directory, args.project))
        
        # Escribir el resultado a JSON
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=4)
        
        print(f"\n✅ Análisis completado. Resultados guardados en: {args.output}")
        
        # Imprimir resumen de métricas
        metadata = graph_data.get("api_metadata", {})
        correlation = metadata.get("correlation_metadata", {})
        print("\n--- Resumen de Métricas ---")
        print(f"  Nodos Totales: {metadata.get('total_nodes')}")
        print(f"  Aristas Totales: {metadata.get('total_edges')}")
        print(f"  Hallazgos Únicos: {metadata.get('total_findings_unique')}")
        print(f"  Nodos Vulnerables: {correlation.get('nodes_with_issues_count', 0)}")
        print(f"  No Asignados: {metadata.get('unassigned_findings_count', 0)}")
        
    except PipelineError as e:
        print(f"\n❌ Error en el pipeline: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        exit(1)

