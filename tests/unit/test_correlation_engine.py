"""
Tests unitarios para el motor de correlación (correlation_engine.py)
"""

import os
import pytest
from modules.correlation_engine import normalize_file_path, set_project_root


def test_normalize_path_absolute():
    """
    Verifica que normalize_file_path convierte correctamente una ruta absoluta.
    La función devuelve una ruta absoluta normalizada.
    """
    # Simula la raíz del proyecto
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    set_project_root(project_root)
    
    # Simula una ruta de fichero de un hallazgo SARIF (absoluta)
    test_path = os.path.join(project_root, "test_infra", "main.tf")
    
    # Llama a la función
    normalized = normalize_file_path(test_path, project_root)
    
    # Verifica el resultado (debe ser una ruta absoluta normalizada)
    assert normalized is not None
    assert os.path.isabs(normalized), "La ruta normalizada debe ser absoluta"
    assert os.path.normpath(normalized) == os.path.normpath(test_path), "Las rutas deben coincidir"
    assert "test_infra" in normalized
    assert "main.tf" in normalized


def test_normalize_path_relative():
    """
    Verifica que normalize_file_path convierte correctamente una ruta relativa a absoluta.
    """
    # Simula la raíz del proyecto
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    set_project_root(project_root)
    
    # Simula una ruta relativa
    test_path = "test_infra/main.tf"
    
    # Llama a la función
    normalized = normalize_file_path(test_path, project_root)
    
    # Verifica el resultado (debe convertir a absoluta)
    assert normalized is not None
    assert os.path.isabs(normalized), "La ruta normalizada debe ser absoluta"
    
    # La ruta normalizada debe incluir el proyecto raíz
    assert project_root in normalized or os.path.basename(project_root) in normalized
    assert "test_infra" in normalized
    assert "main.tf" in normalized


def test_normalize_path_empty():
    """
    Verifica que normalize_file_path maneja correctamente rutas vacías.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    set_project_root(project_root)
    
    # Ruta vacía
    result = normalize_file_path("", project_root)
    assert result == ""


def test_normalize_path_with_project_root_prefix():
    """
    Verifica que normalize_file_path maneja correctamente rutas que incluyen
    el nombre del directorio raíz del proyecto como prefijo.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    project_root_basename = os.path.basename(project_root)
    set_project_root(project_root)
    
    # Ruta con prefijo del directorio raíz
    test_path = f"{project_root_basename}/test_infra/main.tf"
    
    normalized = normalize_file_path(test_path, project_root)
    
    assert normalized is not None
    assert os.path.isabs(normalized)
    assert "test_infra" in normalized
    assert "main.tf" in normalized

