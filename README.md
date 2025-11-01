# GraphSec-IaC

Una herramienta de orquestación para visualizar la seguridad en infraestructura como código (IaC).

## Descripción

GraphSec-IaC es una herramienta que combina la visualización de infraestructura con el análisis de seguridad, permitiendo correlacionar los resultados de escáneres de seguridad (como Checkov/Trivy) con la estructura de dependencias de la infraestructura generada por herramientas como Blast Radius.

## Arquitectura

El proyecto está dividido en tres etapas principales:

### Etapa 1: Generación y Enriquecimiento de Grafos ✅
- **Módulos**: 
  - `modules/graph_generator.py`: Genera grafos usando `blast-radius`
  - `modules/tf_parser.py`: Parser robusto de Terraform usando `python-hcl2`
  - `modules/graph_builder.py`: Enriquece nodos con metadatos precisos de archivo/líneas
- **Función**: Genera grafos de infraestructura y enriquece nodos con ubicación precisa
- **Salida**: JSON con estructura de nodos, aristas y metadatos de ubicación

### Etapa 2: Análisis de Seguridad ✅
- **Módulo**: `modules/security_scanner.py`
- **Herramientas**: Checkov y Trivy (múltiples escáneres)
- **Formato**: Reportes SARIF
- **Función**: Escanear infraestructura en busca de vulnerabilidades y malas configuraciones
- **Salida**: Archivos SARIF con hallazgos de seguridad de múltiples fuentes

### Etapa 3: Normalización (CIS) y De-duplicación con CFI ✅
- **Módulo**: `modules/correlation_engine.py`
- **Funciones clave**:
  - `load_sarif_results(path)`: Carga SARIF y extrae `partialFingerprints` si existen
  - `process_and_deduplicate_findings(findings, graph_data, project_root)`: Genera CFI, filtra ruido y de-duplica
  - `attach_findings_to_graph(graph_data, unique_findings)`: Adjunta hallazgos por recurso
- **Algoritmo**: CFI (Canonical Finding Identifier) basado en controles CIS normalizados + ubicación + resource_id; prioriza `partialFingerprints` cuando están presentes
- **De-duplicación**: Estable por CFI (independiente del texto del mensaje), elimina duplicados entre y dentro de escáneres
- **Filtrado inteligente**: Elimina automáticamente hallazgos de `examples/`, `tests/` y archivos `.yml/.yaml` que no tienen nodos en el grafo
- **Correlación por capas**:
  - **Capa 1 (Precisa)**: Correlación por rango de líneas exactas + rutas absolutas normalizadas. Requiere que el hallazgo esté dentro del rango `[start_line, end_line]` del nodo.
  - **Capa 2 (Filename)**: Fallback por coincidencia de nombre de archivo (ruta absoluta normalizada). Útil cuando el parser no capturó rangos precisos.
  - **Capa 3 (Semántica/CIS)**: Fallback conservador que solo asigna cuando hay exactamente 1 candidato único basado en tipo de recurso y regla CIS.
- **Normalización de rutas**: Usa rutas absolutas como fuente única de verdad, permitiendo comparación directa entre hallazgos SARIF y nodos del parser
- **Salida**: Grafo enriquecido con vulnerabilidades únicas correlacionadas exitosamente, estadísticas de distribución por capas

### Etapa 4: API y Frontend Web ✅
- **API**: `api.py` con FastAPI
- **Frontend**: `static/index.html` con visualización vis.js
- **Función**: Exponer funcionalidad a través de API RESTful y interfaz web
- **Características**: Visualización interactiva, nodos coloreados por vulnerabilidades, estadísticas en tiempo real

## Instalación

### Prerrequisitos

- Python 3.8+
- Terraform
- Graphviz
- Git

### Configuración del Entorno

```bash
# Clonar el repositorio
git clone https://github.com/guillermop2002/GraphSec-IaC.git
cd GraphSec-IaC

# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Instalar dependencias
pip install git+https://github.com/Ianyliu/blast-radius-fork
pip install python-hcl2

# Instalar Graphviz (Windows)
winget install Graphviz

# Instalar Terraform (Windows)
winget install Hashicorp.Terraform
```

## Uso

### Ejecutar la Aplicación Web

Con el entorno virtual activado y desde la raíz del proyecto:

```bash
# Iniciar el servidor web
uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

Luego abre tu navegador y ve a: **http://127.0.0.1:8000**

### Ejecutar Análisis por Línea de Comandos (Opcional)

Si prefieres ejecutar el análisis sin interfaz web, puedes usar directamente los módulos:

```python
from modules.graph_generator import generate_graph
from modules.correlation_engine import (
    load_sarif_results,
    process_and_deduplicate_findings,
    attach_findings_to_graph,
)

# Generar grafo e importar hallazgos SARIF
graph_data = generate_graph("./test_infra")
all_findings = []
all_findings.extend(load_sarif_results("checkov_results.sarif"))
all_findings.extend(load_sarif_results("trivy_results.sarif"))

# De-duplicación con CFI y adjunto al grafo
dedup = process_and_deduplicate_findings(all_findings, graph_data)
unique = dedup["unique_findings"]
enriched_graph = attach_findings_to_graph(graph_data, unique)
```

## Estructura del Proyecto

```
GraphSec-IaC/
├── modules/
│   ├── graph_generator.py       # Generador de grafos (Etapa 1)
│   ├── tf_parser.py             # Parser robusto de Terraform usando python-hcl2
│   ├── graph_builder.py         # Enriquecimiento de nodos con metadatos precisos
│   ├── security_scanner.py      # Escáner de seguridad (Etapa 2)
│   └── correlation_engine.py    # Motor de correlación y de-duplicación (Etapa 3)
├── static/
│   └── index.html              # Frontend web (Etapa 4)
├── api.py                      # API FastAPI (Etapa 4)
├── test_infra/
│   └── main.tf                 # Proyecto de prueba
├── checkov_results.sarif/      # Reportes de seguridad (generados al ejecutar)
├── venv/                       # Entorno virtual
└── README.md
```

## Características Principales

### ✅ Parser Robusto de Terraform
- Usa `python-hcl2` (parser oficial de HCL) para parsear archivos Terraform
- Maneja correctamente casos complejos: `count`, `for_each`, bloques dinámicos, comentarios
- Extrae metadatos precisos de ubicación (archivo, línea de inicio, línea de fin)

### ✅ Correlación Precisa por Capas
- **Capa 1 (Rango de líneas + filename)**: Correlación precisa usando rangos de líneas exactos del parser y rutas absolutas normalizadas. Método más preciso.
- **Capa 2 (Filename)**: Fallback cuando no hay rango preciso, usa coincidencia por nombre de archivo.
- **Capa 3 (Semántica/CIS)**: Fallback conservador que solo asigna cuando hay un único candidato claro basado en tipo de recurso y regla CIS.

### ✅ De-duplicación Inteligente con CFI
- Identificador Canónico de Hallazgo (CFI) basado en normalización CIS
- Prioriza `partialFingerprints` de SARIF cuando están disponibles
- Elimina duplicados entre diferentes escáneres (Checkov, Trivy)

### ✅ Multi-scanner Orchestration
- Ejecuta múltiples escáneres de seguridad (Checkov, Trivy)
- Combina resultados y aplica de-duplicación inteligente
- Muestra origen de cada hallazgo en la interfaz web

## Estado del Proyecto

- ✅ **Etapa 1**: Generación y enriquecimiento de grafos implementado y funcionando
- ✅ **Etapa 2**: Análisis de seguridad multi-scanner implementado y funcionando
- ✅ **Etapa 3**: Correlación precisa y de-duplicación con CFI implementada y funcionando
- ✅ **Etapa 4**: API y frontend web implementados y funcionando

## Contribución

Este es un proyecto de TFG (Trabajo de Fin de Grado). Para contribuir, por favor contacta con el autor.

## Licencia
