# GraphSec-IaC

Una herramienta de orquestación para visualizar la seguridad en infraestructura como código (IaC).

## Descripción

GraphSec-IaC es una herramienta que combina la visualización de infraestructura con el análisis de seguridad, permitiendo correlacionar los resultados de escáneres de seguridad (como Checkov/Trivy) con la estructura de dependencias de la infraestructura generada por herramientas como Blast Radius.

## Arquitectura

El proyecto está dividido en tres etapas principales:

### Etapa 1: Generación de Grafos ✅
- **Módulo**: `modules/graph_generator.py`
- **Función**: Genera grafos de infraestructura usando `blast-radius` sobre proyectos de Terraform
- **Salida**: JSON con estructura de nodos, aristas y metadatos

### Etapa 2: Análisis de Seguridad (En desarrollo)
- **Herramientas**: Checkov, Trivy
- **Formato**: Reportes SARIF
- **Función**: Escanear infraestructura en busca de vulnerabilidades y malas configuraciones

### Etapa 3: Correlación y Visualización (Planificado)
- **Función**: Correlacionar hallazgos de seguridad con recursos de infraestructura
- **Salida**: Mapa de riesgo visual integrado

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

# Instalar Graphviz (Windows)
winget install Graphviz

# Instalar Terraform (Windows)
winget install Hashicorp.Terraform
```

## Uso

### Generar Grafo de Infraestructura

```bash
python main.py
```

Esto ejecutará el generador de grafos sobre el proyecto de prueba en `test_infra/`.

## Estructura del Proyecto

```
GraphSec-IaC/
├── modules/
│   └── graph_generator.py    # Generador de grafos
├── main.py                   # Script principal
├── test_infra/
│   └── main.tf              # Proyecto de prueba
├── venv/                    # Entorno virtual
└── README.md
```

## Estado del Proyecto

- ✅ **Etapa 1**: Generación de grafos implementada y funcionando
- 🚧 **Etapa 2**: Análisis de seguridad (en desarrollo)
- ⏳ **Etapa 3**: Correlación y visualización (planificado)

## Contribución

Este es un proyecto de TFG (Trabajo de Fin de Grado). Para contribuir, por favor contacta con el autor.

## Licencia

[Especificar licencia]
