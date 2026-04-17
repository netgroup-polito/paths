# PATHS
## High Level Overview
PATHS (Progressive Analysis of Threats in Hybrid Systems) is a formal framework for modeling and analyzing security threats in hybrid systems. The framework provides:
- A formal threat model that represents system behavior, assets, and security relationships through structured entities and relations.
- An automated analysis engine that evaluates the model by repeatedly applying formal derivation rules, producing a systematic assessment of the security properties of each system component.

## Inputs and Outputs
The PATHS Threat Analysis tool processes the **Knowledge Base** (KB) file as input. The KB is a Prolog file containing the formal description of the system’s architecture, components, and relevant security relationships, and must be written using the syntax and constructs defined by the PATHS Threat Model.
After loading the KB, the Threat Analysis tool iteratively applies a set of formal derivation rules. At each iteration, the tool:
- derives new security properties for each entity, covering *Vulnerability*, *Compromission*, and *Malfunctioning*;
- updates the Knowledge Base with the newly derived facts;
- constructs a *local* derivation graph for each new fact.

This inference cycle terminates when no additional facts can be derived. At that point, the tool outputs the complete set of derived facts.

In addition, users may request the generation of an Attack Path Graph:
- For a specific fact, the tool constructs a global derivation graph by recursively combining all the local graphs contributing to that fact.
- For a set of facts specified via a regex, the tool finds all matching graph roots and returns a forest of derivation graphs, each built by recursively combining the relevant local graphs.

The graphs are returned as directed NetworkX graphs composed of nodes and edges. The root of each graph corresponds to the derived fact, and it is connected to all other nodes that represent the sources contributing to the derivation of that fact.
When using the provided GUI, the graphs are visually rendered with Cytoscape.

## Project Structure

```
.
├── app.py                 # Flask backend with Prolog engine
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Docker Compose orchestration
├── setup.sh             # Setup verification script
├── start.sh             # Application startup script
├── static/
│   ├── script.js        # Frontend interaction logic
│   ├── style.css        # Styling
│   └── prolog_files/    # Prolog derivation rules and example of KB
└── templates/
    └── index.html       # Web interface
```

## API Endpoints

- `POST /api/upload` - Upload Knowledge Base file
- `POST /api/run-inference` - Execute inference engine
- `GET /api/facts-list` - Retrieve all derived facts
- `POST /api/search` - Retrieve derived facts matching the pattern
- `POST /api/expand-graph` - Visualize forest of paths matching the pattern
- `POST /api/visualize-root` - Visualize specific fact path

## Usage 
### Option 1: Docker 

**Prerequisites:** Docker and Docker Compose

```bash
docker-compose up --build
```

Visit `http://localhost:5001` in your browser.

### Option 2: Local Installation

**Prerequisites:** Python 3, SWI-Prolog, Graphviz

```bash
./setup.sh
./start.sh
```

Visit `http://localhost:5001` in your browser.



