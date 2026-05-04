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
├── app.py                          # Flask backend with Prolog engine
├── requirements.txt                # Python dependencies
├── Dockerfile                      # Docker container definition
├── docker-compose.yml              # Docker Compose orchestration
├── setup.sh                        # Setup verification script
├── start.sh                        # Application startup script
├── parser/
│   ├── parser.py                   # ctxd-v2.0 JSON → Prolog converter
│   └── filler.py                   # 5G attack-scenario knowledge base appender
├── prolog/
│   ├── rule.p                      # Formal derivation rules
│   └── examples/                   # Sample Knowledge Base files
├── data/
│   ├── schemas/
│   │   └── ctxd-v2.0.json          # ctxd-v2.0 JSON schema
│   ├── samples/                    # Example JSON inputs
│   ├── output_threat_correlator.json
│   └── generated.p                 # Parser + filler output
├── static/
│   ├── script.js                   # Frontend interaction logic
│   └── style.css                   # Styling
└── templates/
    └── index.html                  # Web interface
```

## API Endpoints

- `POST /api/upload` - Upload a Prolog Knowledge Base file (.p)
- `POST /api/parse-json` - Upload a ctxd-v2.0 JSON file, parse it into a KB, and load it
- `POST /api/fetch-kafka` - Fetch the latest ctxd-v2.0-conforming message from Kafka and load it
- `POST /api/run-inference` - Execute the inference engine on the loaded KB
- `GET  /api/facts-list` - Retrieve all derived facts
- `POST /api/search` - Retrieve derived facts matching a pattern
- `POST /api/expand-graph` - Visualize the forest of derivation paths matching a pattern
- `POST /api/visualize-root` - Visualize the derivation path for a specific fact

## Usage

### Using the Web GUI

Once the application is running, navigate to it in your browser:

- **Local / Docker installation:** `http://localhost:5001`
- **Inside the OneSource VPN:** `http://attack-threat-modeling.intra.miranda.onesource.pt/`

**Step 1 — Load a Knowledge Base**

The landing page presents two input modes:

- **Prolog File (.p)** — select this tab, then click *Browse* (or drag-and-drop) to upload a `.p` Knowledge Base file directly.
- **SCG (.json)** — select this tab to load a ctxd-v2.0 JSON file. Either click *Browse* to upload a local file, or click **Fetch from Kafka** to pull the latest conforming message from the configured Kafka topic, enrich it via the Threat Correlator, and parse it into a Knowledge Base — all automatically.

Click **Analyze Paths** to upload and initialize the inference engine.

**Step 2 — Inspect derived facts**

After a successful upload, the main analysis view opens. The left sidebar lists all facts derived by the inference engine, organized into three tabs:

| Tab | Contents |
|-----|----------|
| **Vulns** | `canbeVul` facts — potential vulnerabilities |
| **Comps** | `canbeComp` facts — possible compromissions |
| **Malfun** | `canbeMalfun` facts — malfunctioning conditions |

Click any fact to render its full attack path graph in the central canvas.

**Step 3 — Query and explore**

Click the **Search** button (top-right) to open the query modal. Enter a Prolog-style pattern (e.g. `canbeVul(E, V)`, using `X` or `_` as wildcards) and click **Execute Query**. The panel returns all matching facts; clicking one renders the corresponding derivation graph beneath the results.

To load a different Knowledge Base, click **Upload New** (top-right) to return to the landing page.

---

### Using the API

All endpoints are served at the base URL for your environment:

- **Local / Docker:** `http://localhost:5001`
- **OneSource VPN:** `http://attack-threat-modeling.intra.miranda.onesource.pt/`

The typical workflow is: **load a KB → run inference → query results / retrieve graphs**.

#### 1. Load a Knowledge Base

There are three ways to load a KB, depending on how your input is available.

---

**Option A — Upload a Prolog KB directly**

Use this when you already have a `.p` Knowledge Base file:

```http
POST /api/upload
Content-Type: multipart/form-data

use_case=<path/to/kb.p>
```

Returns `{ "success": true, "message": "...", "entities": [...] }`.

---

**Option B — Upload an SCG JSON file**

Use this when you have a ctxd-v2.0 JSON file that already contains vulnerability information. The file is parsed and converted to a Prolog KB automatically:

```http
POST /api/parse-json
Content-Type: multipart/form-data

json_file=<path/to/scg.json>
```

Returns `{ "success": true, "message": "...", "entities": [...] }`.

---

**Option C — Fetch from Kafka, enrich, then parse**

Use this to load the SCG fully automatically. The plain SCG fetched from Kafka does not contain vulnerability information yet, so it must be enriched first before parsing. Execute the three steps in sequence:

```http
# Step 1 — fetch the latest ctxd-v2.0 message from Kafka (no request body)
POST /api/fetch-kafka
```

Returns `{ "success": true, "scg": { <plain SCG> } }`.

```http
# Step 2 — enrich the SCG with vulnerability information via the Threat Correlator
POST /api/enrich-scg
Content-Type: application/json

<scg object from Step 1>
```

Returns `{ "success": true, "scg": { <enriched SCG> } }`.

```http
# Step 3 — parse the enriched SCG into a Knowledge Base (same as Option B)
POST /api/parse-json
Content-Type: multipart/form-data

json_file=<enriched SCG from Step 2, saved as a .json file>
```

Returns `{ "success": true, "message": "...", "entities": [...] }`.

---

#### 2. Run inference

```http
POST /api/run-inference
```

No request body required. Returns:

```json
{ "success": true, "message": "Inference complete: N facts in K iterations", "total_facts": N, "total_roots": M }
```

#### 3. Retrieve all derived facts

```http
GET /api/facts-list
```

Returns all derived facts grouped by type, the per-iteration breakdown, and the list of graph roots:

```json
{
  "success": true,
  "total_facts": N,
  "vulnerabilities": ["canbeVul(\"e\", \"v\")", ...],
  "compromises":     ["canbeComp(\"e\", \"c\")", ...],
  "malfunctions":    ["canbeMalfun(\"e\", \"m\")", ...],
  "iterations":      { "1": { "facts": [...], "count": K }, ... },
  "roots":           ["canbeVul(\"e\", \"v\")", ...]
}
```

#### 4. Search for matching roots

```http
POST /api/search
Content-Type: application/json

{ "pattern": "canbeVul(X, _)" }
```

`X` and `_` act as wildcards. Returns:

```json
{ "success": true, "matching_roots": ["canbeVul(\"e\", \"v\")", ...], "count": N }
```

#### 5. Visualize an attack path graph

For a **specific root fact**:

```http
POST /api/visualize-root
Content-Type: application/json

{ "root": "canbeVul(\"entity_name\", \"vuln_type\")" }
```

For a **pattern** (returns the merged forest of all matching derivation graphs):

```http
POST /api/expand-graph
Content-Type: application/json

{ "pattern": "canbeVul(X, _)" }
```

Both endpoints return:

```json
{
  "success": true,
  "node_count": N,
  "edge_count": M,
  "graph_image": "<base64-encoded PNG>",
  "graph_data": { <NetworkX node-link JSON> }
}
```

