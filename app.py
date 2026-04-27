import os
import io
import re
import sys
import json
import base64
import tempfile
import shutil
import atexit
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'parser'))
from parser import build_name_registry, collect_entities, process_links, write_prolog, collect_vulnerabilities
from filler import fill_prolog_file

from kafka import KafkaConsumer, TopicPartition
import jsonschema

import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

import networkx as nx
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from pyswip import Prolog

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024
app.config['STATIC_RULES_FILE'] = os.path.join(
    os.path.dirname(__file__), 'prolog', 'rule.p'
)
app.config['TEMP_UPLOAD_DIR'] = tempfile.mkdtemp(prefix='prolog_analyzer_')


def _cleanup_temp_dir():
    temp_dir = app.config.get('TEMP_UPLOAD_DIR')
    if temp_dir and os.path.exists(temp_dir):
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass


atexit.register(_cleanup_temp_dir)


@app.after_request
def _add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


class PrologAnalyzer:
    
    def __init__(self):
        self.prolog = None
        self.graphs = []
        self.root_graphs = {}
        self.all_facts = set()
        self.iteration_facts = {}
    
    def initialize(self, use_case_path):
        self._reset_state()
        self._cleanup_prolog_instance()
        self.prolog = Prolog()
        
        try:
            use_case_abs = os.path.abspath(use_case_path)
            
            if not os.path.exists(use_case_abs):
                return False, f"File not found: {use_case_abs}"
            
            with open(use_case_abs, 'r') as f:
                if not f.read().strip():
                    return False, "File is empty"
            
            rule_file = app.config['STATIC_RULES_FILE']
            if not os.path.exists(rule_file):
                return False, f"Static rule file not found: {rule_file}"
            
            self.prolog.consult(rule_file)
            self.prolog.consult(use_case_abs)
            self._enable_tracing()
            return True, "Prolog initialized successfully"
        
        except Exception as e:
            return False, f"Prolog init error: {str(e)}"
    
    def _reset_state(self):
        self.graphs = []
        self.root_graphs = {}
        self.all_facts = set()
        self.iteration_facts = {}
    
    def _cleanup_prolog_instance(self):
        if self.prolog:
            try:
                list(self.prolog.query("retractall(assVul(_, _))"))
                list(self.prolog.query("retractall(assComp(_, _))"))
                list(self.prolog.query("retractall(assMalfun(_, _))"))
                list(self.prolog.query("retractall(derived_from(_, _))"))
            except Exception:
                pass
            del self.prolog
    
    def _enable_tracing(self):
        try:
            list(self.prolog.query("retractall(derived_from(_, _))"))
            list(self.prolog.query("assert(trace_enabled)"))
        except Exception:
            pass
    
    def get_entities(self):
        if not self.prolog:
            return []
        
        entities = []
        try:
            results = list(self.prolog.query("digital_entity(E)"))
            for row in results:
                entity = row.get("E")
                if isinstance(entity, bytes):
                    entities.append(entity.decode())
                else:
                    value = str(entity).strip('"').strip("'")
                    entities.append(value)
        except Exception:
            pass
        
        return entities
    
    def run_inference(self):
        if not self.prolog:
            return False, "Prolog not initialized"
        
        entities = self.get_entities()
        if not entities:
            return False, "No entities found"
        
        self._reset_state()
        iteration = 0
        
        while True:
            iteration += 1
            new_facts = []
            
            for entity in entities:
                new_facts.extend(self._infer_for_entity(entity))
            
            self.all_facts.update(new_facts)
            self.iteration_facts[iteration] = {
                'facts': new_facts,
                'count': len(new_facts)
            }
            
            if not new_facts or iteration > 100:
                break
        
        self.root_graphs = self._build_root_mapping(self.graphs)
        return True, f"Inference complete: {len(self.all_facts)} facts in {iteration} iterations"
    
    def _infer_for_entity(self, entity):
        new_facts = []
        
        for predicate, query_template in [
            ('canbeVul', 'canbeVul("{}", T)'),
            ('canbeComp', 'canbeComp("{}", T)'),
            ('canbeMalfun', 'canbeMalfun("{}", M)')
        ]:
            results = list(self.prolog.query(query_template.format(entity)))
            param = 'M' if predicate == 'canbeMalfun' else 'T'
            
            for result in results:
                value = self._clean_value(result.get(param))
                assumed = f'ass{predicate[5:]}("{entity}", "{value}")'
                derived = f'{predicate}("{entity}", "{value}")'
                
                if not self._fact_exists(assumed):
                    try:
                        self.prolog.assertz(assumed)
                    except Exception:
                        pass
                    new_facts.append(derived)
                    self._build_graph_for_fact(derived)
        
        return new_facts
    
    def _build_graph_for_fact(self, fact):
        graph = nx.DiGraph()
        try:
            sources = list(self.prolog.query(f'derived_from({fact}, Sources)'))
            for source_result in sources:
                for source in source_result.get("Sources", []):
                    cleaned = self._normalize_source(source)
                    graph.add_edge(fact, cleaned)
        except Exception:
            pass
        
        if graph.nodes():
            self.graphs.append(graph)
    
    def _normalize_source(self, source):
        source = re.sub(r"b'([^']*)'", r"'\1'", source)
        source = re.sub(r'b\"([^\"]*)\"', r'\"\1\"', source)
        source = re.sub(r"'([^']*)'", r'"\1"', source)
        source = re.sub(r'\bassVul\(', 'canbeVul(', source)
        source = re.sub(r'\bassComp\(', 'canbeComp(', source)
        source = re.sub(r'\bassMalfun\(', 'canbeMalfun(', source)
        return source
    
    def _fact_exists(self, fact):
        if not self.prolog:
            return False
        try:
            return len(list(self.prolog.query(fact))) > 0
        except Exception:
            return False
    
    def _clean_value(self, value):
        if isinstance(value, bytes):
            return value.decode()
        elif isinstance(value, (list, tuple)):
            return "[" + ", ".join(self._clean_value(v) for v in value) + "]"
        else:
            return str(value)
    
    def _build_root_mapping(self, graphs):
        mapping = {}
        for graph in graphs:
            if graph.nodes():
                root = list(graph.nodes())[0]
                mapping[root] = graph
        return mapping
    
    def match_roots(self, pattern):
        regex_pattern = (
            pattern.replace("(", r"\(")
                   .replace(")", r"\)")
                   .replace(",", r",")
                   .replace("X", ".*")
                   .replace("_", ".*")
        )
        regex = re.compile(f"^{regex_pattern}$")
        return [root for root in self.root_graphs if regex.match(root)]
    
    def expand_graph(self, root, visited=None, global_graph=None):
        if visited is None:
            visited = set()
        if global_graph is None:
            global_graph = nx.DiGraph()
        
        if root in visited or root not in self.root_graphs:
            return global_graph
        
        visited.add(root)
        sub = self.root_graphs[root]
        global_graph.add_nodes_from(sub.nodes(data=True))
        global_graph.add_edges_from(sub.edges())
        
        for node in sub.nodes():
            if node in self.root_graphs and node not in visited:
                self.expand_graph(node, visited, global_graph)
        
        return global_graph
    
    def visualize_graph(self, graph):
        if not graph.nodes():
            return None
        
        try:
            fig, ax = plt.subplots(figsize=(30, 20), dpi=250, facecolor='#0a0a0f')
            ax.set_facecolor('#0a0a0f')
            
            try:
                pos = nx.nx_agraph.graphviz_layout(graph, prog='dot')
            except Exception:
                pos = nx.spring_layout(graph, k=4, iterations=100, seed=42, scale=3)
            
            x_coords = [pos[node][0] for node in graph.nodes()]
            y_coords = [pos[node][1] for node in graph.nodes()]
            x_range = max(x_coords) - min(x_coords) if len(x_coords) > 1 else 100
            y_range = max(y_coords) - min(y_coords) if len(y_coords) > 1 else 100
            
            base_width = x_range * 0.12
            base_height = y_range * 0.05
            
            labels = {}
            node_sizes = {}
            
            for node in graph.nodes():
                label_text = str(node)
                labels[node] = label_text
                text_len = len(label_text)
                width = base_width * max(1.2, text_len / 25.0)
                height = base_height * 1.5
                node_sizes[node] = (width, height)
            
            node_colors = ['#8b5cf6', '#a78bfa', '#c084fc', '#e879f9'] * (len(graph.nodes()) // 4 + 1)
            
            for idx, node in enumerate(graph.nodes()):
                x, y = pos[node]
                width, height = node_sizes[node]
                
                rect = mpatches.FancyBboxPatch(
                    (x - width / 2, y - height / 2), width, height,
                    boxstyle="round,pad=0.02,rounding_size=0.1",
                    linewidth=3,
                    edgecolor='#6366f1',
                    facecolor=node_colors[idx % len(node_colors)],
                    alpha=0.92,
                    zorder=2
                )
                ax.add_patch(rect)
            
            for node, label in labels.items():
                x, y = pos[node]
                ax.text(x, y, label, fontsize=11, fontweight='600', fontfamily='DejaVu Sans',
                       color='#ffffff', verticalalignment='center', horizontalalignment='center', zorder=3)
            
            reversed_edges = [(v, u) for (u, v) in graph.edges()]
            reversed_graph = nx.DiGraph()
            reversed_graph.add_edges_from(reversed_edges)
            
            nx.draw_networkx_edges(
                reversed_graph, pos, ax=ax,
                edge_color='#a78bfa',
                width=3,
                arrowsize=30,
                arrowstyle='-|>',
                connectionstyle='arc3,rad=0.15',
                alpha=0.7,
                node_size=0
            )
            
            ax.set_title(
                f"Attack Path Graph\n{len(graph.nodes())} nodes • {len(graph.edges())} edges",
                fontsize=20, fontweight='bold', color='#e879f9', pad=25
            )
            ax.axis('off')
            
            ax.set_xlim(min(x_coords) - base_width * 2, max(x_coords) + base_width * 2)
            ax.set_ylim(min(y_coords) - base_height * 2, max(y_coords) + base_height * 2)
            
            plt.tight_layout(pad=2)
            
            img = io.BytesIO()
            FigureCanvas(fig).print_png(img)
            img.seek(0)
            img_base64 = base64.b64encode(img.getvalue()).decode()
            plt.close(fig)
            
            return img_base64
        except Exception:
            return None


analyzer = PrologAnalyzer()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/upload', methods=['POST', 'OPTIONS'])
def upload_files():
    if request.method == 'OPTIONS':
        return '', 200
    
    if 'use_case' not in request.files:
        return jsonify({'success': False, 'message': 'use_case.p file required'}), 400
    
    use_case_file = request.files['use_case']
    
    if not use_case_file.filename:
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    try:
        filename = secure_filename(use_case_file.filename)
        temp_dir = app.config['TEMP_UPLOAD_DIR']
        filepath = os.path.join(temp_dir, filename)
        use_case_file.save(filepath)
        
        success, message = analyzer.initialize(filepath)
        
        if not success:
            try:
                os.remove(filepath)
            except Exception:
                pass
            return jsonify({'success': False, 'message': message}), 400
        
        entities = analyzer.get_entities()
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'entities': entities
        }), 200
    
    except Exception as e:
        return jsonify({'success': False, 'message': f"Upload error: {str(e)}"}), 500


KAFKA_BROKERS = [
    'kafka-broker-0.sph.svc.cluster.local:9092',
    'kafka-broker-1.sph.svc.cluster.local:9092',
    'kafka-broker-2.sph.svc.cluster.local:9092',
]
KAFKA_TOPIC = 'ctxd'
KAFKA_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'schemas', 'ctxd-v2.0.json')
THREAT_CORRELATOR_URL = 'https://threat-correlator.intra.miranda.onesource.pt'
KAFKA_LOOKBACK = 5  # max messages to scan backwards per partition

with open(KAFKA_SCHEMA_PATH, encoding='utf-8') as _f:
    _CTXD_SCHEMA = json.load(_f)


def _matches_ctxd_schema(raw_bytes):
    try:
        data = json.loads(raw_bytes)
    except (json.JSONDecodeError, ValueError):
        return None
    try:
        jsonschema.validate(instance=data, schema=_CTXD_SCHEMA)
        return data
    except jsonschema.ValidationError:
        return None


def _fetch_latest_kafka_message(brokers, topic, timeout_ms=15000):
    consumer = KafkaConsumer(
        bootstrap_servers=brokers,
        security_protocol='PLAINTEXT',
        consumer_timeout_ms=timeout_ms,
        auto_offset_reset='earliest',
        enable_auto_commit=False,
    )
    try:
        partition_ids = consumer.partitions_for_topic(topic)
        if not partition_ids:
            raise RuntimeError(f"Topic '{topic}' not found or has no partitions")

        tps = [TopicPartition(topic, p) for p in partition_ids]
        consumer.assign(tps)
        consumer.seek_to_end(*tps)

        windows = {}
        for tp in tps:
            end = consumer.position(tp)
            if end > 0:
                consumer.seek(tp, max(0, end - KAFKA_LOOKBACK))
                windows[tp.partition] = end

        if not windows:
            raise RuntimeError(f"Topic '{topic}' exists but contains no messages")

        bucket: dict[int, list] = {p: [] for p in windows}
        for msg in consumer:
            if msg.partition in windows and msg.offset < windows[msg.partition]:
                bucket[msg.partition].append(msg)

        candidates = sorted(
            [m for msgs in bucket.values() for m in msgs],
            key=lambda m: m.offset,
            reverse=True,
        )

        for msg in candidates:
            data = _matches_ctxd_schema(msg.value)
            if data is not None:
                return data

        raise RuntimeError(
            f"No ctxd-v2.0-conforming message found in the last {KAFKA_LOOKBACK} "
            f"messages of topic '{topic}'"
        )
    finally:
        consumer.close()


@app.route('/api/fetch-kafka', methods=['POST', 'OPTIONS'])
def fetch_kafka():
    if request.method == 'OPTIONS':
        return '', 200

    try:
        scg = _fetch_latest_kafka_message(KAFKA_BROKERS, KAFKA_TOPIC)
    except Exception as e:
        return jsonify({'success': False, 'message': f'Kafka error: {str(e)}'}), 502

    return jsonify({'success': True, 'scg': scg}), 200


@app.route('/api/enrich-scg', methods=['POST', 'OPTIONS'])
def enrich_scg():
    if request.method == 'OPTIONS':
        return '', 200

    scg = request.get_json(silent=True)
    if not scg:
        return jsonify({'success': False, 'message': 'Request body must be a JSON SCG'}), 400

    creator = scg.get('creator')
    if not creator:
        return jsonify({'success': False, 'message': 'SCG missing creator field'}), 400

    # Step 1: retrieve existing graph_ids from Threat Correlator
    try:
        resp = requests.get(f'{THREAT_CORRELATOR_URL}/neo4j/graphs', timeout=30)
        resp.raise_for_status()
        graph_ids = [g['graph_id'] for g in resp.json().get('graphs', [])]
    except Exception as e:
        return jsonify({'success': False, 'message': f'Threat Correlator error (list graphs): {str(e)}'}), 502

    graph_id = creator

    if creator not in graph_ids:
        # Step 2: ingest SCG
        try:
            resp = requests.post(f'{THREAT_CORRELATOR_URL}/neo4j/graphs', json=scg, timeout=60)
            resp.raise_for_status()
            graph_id = resp.json()['graph_id']
        except Exception as e:
            return jsonify({'success': False, 'message': f'Threat Correlator error (ingest): {str(e)}'}), 502

        # Step 3: trigger vulnerability enrichment
        try:
            resp = requests.post(
                f'{THREAT_CORRELATOR_URL}/events/graph',
                json={'event': 'graph.updated', 'graph_id': graph_id},
                timeout=120
            )
            resp.raise_for_status()
        except Exception as e:
            return jsonify({'success': False, 'message': f'Threat Correlator error (enrich): {str(e)}'}), 502

    # Step 4: retrieve enriched SCG
    try:
        # TODO: GET /api/... — replace with exact endpoint to retrieve enriched SCG by graph_id
        resp = requests.get(f'{THREAT_CORRELATOR_URL}/neo4j/graph/{graph_id}/vulnerabilities', timeout=30)
        resp.raise_for_status()
        enriched_scg = resp.json()
    except Exception as e:
        return jsonify({'success': False, 'message': f'Threat Correlator error (retrieve): {str(e)}'}), 502

    return jsonify({'success': True, 'scg': enriched_scg}), 200


@app.route('/api/parse-json', methods=['POST', 'OPTIONS'])
def parse_json():
    if request.method == 'OPTIONS':
        return '', 200

    if 'json_file' not in request.files:
        return jsonify({'success': False, 'message': 'json_file required'}), 400

    json_file = request.files['json_file']
    if not json_file.filename:
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    try:
        data = json.load(json_file)
    except json.JSONDecodeError as e:
        return jsonify({'success': False, 'message': f'Invalid JSON: {e}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Read error: {e}'}), 400

    try:
        services = data.get('services', [])
        links = data.get('links', [])
        service_vulns = data.get('service_vulnerabilities', [])

        registry = build_name_registry(services, links)
        entity_ids, _ = collect_entities(services, registry)
        relations = process_links(links, registry)
        vulnerabilities, exposed_pairs = collect_vulnerabilities(service_vulns, registry)

        temp_dir = app.config['TEMP_UPLOAD_DIR']
        base_name = secure_filename(json_file.filename or 'parsed')
        if base_name.endswith('.json'):
            base_name = base_name[:-5]
        prolog_path = os.path.join(temp_dir, base_name + '.p')

        with open(prolog_path, 'w', encoding='utf-8') as out:
            write_prolog(out, json_file.filename, entity_ids, relations,
                         load_rule=False, vulnerabilities=vulnerabilities,
                         exposed_pairs=exposed_pairs)

        fill_prolog_file(prolog_path, prolog_path)

        success, message = analyzer.initialize(prolog_path)
        if not success:
            return jsonify({'success': False, 'message': message}), 400

        entities = analyzer.get_entities()
        return jsonify({
            'success': True,
            'message': f'Parsed {len(entity_ids)} entities, {len(relations["contains"])} containment, '
                       f'{len(relations["controls"])} control, {len(relations["connects"])} connection, '
                       f'{len(exposed_pairs)} exposed facts',
            'entities': entities
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f'Parse error: {str(e)}'}), 500


@app.route('/api/run-inference', methods=['POST'])
def run_inference():
    if not analyzer.prolog:
        return jsonify({'success': False, 'message': 'Initialize first'}), 400
    
    success, message = analyzer.run_inference()
    return jsonify({
        'success': success,
        'message': message,
        'total_facts': len(analyzer.all_facts) if success else 0,
        'total_roots': len(analyzer.root_graphs) if success else 0
    })


def _build_single_root_graph(root):
    merged_graph = nx.DiGraph()
    visited = set()
    analyzer.expand_graph(root, visited, merged_graph)
    img_base64 = analyzer.visualize_graph(merged_graph)
    graph_data = nx.node_link_data(merged_graph)
    return merged_graph, img_base64, graph_data


def _get_matching_roots(pattern_str):
    pattern = pattern_str.strip()
    if not pattern:
        return None, (jsonify({'success': False, 'message': 'Pattern required'}), 400)
    matching_roots = analyzer.match_roots(pattern)
    if not matching_roots:
        return None, (jsonify({'success': False, 'message': f'No roots match pattern: {pattern}'}), 404)
    return matching_roots, None


@app.route('/api/search', methods=['POST'])
def search_pattern():
    if not analyzer.prolog:
        return jsonify({'success': False, 'message': 'Please upload files first'}), 400
    
    data = request.get_json()
    matching_roots, error = _get_matching_roots(data.get('pattern', ''))
    
    if error:
        return error
    
    return jsonify({
        'success': True,
        'matching_roots': matching_roots,
        'count': len(matching_roots)
    })


@app.route('/api/visualize-root', methods=['POST'])
def visualize_root():
    if not analyzer.prolog:
        return jsonify({'success': False, 'message': 'Please upload files first'}), 400
    
    data = request.get_json()
    root = data.get('root', '').strip()
    
    if not root:
        return jsonify({'success': False, 'message': 'Root required'}), 400
    
    if root not in analyzer.root_graphs:
        return jsonify({'success': False, 'message': f'Root not found: {root}'}), 404
    
    merged_graph, img_base64, graph_data = _build_single_root_graph(root)
    
    if not img_base64:
        return jsonify({'success': False, 'message': 'Failed to generate graph image'}), 500
    
    return jsonify({
        'success': True,
        'root': root,
        'node_count': len(merged_graph.nodes()),
        'edge_count': len(merged_graph.edges()),
        'graph_image': img_base64,
        'graph_data': graph_data
    })


@app.route('/api/expand-graph', methods=['POST'])
def expand_graph_route():
    if not analyzer.prolog:
        return jsonify({'success': False, 'message': 'Please upload files first'}), 400
    
    data = request.get_json()
    matching_roots, error = _get_matching_roots(data.get('pattern', ''))
    
    if error:
        return error
    
    merged_forest = nx.DiGraph()
    for root in matching_roots:
        visited = set()
        analyzer.expand_graph(root, visited, merged_forest)
    
    img_base64 = analyzer.visualize_graph(merged_forest)
    graph_data = nx.node_link_data(merged_forest)
    
    return jsonify({
        'success': True,
        'matching_count': len(matching_roots),
        'node_count': len(merged_forest.nodes()),
        'edge_count': len(merged_forest.edges()),
        'graph_image': img_base64,
        'graph_data': graph_data
    })


@app.route('/api/facts-list', methods=['GET'])
def facts_list():
    if not analyzer.prolog:
        return jsonify({'success': False, 'message': 'Run inference first'}), 400
    
    vulns = [f for f in analyzer.all_facts if 'canbeVul' in f]
    comps = [f for f in analyzer.all_facts if 'canbeComp' in f]
    malfuns = [f for f in analyzer.all_facts if 'canbeMalfun' in f]
    
    return jsonify({
        'success': True,
        'total_facts': len(analyzer.all_facts),
        'vulnerabilities': sorted(vulns),
        'compromises': sorted(comps),
        'malfunctions': sorted(malfuns),
        'iterations': analyzer.iteration_facts,
        'roots': list(analyzer.root_graphs.keys())
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
