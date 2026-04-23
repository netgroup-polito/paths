let allFacts = [];
let uploadBtn, useCase, uploadStatus, reloadBtn;
let uploadMode = 'prolog';

function initializePage() {
    uploadBtn = document.getElementById('upload_btn');
    useCase = document.getElementById('use_case_file');
    uploadStatus = document.getElementById('upload_status');
    reloadBtn = document.getElementById('reload_btn');

    if (!uploadBtn || !useCase) return;

    attachEventListeners();
}

function attachEventListeners() {
    if (useCase) useCase.addEventListener('change', handleFileInputChange);
    if (uploadBtn) uploadBtn.addEventListener('click', handleUploadClick);
    setupReloadButton();
    setupModeToggle();
}

function setupModeToggle() {
    const prologBtn = document.getElementById('mode_prolog_btn');
    const jsonBtn = document.getElementById('mode_json_btn');
    const prologGroup = document.getElementById('prolog_input_group');
    const jsonGroup = document.getElementById('json_input_group');
    const jsonFileInput = document.getElementById('json_file');

    if (!prologBtn || !jsonBtn) return;

    prologBtn.addEventListener('click', () => {
        uploadMode = 'prolog';
        prologBtn.style.background = 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)';
        prologBtn.style.border = 'none';
        jsonBtn.style.background = 'rgba(30,30,45,0.6)';
        jsonBtn.style.border = '1px solid #4b5563';
        prologGroup.style.display = '';
        jsonGroup.style.display = 'none';
    });

    jsonBtn.addEventListener('click', () => {
        uploadMode = 'json';
        jsonBtn.style.background = 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)';
        jsonBtn.style.border = 'none';
        prologBtn.style.background = 'rgba(30,30,45,0.6)';
        prologBtn.style.border = '1px solid #4b5563';
        jsonGroup.style.display = '';
        prologGroup.style.display = 'none';
    });

    if (jsonFileInput) {
        jsonFileInput.addEventListener('change', (e) => {
            const fileName = e.target.files[0]?.name;
            const label = document.getElementById('json_file_label');
            const nameEl = document.getElementById('json_file_name');
            const placeholderEl = document.getElementById('json_file_placeholder');
            if (fileName) {
                if (label) label.classList.add('has-file');
                if (nameEl) { nameEl.textContent = fileName; nameEl.style.display = 'block'; }
                if (placeholderEl) placeholderEl.style.display = 'none';
            } else {
                if (label) label.classList.remove('has-file');
                if (nameEl) nameEl.style.display = 'none';
                if (placeholderEl) placeholderEl.style.display = 'block';
            }
        });
    }

    const kafkaBtn = document.getElementById('kafka_btn');
    if (kafkaBtn) {
        kafkaBtn.addEventListener('click', handleKafkaFetch);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializePage);
} else {
    initializePage();
}

function handleFileInputChange(e) {
    const fileName = e.target.files[0]?.name;
    const label = document.getElementById('use_case_label');
    const nameEl = document.getElementById('use_case_name');
    const placeholderEl = document.getElementById('use_case_placeholder');
    
    if (fileName) {
        if (label) label.classList.add('has-file');
        if (nameEl) {
            nameEl.textContent = fileName;
            nameEl.style.display = 'block';
        }
        if (placeholderEl) placeholderEl.style.display = 'none';
    } else {
        if (label) label.classList.remove('has-file');
        if (nameEl) nameEl.style.display = 'none';
        if (placeholderEl) placeholderEl.style.display = 'block';
    }
}

function showStatus(elementId, message, type) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = `status show ${type}`;
    if (type === 'success') {
        setTimeout(() => element.classList.remove('show'), 5001);
    }
}

function showLoading(elementId, message) {
    const element = document.getElementById(elementId);
    element.innerHTML = `<div style="display: flex; align-items: center; justify-content: center; gap: 12px; color: #ffffff; font-weight: 500;">
        <span class="loading-spinner"></span>
        <span>${message}</span>
    </div>`;
    element.className = 'status show info';
}

function clearStatus(elementId) {
    const element = document.getElementById(elementId);
    element.textContent = '';
    element.className = 'status';
}

function setupReloadButton() {
    const btn = document.getElementById('reload_btn');
    if (!btn) return;
    
    btn.addEventListener('click', () => {
        const useCaseInput = document.getElementById('use_case_file');
        const uploadStatusEl = document.getElementById('upload_status');
        
        document.getElementById('upload_page').style.display = 'flex';
        document.getElementById('main_page').style.display = 'none';
        
        if (useCaseInput) useCaseInput.value = '';
        const useCaseLabel = document.getElementById('use_case_label');
        if (useCaseLabel) useCaseLabel.classList.remove('has-file');
        const useCaseName = document.getElementById('use_case_name');
        if (useCaseName) useCaseName.style.display = 'none';
        const useCasePlaceholder = document.getElementById('use_case_placeholder');
        if (useCasePlaceholder) useCasePlaceholder.style.display = 'block';

        const jsonInput = document.getElementById('json_file');
        if (jsonInput) jsonInput.value = '';
        const jsonLabel = document.getElementById('json_file_label');
        if (jsonLabel) jsonLabel.classList.remove('has-file');
        const jsonName = document.getElementById('json_file_name');
        if (jsonName) jsonName.style.display = 'none';
        const jsonPlaceholder = document.getElementById('json_file_placeholder');
        if (jsonPlaceholder) jsonPlaceholder.style.display = 'block';

        if (uploadStatusEl) uploadStatusEl.innerHTML = '';
        
        document.getElementById('vuln_list').innerHTML = '';
        document.getElementById('comp_list').innerHTML = '';
        document.getElementById('mal_list').innerHTML = '';
        
        document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
            const tabName = btn.getAttribute('data-tab');
            if (idx === 0) {
                btn.innerHTML = 'Vulns';
                btn.style.background = 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)';
                btn.style.color = 'white';
                btn.style.border = 'none';
            } else {
                const tabLabels = {
                    'compromises': 'Comps',
                    'malfunctions': 'Malfun'
                };
                btn.innerHTML = tabLabels[tabName] || tabName;
                btn.style.background = 'rgba(30, 30, 45, 0.5)';
                btn.style.color = '#94a3b8';
                btn.style.border = 'none';
            }
        });
        
        document.getElementById('graph_area').innerHTML = `
            <div style="text-align: center; color: #64748b;">
                <p style="font-size: 18px; margin: 0;">No facts found</p>
            </div>
        `;
        document.getElementById('graph_status').innerHTML = '';
        
        document.getElementById('vuln_list').style.display = 'block';
        document.getElementById('comp_list').style.display = 'none';
        document.getElementById('mal_list').style.display = 'none';
    });
}

async function visualizeFact(factRoot) {
    const graphArea = document.getElementById('graph_area');
    const graphStatus = document.getElementById('graph_status');
    
    if (!factRoot) {
        graphStatus.textContent = 'No fact selected';
        return;
    }
    
    graphStatus.textContent = 'Loading graph...';
    
    try {
        const response = await fetch('/api/visualize-root', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ root: factRoot })
        });
        
        const result = await response.json();
        
        if (result.success && result.graph_data) {
            graphArea.innerHTML = `
                <div style="position: relative; width: 100%; height: 100%;">
                    <div id="cy" style="width: 100%; height: 100%; background: #0a0a0f;"></div>
                    <div style="position: absolute; top: 16px; right: 16px; z-index: 10; display: flex; gap: 8px;">
                        <button id="zoom-fit-btn" class="zoom-btn" title="Fit to view">⊞</button>
                        <button id="zoom-in-btn" class="zoom-btn" title="Zoom in">+</button>
                        <button id="zoom-out-btn" class="zoom-btn" title="Zoom out">−</button>
                    </div>
                </div>
            `;
            graphStatus.innerHTML = `<strong>${factRoot}</strong> - Nodes: ${result.node_count}, Edges: ${result.edge_count}`;
            
            if (typeof CosBilkent !== 'undefined') {
                cytoscape.use(CosBilkent);
            }
            
            const graphElements = convertGraphToElements(result.graph_data, factRoot);
            
            const cy = cytoscape({
                container: document.getElementById('cy'),
                elements: graphElements,
                style: getGraphStyle(),
                layout: {
                    name: typeof CosBilkent !== 'undefined' ? 'cose-bilkent' : 'breadthfirst',
                    directed: true,
                    animate: true,
                    animationDuration: 500,
                    nodeSeparation: 200,
                    edgeLengthVal: 250,
                    nestingFactor: 0.1,
                    randomize: false
                }
            });
            
            document.getElementById('zoom-fit-btn').addEventListener('click', () => cy.fit(cy.elements(), 40));
            document.getElementById('zoom-in-btn').addEventListener('click', () => cy.zoom(cy.zoom() * 1.2));
            document.getElementById('zoom-out-btn').addEventListener('click', () => cy.zoom(cy.zoom() / 1.2));
            
            cy.on('grab', 'node', (event) => event.target.style('opacity', 0.8));
            cy.on('free', 'node', (event) => event.target.style('opacity', 1));
            
            setTimeout(() => cy.fit(cy.elements(), 40), 100);
        } else {
            graphStatus.textContent = `Error: ${result.message || 'Failed to generate graph'}`;
        }
    } catch (error) {
        graphStatus.textContent = `Error: ${error.message}`;
    }
}

async function handleUploadClick() {
    if (uploadMode === 'json') {
        await handleJsonUploadClick();
        return;
    }

    if (!useCase || !useCase.files[0]) {
        showStatus('upload_status', 'Please select use_case.p file', 'error');
        return;
    }

    uploadBtn.disabled = true;
    showLoading('upload_status', 'Uploading files...');

    _resetUI();

    const formData = new FormData();
    formData.append('use_case', useCase.files[0]);

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            showLoading('upload_status', 'Files uploaded successfully! Running inference...');
            allFacts = result.entities || [];
            
            const inferenceResponse = await fetch('/api/run-inference', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ trace: false })
            });
            
            if (!inferenceResponse.ok) {
                const errorData = await inferenceResponse.json();
                showStatus('upload_status', `Inference failed: ${errorData.message || 'Unknown error'}`, 'error');
                uploadBtn.disabled = false;
                return;
            }
            
            const inferenceResult = await inferenceResponse.json();
            
            if (inferenceResult.success) {
                const factsResponse = await fetch('/api/facts-list');
                
                if (!factsResponse.ok) {
                    const errorData = await factsResponse.json();
                    showStatus('upload_status', `Failed to fetch facts: ${errorData.message || 'Unknown error'}`, 'error');
                    uploadBtn.disabled = false;
                    return;
                }
                
                const factsData = await factsResponse.json();
                
                if (factsData.success) {
                    _populateFactLists(factsData);
                    
                    setTimeout(() => {
                        document.getElementById('upload_page').style.display = 'none';
                        document.getElementById('main_page').style.display = 'flex';
                    }, 500);
                    
                    clearStatus('upload_status');
                } else {
                    showStatus('upload_status', `Facts error: ${factsData.message || 'Unknown error'}`, 'error');
                }
            } else {
                showStatus('upload_status', `Inference error: ${inferenceResult.message}`, 'error');
            }
        } else {
            showStatus('upload_status', `Error: ${result.message}`, 'error');
        }
    } catch (error) {
        showStatus('upload_status', `Upload failed: ${error.message}`, 'error');
    } finally {
        uploadBtn.disabled = false;
    }
}

async function handleKafkaFetch() {
    uploadBtn.disabled = true;
    const kafkaBtn = document.getElementById('kafka_btn');
    if (kafkaBtn) kafkaBtn.disabled = true;

    showLoading('upload_status', 'Connecting to Kafka and fetching latest SCG…');
    _resetUI();

    try {
        const response = await fetch('/api/fetch-kafka', { method: 'POST' });
        const result = await response.json();

        if (!result.success) {
            showStatus('upload_status', `Error: ${result.message}`, 'error');
            return;
        }

        showLoading('upload_status', `${result.message} — Running inference…`);
        allFacts = result.entities || [];

        const inferenceResponse = await fetch('/api/run-inference', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ trace: false })
        });

        if (!inferenceResponse.ok) {
            const errorData = await inferenceResponse.json();
            showStatus('upload_status', `Inference failed: ${errorData.message || 'Unknown error'}`, 'error');
            return;
        }

        const inferenceResult = await inferenceResponse.json();

        if (!inferenceResult.success) {
            showStatus('upload_status', `Inference error: ${inferenceResult.message}`, 'error');
            return;
        }

        const factsResponse = await fetch('/api/facts-list');
        const factsData = await factsResponse.json();

        if (factsData.success) {
            _populateFactLists(factsData);
            setTimeout(() => {
                document.getElementById('upload_page').style.display = 'none';
                document.getElementById('main_page').style.display = 'flex';
            }, 500);
            clearStatus('upload_status');
        } else {
            showStatus('upload_status', `Facts error: ${factsData.message || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        showStatus('upload_status', `Kafka fetch failed: ${error.message}`, 'error');
    } finally {
        uploadBtn.disabled = false;
        if (kafkaBtn) kafkaBtn.disabled = false;
    }
}

async function handleJsonUploadClick() {
    const jsonInput = document.getElementById('json_file');
    if (!jsonInput || !jsonInput.files[0]) {
        showStatus('upload_status', 'Please select a JSON file', 'error');
        return;
    }

    uploadBtn.disabled = true;
    showLoading('upload_status', 'Parsing JSON and generating Prolog facts...');

    _resetUI();

    const formData = new FormData();
    formData.append('json_file', jsonInput.files[0]);

    try {
        const response = await fetch('/api/parse-json', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            showLoading('upload_status', `${result.message} — Running inference...`);
            allFacts = result.entities || [];

            const inferenceResponse = await fetch('/api/run-inference', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ trace: false })
            });

            if (!inferenceResponse.ok) {
                const errorData = await inferenceResponse.json();
                showStatus('upload_status', `Inference failed: ${errorData.message || 'Unknown error'}`, 'error');
                uploadBtn.disabled = false;
                return;
            }

            const inferenceResult = await inferenceResponse.json();

            if (inferenceResult.success) {
                const factsResponse = await fetch('/api/facts-list');

                if (!factsResponse.ok) {
                    const errorData = await factsResponse.json();
                    showStatus('upload_status', `Failed to fetch facts: ${errorData.message || 'Unknown error'}`, 'error');
                    uploadBtn.disabled = false;
                    return;
                }

                const factsData = await factsResponse.json();

                if (factsData.success) {
                    _populateFactLists(factsData);
                    setTimeout(() => {
                        document.getElementById('upload_page').style.display = 'none';
                        document.getElementById('main_page').style.display = 'flex';
                    }, 500);
                    clearStatus('upload_status');
                } else {
                    showStatus('upload_status', `Facts error: ${factsData.message || 'Unknown error'}`, 'error');
                }
            } else {
                showStatus('upload_status', `Inference error: ${inferenceResult.message}`, 'error');
            }
        } else {
            showStatus('upload_status', `Error: ${result.message}`, 'error');
        }
    } catch (error) {
        showStatus('upload_status', `Upload failed: ${error.message}`, 'error');
    } finally {
        uploadBtn.disabled = false;
    }
}

function _resetUI() {
    document.getElementById('vuln_list').innerHTML = '';
    document.getElementById('comp_list').innerHTML = '';
    document.getElementById('mal_list').innerHTML = '';
    document.getElementById('graph_area').innerHTML = `<div style="text-align: center; color: #64748b;"><p style="font-size: 18px; margin: 0;">Select a fact from the left to visualize</p></div>`;
    document.getElementById('graph_status').innerHTML = '';
    
    document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
        const tabName = btn.getAttribute('data-tab');
        const tabLabels = {
            'vulnerabilities': 'Vulns',
            'compromises': 'Comps',
            'malfunctions': 'Malfun'
        };
        btn.innerHTML = tabLabels[tabName] || tabName;
        if (idx === 0) {
            btn.style.background = 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)';
            btn.style.color = 'white';
            btn.style.border = 'none';
        } else {
            btn.style.background = 'rgba(30, 30, 45, 0.5)';
            btn.style.color = '#94a3b8';
            btn.style.border = 'none';
        }
    });
    
    document.getElementById('vuln_list').style.display = 'block';
    document.getElementById('comp_list').style.display = 'none';
    document.getElementById('mal_list').style.display = 'none';
}

function _populateFactLists(factsData) {
    const vulnList = document.getElementById('vuln_list');
    const compList = document.getElementById('comp_list');
    const malList = document.getElementById('mal_list');
    
    window.factsByCategory = {
        vulnerabilities: factsData.vulnerabilities,
        compromises: factsData.compromises,
        malfunctions: factsData.malfunctions
    };
    
    vulnList.innerHTML = factsData.vulnerabilities
        .map(f => `<div class="fact-item" data-fact="${f.replace(/"/g, '&quot;')}" style="border-left-color: #8b5cf6;">${f}</div>`)
        .join('');
    
    compList.innerHTML = factsData.compromises
        .map(f => `<div class="fact-item" data-fact="${f.replace(/"/g, '&quot;')}" style="border-left-color: #ec4899;">${f}</div>`)
        .join('');
    
    malList.innerHTML = factsData.malfunctions
        .map(f => `<div class="fact-item" data-fact="${f.replace(/"/g, '&quot;')}" style="border-left-color: #f59e0b;">${f}</div>`)
        .join('');
    
    const vulnBtn = document.querySelector('[data-tab="vulnerabilities"]');
    const compBtn = document.querySelector('[data-tab="compromises"]');
    const malBtn = document.querySelector('[data-tab="malfunctions"]');
    
    if (vulnBtn) vulnBtn.innerHTML = `Vulns (${factsData.vulnerabilities.length})`;
    if (compBtn) compBtn.innerHTML = `Comps (${factsData.compromises.length})`;
    if (malBtn) malBtn.innerHTML = `Malfun (${factsData.malfunctions.length})`;
}

document.addEventListener('click', (event) => {
    const btn = event.target.closest('.tab-btn');
    if (!btn) return;
    
    const tab = btn.getAttribute('data-tab');
    
    const tabMap = {
        'vulnerabilities': 'vuln_list',
        'compromises': 'comp_list',
        'malfunctions': 'mal_list'
    };
    
    const listId = tabMap[tab];
    if (!listId) return;
    
    document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.remove('active');
        b.style.background = 'rgba(30, 30, 45, 0.5)';
        b.style.color = '#94a3b8';
        b.style.border = 'none';
    });
    
    document.querySelectorAll('.facts-list').forEach(list => {
        list.style.display = 'none';
    });
    
    btn.classList.add('active');
    btn.style.background = 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)';
    btn.style.color = 'white';
    btn.style.border = 'none';
    
    const factList = document.getElementById(listId);
    if (factList) {
        factList.style.display = 'block';
    }
});

function setupSearchHandlers() {
    const searchBtn = document.getElementById('search_btn');
    const searchModal = document.getElementById('search_modal');
    const closeSearch = document.getElementById('close_search');
    const searchExecuteBtn = document.getElementById('search_execute_btn');
    const searchInput = document.getElementById('search_input');

    if (searchBtn) {
        searchBtn.addEventListener('click', () => {
            if (searchModal) {
                searchModal.style.display = 'block';
                if (searchInput) setTimeout(() => searchInput.focus(), 100);
            }
        });
    }

    if (closeSearch) {
        closeSearch.addEventListener('click', () => {
            if (searchModal) searchModal.style.display = 'none';
        });
    }

    if (searchModal) {
        searchModal.addEventListener('click', (e) => {
            if (e.target === searchModal) searchModal.style.display = 'none';
        });
    }

    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') executeSearchQuery();
        });
    }

    if (searchExecuteBtn) {
        searchExecuteBtn.addEventListener('click', executeSearchQuery);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupSearchHandlers);
} else {
    setupSearchHandlers();
}

async function executeSearchQuery() {
    const searchInput = document.getElementById('search_input');
    const query = searchInput?.value.trim();
    const resultsContainer = document.getElementById('search_results');
    const visualizationContainer = document.getElementById('search_visualization');
    
    if (!query) {
        resultsContainer.innerHTML = '<div style="text-align: center; color: #ef4444; padding: 20px;">Please enter a query</div>';
        visualizationContainer.style.display = 'none';
        return;
    }
    
    resultsContainer.innerHTML = '<div style="text-align: center; padding: 40px; color: #94a3b8;">Searching...</div>';
    visualizationContainer.style.display = 'none';
    
    try {
        const searchResponse = await fetch('/api/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern: query })
        });
        
        const searchData = await searchResponse.json();
        
        if (!searchData.success) {
            resultsContainer.innerHTML = `<div style="color: #ef4444; padding: 20px;">${searchData.message}</div>`;
            return;
        }
        
        const matchingRoots = searchData.matching_roots || [];
        let resultsHTML = `<div style="color: #06b6d4; font-weight: 600; margin-bottom: 12px;">✓ Found ${matchingRoots.length} matching root(s):</div>`;
        resultsHTML += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        matchingRoots.forEach(root => {
            resultsHTML += `<div style="background: rgba(6, 182, 212, 0.2); border: 1px solid #06b6d4; padding: 8px 12px; border-radius: 6px; color: #e2e8f0; font-size: 13px;">${root}</div>`;
        });
        resultsHTML += '</div>';
        resultsContainer.innerHTML = resultsHTML;
        
        const expandResponse = await fetch('/api/expand-graph', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern: query })
        });
        
        const expandData = await expandResponse.json();
        
        if (expandData.success) {
            visualizationContainer.style.display = 'block';
            
            const graphContainer = document.getElementById('search_graph_container');
            
            if (window.searchCyInstance) {
                window.searchCyInstance.destroy();
            }
            
            window.searchCyInstance = cytoscape({
                container: graphContainer,
                elements: convertGraphToElements(expandData.graph_data, query),
                style: getGraphStyle(),
                layout: { name: 'cose' }
            });
            
            window.searchCyInstance.fit();
        }
    } catch (error) {
        resultsContainer.innerHTML = `<div style="color: #ef4444; padding: 20px;">Error: ${error.message}</div>`;
    }
}

function convertGraphToElements(graphData, rootQuery = '') {
    const elements = [];
    
    function _getNodeColor(nodeId, isRoot) {
        if (isRoot) {
            return {
                'background-color': '#a78bfa',
                'border-width': 4,
                'border-color': '#8b5cf6'
            };
        }
        
        const colorMap = {
            'canbeComp': { bg: '#d946ef', border: '#be185d' },
            'canbeVul': { bg: '#c084fc', border: '#a78bfa' },
            'canbeMalfun': { bg: '#a78bfa', border: '#8b5cf6' },
            'cause(': { bg: '#8b5cf6', border: '#7c3aed' },
            'exploitable(': { bg: '#7c3aed', border: '#6d28d9' },
            'exposed(': { bg: '#6d28d9', border: '#581c87' },
            'induce(': { bg: '#94a3b8', border: '#64748b' },
            'not(defended(': { bg: '#fbbf24', border: '#d97706' },
            'spread(': { bg: '#e879f9', border: '#d946ef' }
        };
        
        for (const [key, colors] of Object.entries(colorMap)) {
            if (nodeId.includes(key)) {
                return {
                    'background-color': colors.bg,
                    'border-width': 2,
                    'border-color': colors.border
                };
            }
        }
        
        return {
            'background-color': '#64748b',
            'border-width': 2,
            'border-color': '#475569'
        };
    }
    
    if (graphData.nodes) {
        graphData.nodes.forEach((node) => {
            const isRoot = rootQuery && node.id === rootQuery;
            const colorStyle = _getNodeColor(node.id, isRoot);
            
            elements.push({
                data: { id: node.id, label: node.id, isRoot: isRoot },
                style: {
                    'content': 'data(label)',
                    ...colorStyle
                }
            });
        });
    }
    
    if (graphData.links) {
        graphData.links.forEach(link => {
            elements.push({
                data: { source: link.source, target: link.target }
            });
        });
    }
    
    return elements;
}

function getGraphStyle() {
    return [
        {
            selector: 'node',
            style: {
                'content': 'data(label)',
                'text-valign': 'center',
                'text-halign': 'center',
                'width': '60px',
                'height': '60px',
                'font-size': '10px',
                'color': '#ffffff',
                'text-wrap': 'wrap',
                'text-max-width': '50px',
                'font-weight': 600,
                'padding': '6px'
            }
        },
        {
            selector: 'node[isRoot]',
            style: {
                'width': '80px',
                'height': '80px',
                'font-size': '11px',
                'font-weight': 700,
                'box-shadow': '0 0 20px rgba(6, 182, 212, 0.8)'
            }
        },
        {
            selector: 'edge',
            style: {
                'width': 2,
                'line-color': '#a78bfa',
                'target-arrow-color': '#a78bfa',
                'target-arrow-shape': 'triangle',
                'arrow-scale': 1.5,
                'curve-style': 'bezier'
            }
        },
        {
            selector: 'node:hover',
            style: {
                'box-shadow': '0 0 12px rgba(139, 92, 246, 0.6)',
                'width': '80px',
                'height': '80px'
            }
        }
    ];
}

document.addEventListener('click', (event) => {
    const factItem = event.target.closest('.fact-item');
    if (factItem) {
        const factRoot = factItem.getAttribute('data-fact');
        if (factRoot) visualizeFact(factRoot);
    }
});
