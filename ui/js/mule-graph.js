/**
 * Ethio-Cyber-Shield (ECS) — Real-Time Financial Mule Ring & Graph Intelligence Visualizer
 * High-performance, zero-dependency Force-Directed Canvas Network Engine.
 * Complies with NBE Cyber Risk Directives & INSA Proclamation No. 1426/2026.
 */

class MuleGraphVisualizer {
    constructor(canvasId, containerId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas ? this.canvas.getContext('2d') : null;
        this.container = document.getElementById(containerId);

        this.nodes = [];
        this.edges = [];
        this.syndicates = [];
        this.metrics = {};

        // Graph simulation state
        this.nodeMap = new Map();
        this.selectedNode = null;
        this.hoveredNode = null;
        this.draggedNode = null;
        this.activeSyndicateId = null;

        // Viewport pan & zoom
        this.transform = { x: 0, y: 0, scale: 1.0 };
        this.isPanning = false;
        this.panStart = { x: 0, y: 0 };

        // Animation flow tick for edge pulses
        this.animTick = 0;
        this.animFrameId = null;

        // Color palette for roles
        this.colors = {
            cashout_hub: { fill: '#ef4444', stroke: '#fca5a5', glow: 'rgba(239, 68, 68, 0.45)', text: '#ffffff' },
            intermediary_mule: { fill: '#f59e0b', stroke: '#fcd34d', glow: 'rgba(245, 158, 11, 0.35)', text: '#ffffff' },
            victim_source: { fill: '#06b6d4', stroke: '#67e8f9', glow: 'rgba(6, 182, 212, 0.35)', text: '#ffffff' },
            normal: { fill: '#475569', stroke: '#94a3b8', glow: 'rgba(100, 116, 139, 0.2)', text: '#cbd5e1' },
            contained: { stroke: '#10b981', glow: 'rgba(16, 185, 129, 0.5)' }
        };

        this.railColors = {
            telebirr: '#06b6d4',
            cbe_birr: '#a855f7',
            ethswitch: '#f59e0b',
            bank_transfer: '#10b981',
            default: '#94a3b8'
        };

        if (this.canvas) {
            this.initCanvas();
            this.bindEvents();
        }
    }

    initCanvas() {
        const resize = () => {
            if (!this.container || !this.canvas) return;
            const rect = this.container.getBoundingClientRect();
            const dpr = window.devicePixelRatio || 1;
            const w = rect.width || 800;
            const h = rect.height || 540;

            this.canvas.width = w * dpr;
            this.canvas.height = h * dpr;
            this.canvas.style.width = w + 'px';
            this.canvas.style.height = h + 'px';
            this.ctx.scale(dpr, dpr);
            this.width = w;
            this.height = h;

            if (this.transform.x === 0 && this.transform.y === 0) {
                this.transform.x = w / 2;
                this.transform.y = h / 2;
            }
        };

        window.addEventListener('resize', resize);
        resize();
    }

    bindEvents() {
        if (!this.canvas) return;

        this.canvas.addEventListener('mousedown', (e) => this.onMouseDown(e));
        window.addEventListener('mousemove', (e) => this.onMouseMove(e));
        window.addEventListener('mouseup', (e) => this.onMouseUp(e));
        this.canvas.addEventListener('wheel', (e) => this.onWheel(e), { passive: false });

        // Touch support for mobile/tablets
        this.canvas.addEventListener('touchstart', (e) => {
            if (e.touches.length === 1) {
                const t = e.touches[0];
                this.onMouseDown({ clientX: t.clientX, clientY: t.clientY });
            }
        });
        window.addEventListener('touchmove', (e) => {
            if (e.touches.length === 1) {
                const t = e.touches[0];
                this.onMouseMove({ clientX: t.clientX, clientY: t.clientY });
            }
        });
        window.addEventListener('touchend', (e) => this.onMouseUp(e));
    }

    // =========================================================================
    // DATA LOADING & GRAPH SETUP
    // =========================================================================

    async loadGraphData(syndicateId = null) {
        try {
            this.activeSyndicateId = syndicateId;
            const params = {};
            if (syndicateId) params.syndicate_id = syndicateId;

            const res = await API.getMuleGraph(params);
            if (!res || !res.data) return;

            const data = res.data;
            this.metrics = data.metrics || {};
            this.syndicates = data.syndicates || [];
            this.updateKPIs(this.metrics, this.syndicates);
            this.renderSyndicateCards(this.syndicates);

            this.setupSimulation(data.nodes || [], data.edges || []);
        } catch (err) {
            console.error('Failed to load mule graph:', err);
        }
    }

    setupSimulation(rawNodes, rawEdges) {
        const existingPos = new Map();
        for (const n of this.nodes) {
            existingPos.set(n.id, { x: n.x, y: n.y, vx: n.vx, vy: n.vy });
        }

        this.nodeMap.clear();
        this.nodes = rawNodes.map((rn, idx) => {
            const old = existingPos.get(rn.id);
            const angle = (idx / rawNodes.length) * Math.PI * 2;
            const radius = 120 + (idx % 3) * 60;
            const node = {
                ...rn,
                x: old ? old.x : Math.cos(angle) * radius,
                y: old ? old.y : Math.sin(angle) * radius,
                vx: old ? old.vx : 0,
                vy: old ? old.vy : 0,
                radius: rn.role === 'cashout_hub' ? 24 : (rn.role === 'victim_source' ? 20 : 18)
            };
            this.nodeMap.set(node.id, node);
            return node;
        });

        this.edges = rawEdges.map(re => ({
            ...re,
            sourceNode: this.nodeMap.get(re.source),
            targetNode: this.nodeMap.get(re.target)
        })).filter(e => e.sourceNode && e.targetNode);

        if (!this.animFrameId) {
            this.startAnimationLoop();
        }
    }

    // =========================================================================
    // PHYSICS SIMULATION & RENDERING
    // =========================================================================

    startAnimationLoop() {
        const loop = () => {
            this.updatePhysics();
            this.draw();
            this.animTick = (this.animTick + 0.05) % 1.0;
            this.animFrameId = requestAnimationFrame(loop);
        };
        this.animFrameId = requestAnimationFrame(loop);
    }

    updatePhysics() {
        const kRepel = 2400;
        const kSpring = 0.04;
        const defaultLength = 140;
        const damp = 0.82;
        const centerGravity = 0.015;

        // 1. Repulsion between all node pairs (Coulomb's Law)
        for (let i = 0; i < this.nodes.length; i++) {
            const na = this.nodes[i];
            for (let j = i + 1; j < this.nodes.length; j++) {
                const nb = this.nodes[j];
                const dx = nb.x - na.x;
                const dy = nb.y - na.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                if (dist > 350) continue;

                const force = kRepel / (dist * dist);
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;

                na.vx -= fx;
                na.vy -= fy;
                nb.vx += fx;
                nb.vy += fy;
            }
        }

        // 2. Spring attraction along edges (Hooke's Law)
        for (const edge of this.edges) {
            const na = edge.sourceNode;
            const nb = edge.targetNode;
            const dx = nb.x - na.x;
            const dy = nb.y - na.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = (dist - defaultLength) * kSpring;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            na.vx += fx;
            na.vy += fy;
            nb.vx -= fx;
            nb.vy -= fy;
        }

        // 3. Central gravity and position integration
        for (const n of this.nodes) {
            if (n === this.draggedNode) continue;

            n.vx -= n.x * centerGravity;
            n.vy -= n.y * centerGravity;

            n.vx *= damp;
            n.vy *= damp;

            n.x += n.vx;
            n.y += n.vy;
        }
    }

    draw() {
        if (!this.ctx || !this.width) return;
        const ctx = this.ctx;

        ctx.save();
        ctx.clearRect(0, 0, this.width, this.height);

        // Background radar grid
        this.drawRadarGrid(ctx);

        // Apply pan & zoom transform
        ctx.translate(this.transform.x, this.transform.y);
        ctx.scale(this.transform.scale, this.transform.scale);

        // Draw directed transaction edges with arrows & flow pulses
        for (const edge of this.edges) {
            this.drawEdge(ctx, edge);
        }

        // Draw nodes
        for (const node of this.nodes) {
            this.drawNode(ctx, node);
        }

        ctx.restore();

        // Draw overlay tooltip if hovering a node
        if (this.hoveredNode && !this.draggedNode) {
            this.drawTooltip(ctx, this.hoveredNode);
        }
    }

    drawRadarGrid(ctx) {
        ctx.save();
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.05)';
        ctx.lineWidth = 1;

        const cx = this.transform.x;
        const cy = this.transform.y;
        const rMax = Math.max(this.width, this.height);

        // Concentric radar circles
        for (let r = 80; r < rMax; r += 100) {
            ctx.beginPath();
            ctx.arc(cx, cy, r * this.transform.scale, 0, Math.PI * 2);
            ctx.stroke();
        }

        // Crosshairs
        ctx.beginPath();
        ctx.moveTo(cx, 0); ctx.lineTo(cx, this.height);
        ctx.moveTo(0, cy); ctx.lineTo(this.width, cy);
        ctx.stroke();

        ctx.restore();
    }

    drawEdge(ctx, edge) {
        const u = edge.sourceNode;
        const v = edge.targetNode;
        const isHighlighted = this.isEdgeHighlighted(edge);

        const dx = v.x - u.x;
        const dy = v.y - u.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;

        // Offset start/end by node radii
        const startX = u.x + (dx / dist) * u.radius;
        const startY = u.y + (dy / dist) * u.radius;
        const endX = v.x - (dx / dist) * (v.radius + 6);
        const endY = v.y - (dy / dist) * (v.radius + 6);

        const railColor = this.railColors[edge.payment_rail] || this.railColors.default;

        ctx.save();
        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.lineTo(endX, endY);
        ctx.strokeStyle = isHighlighted ? '#f87171' : railColor;
        ctx.lineWidth = isHighlighted ? 2.5 : 1.5;
        ctx.globalAlpha = isHighlighted ? 0.95 : 0.6;
        ctx.stroke();

        // Draw arrow head at target
        const arrowAngle = Math.atan2(dy, dx);
        const arrowLength = isHighlighted ? 10 : 8;
        ctx.beginPath();
        ctx.moveTo(endX, endY);
        ctx.lineTo(endX - arrowLength * Math.cos(arrowAngle - Math.PI / 7), endY - arrowLength * Math.sin(arrowAngle - Math.PI / 7));
        ctx.lineTo(endX - arrowLength * Math.cos(arrowAngle + Math.PI / 7), endY - arrowLength * Math.sin(arrowAngle + Math.PI / 7));
        ctx.closePath();
        ctx.fillStyle = isHighlighted ? '#f87171' : railColor;
        ctx.fill();

        // Animated fund flow pulse
        const pulsePos = (this.animTick + (Math.abs(hashString(edge.id)) % 10) * 0.1) % 1.0;
        const px = startX + (endX - startX) * pulsePos;
        const py = startY + (endY - startY) * pulsePos;

        ctx.beginPath();
        ctx.arc(px, py, isHighlighted ? 3.5 : 2.5, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = railColor;
        ctx.shadowBlur = 8;
        ctx.fill();

        // Edge amount label
        if (this.transform.scale >= 0.75) {
            const midX = (startX + endX) / 2;
            const midY = (startY + endY) / 2;
            ctx.font = '9px var(--bs-font-monospace, monospace)';
            ctx.fillStyle = '#94a3b8';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            const amtStr = edge.amount >= 1000 ? `${(edge.amount / 1000).toFixed(1)}k ETB` : `${edge.amount} ETB`;
            ctx.fillText(amtStr, midX, midY - 6);
        }

        ctx.restore();
    }

    drawNode(ctx, node) {
        const isHovered = node === this.hoveredNode;
        const isSelected = node === this.selectedNode;
        const style = this.colors[node.role] || this.colors.normal;

        ctx.save();

        // 1. Outer glow halo
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + (isHovered || isSelected ? 8 : 4), 0, Math.PI * 2);
        ctx.fillStyle = node.is_contained ? this.colors.contained.glow : style.glow;
        ctx.fill();

        // 2. Node circle fill & stroke
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = style.fill;
        ctx.fill();

        ctx.lineWidth = node.is_contained ? 3 : (isSelected || isHovered ? 2.5 : 1.5);
        ctx.strokeStyle = node.is_contained ? this.colors.contained.stroke : style.stroke;
        ctx.stroke();

        // 3. Contained lock badge or Cash-Out crown
        if (node.is_contained) {
            ctx.fillStyle = '#10b981';
            ctx.beginPath();
            ctx.arc(node.x + node.radius * 0.7, node.y - node.radius * 0.7, 7, 0, Math.PI * 2);
            ctx.fill();
            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 8px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('🔒', node.x + node.radius * 0.7, node.y - node.radius * 0.7);
        } else if (node.role === 'cashout_hub') {
            ctx.fillStyle = '#f59e0b';
            ctx.beginPath();
            ctx.arc(node.x, node.y - node.radius - 4, 4, 0, Math.PI * 2);
            ctx.fill();
        }

        // 4. Node Label
        ctx.font = '10px var(--bs-font-monospace, monospace)';
        ctx.fillStyle = style.text;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        let displayId = node.id.replace('ACC-', '').replace('TELE-', 'TL-').replace('CBE-', 'CB-');
        if (displayId.length > 12) displayId = displayId.slice(0, 10) + '..';
        ctx.fillText(displayId, node.x, node.y);

        // 5. Role subtitle badge below node
        if (this.transform.scale >= 0.75) {
            ctx.font = '9px sans-serif';
            ctx.fillStyle = '#94a3b8';
            const roleName = node.role === 'cashout_hub' ? '⚡ CASHOUT' :
                             node.role === 'intermediary_mule' ? 'MULE' :
                             node.role === 'victim_source' ? 'VICTIM' : 'RETAIL';
            ctx.fillText(roleName, node.x, node.y + node.radius + 12);
        }

        ctx.restore();
    }

    drawTooltip(ctx, node) {
        ctx.save();
        const screenX = node.x * this.transform.scale + this.transform.x;
        const screenY = node.y * this.transform.scale + this.transform.y;

        const pad = 10;
        const boxW = 210;
        const boxH = 96;
        let bx = screenX + 16;
        let by = screenY - 20;

        if (bx + boxW > this.width) bx = screenX - boxW - 16;
        if (by + boxH > this.height) by = this.height - boxH - 10;

        // Box background
        ctx.fillStyle = 'rgba(15, 23, 42, 0.95)';
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.4)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(bx, by, boxW, boxH, 6);
        ctx.fill();
        ctx.stroke();

        // Header: Account ID & Risk
        ctx.font = 'bold 11px var(--bs-font-monospace, monospace)';
        ctx.fillStyle = '#f8fafc';
        ctx.textAlign = 'left';
        ctx.fillText(node.id, bx + pad, by + 18);

        ctx.font = 'bold 10px sans-serif';
        ctx.fillStyle = node.risk_score >= 85 ? '#ef4444' : (node.risk_score >= 60 ? '#f59e0b' : '#10b981');
        ctx.textAlign = 'right';
        ctx.fillText(`RISK: ${node.risk_score}/100`, bx + boxW - pad, by + 18);

        // Body stats
        ctx.font = '10px sans-serif';
        ctx.fillStyle = '#94a3b8';
        ctx.textAlign = 'left';

        ctx.fillText(`Role: ${node.role.replace('_', ' ').toUpperCase()}`, bx + pad, by + 36);
        ctx.fillText(`Total Inflow: ${node.total_inflow.toLocaleString()} ETB`, bx + pad, by + 52);
        ctx.fillText(`Total Outflow: ${node.total_outflow.toLocaleString()} ETB`, bx + pad, by + 68);

        const statusText = node.is_contained ? '🔒 CONTAINED / FROZEN' : 'ACTIVE / UNRESTRICTED';
        ctx.fillStyle = node.is_contained ? '#10b981' : '#f87171';
        ctx.fillText(`Status: ${statusText}`, bx + pad, by + 84);

        ctx.restore();
    }

    isEdgeHighlighted(edge) {
        if (this.selectedNode) {
            return edge.source === this.selectedNode.id || edge.target === this.selectedNode.id;
        }
        if (this.hoveredNode) {
            return edge.source === this.hoveredNode.id || edge.target === this.hoveredNode.id;
        }
        return false;
    }

    // =========================================================================
    // MOUSE & GESTURE INTERACTION
    // =========================================================================

    getMousePos(e) {
        const rect = this.canvas.getBoundingClientRect();
        return {
            x: e.clientX - rect.left,
            y: e.clientY - rect.top
        };
    }

    screenToWorld(sx, sy) {
        return {
            x: (sx - this.transform.x) / this.transform.scale,
            y: (sy - this.transform.y) / this.transform.scale
        };
    }

    findNodeAt(wx, wy) {
        for (let i = this.nodes.length - 1; i >= 0; i--) {
            const n = this.nodes[i];
            const dx = wx - n.x;
            const dy = wy - n.y;
            if (dx * dx + dy * dy <= n.radius * n.radius) {
                return n;
            }
        }
        return null;
    }

    onMouseDown(e) {
        const m = this.getMousePos(e);
        const w = this.screenToWorld(m.x, m.y);
        const hit = this.findNodeAt(w.x, w.y);

        if (hit) {
            this.draggedNode = hit;
            this.selectedNode = hit;
        } else {
            this.isPanning = true;
            this.panStart = { x: m.x - this.transform.x, y: m.y - this.transform.y };
            this.selectedNode = null;
        }
    }

    onMouseMove(e) {
        const m = this.getMousePos(e);
        if (this.draggedNode) {
            const w = this.screenToWorld(m.x, m.y);
            this.draggedNode.x = w.x;
            this.draggedNode.y = w.y;
            this.draggedNode.vx = 0;
            this.draggedNode.vy = 0;
            return;
        }

        if (this.isPanning) {
            this.transform.x = m.x - this.panStart.x;
            this.transform.y = m.y - this.panStart.y;
            return;
        }

        const w = this.screenToWorld(m.x, m.y);
        this.hoveredNode = this.findNodeAt(w.x, w.y);
        this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'grab';
    }

    onMouseUp(e) {
        this.draggedNode = null;
        this.isPanning = false;
        if (this.canvas) this.canvas.style.cursor = 'default';
    }

    onWheel(e) {
        e.preventDefault();
        const m = this.getMousePos(e);
        const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
        const newScale = Math.min(3.0, Math.max(0.35, this.transform.scale * zoomFactor));

        // Zoom relative to mouse position
        this.transform.x = m.x - (m.x - this.transform.x) * (newScale / this.transform.scale);
        this.transform.y = m.y - (m.y - this.transform.y) * (newScale / this.transform.scale);
        this.transform.scale = newScale;
    }

    resetView() {
        this.transform.scale = 1.0;
        this.transform.x = this.width / 2;
        this.transform.y = this.height / 2;
    }

    zoom(delta) {
        const factor = delta > 0 ? 1.2 : 0.83;
        const newScale = Math.min(3.0, Math.max(0.35, this.transform.scale * factor));
        const cx = this.width / 2;
        const cy = this.height / 2;
        this.transform.x = cx - (cx - this.transform.x) * (newScale / this.transform.scale);
        this.transform.y = cy - (cy - this.transform.y) * (newScale / this.transform.scale);
        this.transform.scale = newScale;
    }

    // =========================================================================
    // UI UPDATES & ACTIONS
    // =========================================================================

    updateKPIs(metrics, syndicates) {
        const totalSyn = document.getElementById('muleKpiTotalSyndicates');
        const vol = document.getElementById('muleKpiVolume');
        const mules = document.getElementById('muleKpiActiveMules');
        const contained = document.getElementById('muleKpiContained');
        const badge = document.getElementById('badgeMuleRingsCount');

        if (totalSyn) totalSyn.textContent = syndicates.length;
        if (badge) badge.textContent = syndicates.length;
        if (vol) vol.textContent = (metrics.total_laundering_volume_etb || 0).toLocaleString() + ' ETB';
        if (mules) mules.textContent = metrics.active_mules || 0;
        if (contained) contained.textContent = metrics.contained_accounts || 0;
    }

    renderSyndicateCards(syndicates) {
        const container = document.getElementById('muleSyndicateCardsContainer');
        if (!container) return;

        if (!syndicates || syndicates.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4 text-muted">
                    <i class="bi bi-shield-check display-6 d-block mb-2 text-success opacity-50"></i>
                    No active financial laundering rings detected.
                </div>
            `;
            return;
        }

        container.innerHTML = syndicates.map(s => {
            const isContained = s.containment_status === 'CONTAINED';
            const badgeClass = s.severity === 'critical' ? 'bg-danger' : 'bg-warning text-dark';
            const typeLabel = s.syndicate_type === 'CIRCULAR_LAUNDERING_RING' ? 'CIRCULAR LAUNDERING RING' : 'COORDINATED SMURFING RING';

            return `
                <div class="card bg-dark border-secondary mb-3 shadow-sm syndicate-card" id="card-${s.syndicate_id}" style="border-left: 4px solid ${isContained ? '#10b981' : '#ef4444'} !important;">
                    <div class="card-body p-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="badge ${badgeClass} font-monospace">${s.syndicate_id}</span>
                            <span class="badge ${isContained ? 'bg-success' : 'bg-danger'}">${isContained ? '🔒 CONTAINED' : '⚡ ACTIVE'}</span>
                        </div>
                        <h6 class="text-light fw-bold mb-1" style="font-size: 0.85rem;">${typeLabel}</h6>
                        <div class="d-flex gap-2 text-muted small mb-2 font-monospace" style="font-size: 0.72rem;">
                            <span><i class="bi bi-diagram-3 text-info"></i> ${s.hop_count} Hops</span>
                            <span>•</span>
                            <span class="text-warning"><i class="bi bi-cash-stack"></i> ${s.total_volume_etb.toLocaleString()} ETB</span>
                            <span>•</span>
                            <span class="text-danger fw-bold">RISK: ${s.risk_score}/100</span>
                        </div>
                        <p class="small text-light opacity-75 mb-2" style="font-size: 0.76rem; line-height: 1.35;">
                            ${s.detection_reason}
                        </p>
                        <div class="d-flex flex-wrap gap-1 mb-3">
                            ${(s.involved_accounts || []).map(acc => `
                                <span class="badge bg-secondary font-monospace" style="cursor: pointer; font-size: 0.65rem;" onclick="window.muleVisualizer.focusNode('${acc}')">
                                    ${acc}
                                </span>
                            `).join('')}
                        </div>
                        <div class="d-flex gap-2">
                            <button class="btn btn-sm btn-outline-info flex-fill" style="font-size: 0.75rem;" onclick="window.muleVisualizer.isolateSyndicate('${s.syndicate_id}')">
                                <i class="bi bi-eye me-1"></i> Inspect Subgraph
                            </button>
                            ${!isContained ? `
                                <button class="btn btn-sm btn-danger flex-fill fw-bold" style="font-size: 0.75rem;" onclick="window.muleVisualizer.containSyndicateAction('${s.syndicate_id}')">
                                    <i class="bi bi-shield-slash me-1"></i> 1-Click Freeze
                                </button>
                            ` : `
                                <span class="btn btn-sm btn-outline-success flex-fill disabled" style="font-size: 0.75rem;">
                                    <i class="bi bi-check-circle me-1"></i> Contained (1426/2026)
                                </span>
                            `}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    focusNode(nodeId) {
        const node = this.nodeMap.get(nodeId);
        if (!node) return;

        this.selectedNode = node;
        this.transform.x = this.width / 2 - node.x * this.transform.scale;
        this.transform.y = this.height / 2 - node.y * this.transform.scale;
    }

    isolateSyndicate(syndicateId) {
        this.loadGraphData(syndicateId);
    }

    async containSyndicateAction(syndicateId) {
        if (!confirm(`Confirm autonomous multi-account freeze for syndicate ${syndicateId} under INSA Proclamation No. 1426/2026?`)) {
            return;
        }

        try {
            const res = await API.containMuleRing(syndicateId, 'Autonomous freeze dispatched from SOC Graph Explorer');
            if (res && res.result) {
                if (typeof showToast === 'function') {
                    showToast(`Syndicate ${syndicateId} contained! ${res.result.accounts_frozen_count} accounts frozen.`, 'success');
                }
                // Reload graph
                await this.loadGraphData(this.activeSyndicateId);
            }
        } catch (err) {
            console.error('Failed to contain syndicate:', err);
            if (typeof showToast === 'function') {
                showToast('Containment error: ' + (err.message || 'Server error'), 'error');
            }
        }
    }

    async seedDemo() {
        try {
            const res = await API.seedDemoMuleRings();
            if (res) {
                if (typeof showToast === 'function') {
                    showToast('Seeded authentic Ethiopian financial mule syndicates (telebirr, CBE Birr, EthSwitch).', 'info');
                }
                await this.loadGraphData();
            }
        } catch (err) {
            console.error('Failed to seed demo:', err);
        }
    }
}

// Utility hash function
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return hash;
}

window.MuleGraphVisualizer = MuleGraphVisualizer;
