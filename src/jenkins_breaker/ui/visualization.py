"""
Network topology visualizer for Jenkins infrastructure mapping.
Generates visual representations of Jenkins servers, nodes, jobs, and their relationships.
"""

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jenkins_breaker.core.enumeration import JenkinsEnumerator
from jenkins_breaker.core.session import JenkinsSession


@dataclass
class Node:
    """Represents a node in the topology graph."""

    id: str
    label: str
    type: str
    metadata: dict[str, Any] = field(default_factory=dict)
    x: Optional[float] = None
    y: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Edge:
    """Represents a connection between nodes."""

    source: str
    target: str
    label: str = ""
    type: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TopologyGraph:
    """Represents the complete topology graph."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class TopologyVisualizer:
    """
    Builds and visualizes Jenkins infrastructure topology.

    Features:
    - Server and node discovery
    - Job dependency mapping
    - Plugin relationship tracking
    - User and permission mapping
    - Multiple export formats (JSON, DOT, HTML)
    """

    def __init__(self):
        self.graph = TopologyGraph()
        self.node_index: dict[str, Node] = {}
        self.edge_index: set[tuple[str, str]] = set()

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        metadata: Optional[dict[str, Any]] = None
    ) -> Node:
        """
        Add a node to the topology graph.

        Args:
            node_id: Unique identifier
            label: Display label
            node_type: Type (server, agent, job, plugin, user, etc.)
            metadata: Additional node data

        Returns:
            Created Node object
        """
        if node_id in self.node_index:
            return self.node_index[node_id]

        node = Node(
            id=node_id,
            label=label,
            type=node_type,
            metadata=metadata or {}
        )

        self.graph.nodes.append(node)
        self.node_index[node_id] = node

        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        label: str = "",
        edge_type: str = "default",
        metadata: Optional[dict[str, Any]] = None
    ) -> Optional[Edge]:
        """
        Add an edge between two nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            label: Edge label
            edge_type: Type (manages, triggers, depends_on, etc.)
            metadata: Additional edge data

        Returns:
            Created Edge object or None if nodes don't exist
        """
        if source_id not in self.node_index or target_id not in self.node_index:
            return None

        edge_key = (source_id, target_id)
        if edge_key in self.edge_index:
            return None

        edge = Edge(
            source=source_id,
            target=target_id,
            label=label,
            type=edge_type,
            metadata=metadata or {}
        )

        self.graph.edges.append(edge)
        self.edge_index.add(edge_key)

        return edge

    def build_from_session(self, session: JenkinsSession) -> TopologyGraph:
        """
        Build topology graph from a Jenkins session.

        Args:
            session: Active Jenkins session

        Returns:
            Complete topology graph
        """
        enumerator = JenkinsEnumerator(session)

        server_id = f"server_{session.config.url}"
        self.add_node(
            server_id,
            session.config.url,
            "server",
            {
                "version": session.version,
                "authenticated": session.authenticated,
                "url": session.config.url
            }
        )

        try:
            agents = enumerator.enumerate_agents()
            for agent in agents:
                agent_id = f"agent_{agent.get('name', 'unknown')}"
                self.add_node(
                    agent_id,
                    agent.get("displayName", agent.get("name", "Unknown")),
                    "agent",
                    {
                        "offline": agent.get("offline", False),
                        "idle": agent.get("idle", True),
                        "num_executors": agent.get("numExecutors", 0)
                    }
                )

                self.add_edge(server_id, agent_id, "manages", "manages")
        except Exception:
            pass

        try:
            jobs = enumerator.enumerate_jobs()
            for job in jobs:
                job_id = f"job_{job.get('name', 'unknown')}"
                self.add_node(
                    job_id,
                    job.get("fullName", job.get("name", "Unknown")),
                    "job",
                    {
                        "url": job.get("url", ""),
                        "buildable": job.get("buildable", False),
                        "color": job.get("color", "grey")
                    }
                )

                self.add_edge(server_id, job_id, "hosts", "hosts")
        except Exception:
            pass

        try:
            plugins = enumerator.enumerate_plugins()
            plugin_node_id = f"plugins_{server_id}"
            self.add_node(
                plugin_node_id,
                f"Plugins ({len(plugins)})",
                "plugin_group",
                {
                    "count": len(plugins),
                    "plugins": [p.get("shortName", "") for p in plugins[:10]]
                }
            )

            self.add_edge(server_id, plugin_node_id, "uses", "uses")

            for plugin in plugins[:20]:
                plugin_id = f"plugin_{plugin.get('shortName', 'unknown')}"
                self.add_node(
                    plugin_id,
                    plugin.get("longName", plugin.get("shortName", "Unknown")),
                    "plugin",
                    {
                        "version": plugin.get("version", "unknown"),
                        "enabled": plugin.get("enabled", False),
                        "active": plugin.get("active", False)
                    }
                )

                self.add_edge(plugin_node_id, plugin_id, "", "contains")
        except Exception:
            pass

        self.graph.metadata = {
            "generated": datetime.now().isoformat(),
            "source": session.config.url,
            "node_count": len(self.graph.nodes),
            "edge_count": len(self.graph.edges)
        }

        return self.graph

    def calculate_layout(self, algorithm: str = "force") -> TopologyGraph:
        """
        Calculate node positions using a layout algorithm.

        Args:
            algorithm: Layout algorithm (force, hierarchical, circular)

        Returns:
            Graph with updated node positions
        """
        if algorithm == "force":
            self._force_directed_layout()
        elif algorithm == "hierarchical":
            self._hierarchical_layout()
        elif algorithm == "circular":
            self._circular_layout()

        return self.graph

    def _force_directed_layout(self):
        """Simple force-directed layout algorithm."""
        import math

        for i, node in enumerate(self.graph.nodes):
            angle = (2 * math.pi * i) / len(self.graph.nodes)
            node.x = 500 + 300 * math.cos(angle)
            node.y = 500 + 300 * math.sin(angle)

        iterations = 100
        k = 50

        for _ in range(iterations):
            forces = defaultdict(lambda: {"x": 0.0, "y": 0.0})

            for i, node1 in enumerate(self.graph.nodes):
                for j, node2 in enumerate(self.graph.nodes):
                    if i == j:
                        continue

                    dx = node2.x - node1.x
                    dy = node2.y - node1.y
                    distance = math.sqrt(dx*dx + dy*dy) + 0.01

                    repulsion = k * k / distance
                    forces[node1.id]["x"] -= repulsion * dx / distance
                    forces[node1.id]["y"] -= repulsion * dy / distance

            for edge in self.graph.edges:
                source = self.node_index[edge.source]
                target = self.node_index[edge.target]

                dx = target.x - source.x
                dy = target.y - source.y
                distance = math.sqrt(dx*dx + dy*dy) + 0.01

                attraction = distance / k
                forces[source.id]["x"] += attraction * dx / distance
                forces[source.id]["y"] += attraction * dy / distance
                forces[target.id]["x"] -= attraction * dx / distance
                forces[target.id]["y"] -= attraction * dy / distance

            for node in self.graph.nodes:
                if node.id in forces:
                    node.x += forces[node.id]["x"] * 0.1
                    node.y += forces[node.id]["y"] * 0.1

    def _hierarchical_layout(self):
        """Hierarchical layout based on node types."""
        layers = defaultdict(list)

        for node in self.graph.nodes:
            if node.type == "server":
                layers[0].append(node)
            elif node.type in ["agent", "plugin_group"]:
                layers[1].append(node)
            elif node.type in ["job", "plugin"]:
                layers[2].append(node)
            else:
                layers[3].append(node)

        y_offset = 100
        layer_spacing = 200

        for layer_num, nodes in sorted(layers.items()):
            x_spacing = 1000 / (len(nodes) + 1) if nodes else 0

            for i, node in enumerate(nodes):
                node.x = (i + 1) * x_spacing
                node.y = y_offset + layer_num * layer_spacing

    def _circular_layout(self):
        """Circular layout."""
        import math

        center_x, center_y = 500, 500
        radius = 300

        for i, node in enumerate(self.graph.nodes):
            angle = (2 * math.pi * i) / len(self.graph.nodes)
            node.x = center_x + radius * math.cos(angle)
            node.y = center_y + radius * math.sin(angle)

    def export_json(self, filepath: Optional[Path] = None) -> str:
        """
        Export graph to JSON format.

        Args:
            filepath: Optional file path to save JSON

        Returns:
            JSON string
        """
        json_data = self.graph.to_json()

        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_data)

        return json_data

    def export_dot(self, filepath: Optional[Path] = None) -> str:
        """
        Export graph to Graphviz DOT format.

        Args:
            filepath: Optional file path to save DOT file

        Returns:
            DOT format string
        """
        lines = ["digraph JenkinsTopology {"]
        lines.append("  rankdir=TB;")
        lines.append("  node [shape=box, style=rounded];")
        lines.append("")

        node_styles = {
            "server": "shape=cylinder, fillcolor=lightblue, style=filled",
            "agent": "shape=box, fillcolor=lightgreen, style=filled",
            "job": "shape=ellipse, fillcolor=lightyellow, style=filled",
            "plugin": "shape=component, fillcolor=lightgray, style=filled",
            "plugin_group": "shape=folder, fillcolor=lightcoral, style=filled"
        }

        for node in self.graph.nodes:
            style = node_styles.get(node.type, "")
            label = node.label.replace('"', '\\"')
            lines.append(f'  "{node.id}" [label="{label}", {style}];')

        lines.append("")

        edge_styles = {
            "manages": "color=blue",
            "hosts": "color=green",
            "uses": "color=orange",
            "contains": "color=gray, style=dashed"
        }

        for edge in self.graph.edges:
            style = edge_styles.get(edge.type, "")
            label = edge.label.replace('"', '\\"')
            label_attr = f'label="{label}"' if label else ""
            lines.append(f'  "{edge.source}" -> "{edge.target}" [{label_attr} {style}];')

        lines.append("}")

        dot_content = "\n".join(lines)

        if filepath:
            with open(filepath, 'w') as f:
                f.write(dot_content)

        return dot_content

    def export_html(self, filepath: Optional[Path] = None) -> str:
        """
        Export graph to interactive HTML using vis.js.

        Args:
            filepath: Optional file path to save HTML

        Returns:
            HTML content
        """
        json_data = self.graph.to_json()

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Jenkins Topology Visualization</title>
    <script src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #1a1a1a;
            color: #fff;
        }}

        #header {{
            background: #2d2d2d;
            padding: 20px;
            border-bottom: 2px solid #00ff41;
        }}

        h1 {{
            margin: 0;
            color: #00ff41;
        }}

        #network {{
            width: 100%;
            height: calc(100vh - 100px);
            border: 1px solid #444;
        }}

        #controls {{
            padding: 10px 20px;
            background: #2d2d2d;
        }}

        button {{
            background: #00ff41;
            color: #000;
            border: none;
            padding: 10px 20px;
            margin-right: 10px;
            cursor: pointer;
            font-weight: 600;
            border-radius: 4px;
        }}

        button:hover {{
            background: #00cc33;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>Jenkins Infrastructure Topology</h1>
    </div>

    <div id="controls">
        <button onclick="network.fit()">Fit View</button>
        <button onclick="resetPhysics()">Reset Layout</button>
        <button onclick="togglePhysics()">Toggle Physics</button>
    </div>

    <div id="network"></div>

    <script>
        const graphData = {json_data};

        const nodeColors = {{
            server: '#3498db',
            agent: '#2ecc71',
            job: '#f39c12',
            plugin: '#95a5a6',
            plugin_group: '#e74c3c'
        }};

        const nodes = graphData.nodes.map(n => ({{
            id: n.id,
            label: n.label,
            color: nodeColors[n.type] || '#666',
            title: `Type: ${{n.type}}<br>${{JSON.stringify(n.metadata)}}`,
            shape: n.type === 'server' ? 'database' : 'box'
        }}));

        const edges = graphData.edges.map(e => ({{
            from: e.source,
            to: e.target,
            label: e.label,
            arrows: 'to',
            color: e.type === 'manages' ? '#3498db' : '#666'
        }}));

        const container = document.getElementById('network');
        const data = {{ nodes: nodes, edges: edges }};

        const options = {{
            physics: {{
                enabled: true,
                barnesHut: {{
                    gravitationalConstant: -2000,
                    centralGravity: 0.3,
                    springLength: 150,
                    springConstant: 0.04
                }},
                stabilization: {{
                    iterations: 100
                }}
            }},
            nodes: {{
                font: {{
                    color: '#fff',
                    size: 14
                }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                width: 2,
                smooth: {{
                    type: 'cubicBezier'
                }},
                font: {{
                    color: '#fff',
                    size: 12
                }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 100
            }}
        }};

        const network = new vis.Network(container, data, options);

        let physicsEnabled = true;

        function togglePhysics() {{
            physicsEnabled = !physicsEnabled;
            network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
        }}

        function resetPhysics() {{
            network.setOptions({{ physics: {{ enabled: true }} }});
            network.stabilize();
        }}

        network.on('click', function(params) {{
            if (params.nodes.length > 0) {{
                const nodeId = params.nodes[0];
                const node = graphData.nodes.find(n => n.id === nodeId);
                console.log('Selected node:', node);
            }}
        }});
    </script>
</body>
</html>"""

        if filepath:
            with open(filepath, 'w') as f:
                f.write(html_content)

        return html_content

    def get_statistics(self) -> dict[str, Any]:
        """
        Get topology statistics.

        Returns:
            Dictionary of statistics
        """
        node_types = defaultdict(int)
        for node in self.graph.nodes:
            node_types[node.type] += 1

        edge_types = defaultdict(int)
        for edge in self.graph.edges:
            edge_types[edge.type] += 1

        return {
            "total_nodes": len(self.graph.nodes),
            "total_edges": len(self.graph.edges),
            "node_types": dict(node_types),
            "edge_types": dict(edge_types),
            "metadata": self.graph.metadata
        }


def visualize_jenkins(
    session: JenkinsSession,
    layout: str = "force",
    export_format: str = "html",
    output_path: Optional[Path] = None
) -> str:
    """
    Convenience function to visualize Jenkins infrastructure.

    Args:
        session: Active Jenkins session
        layout: Layout algorithm (force, hierarchical, circular)
        export_format: Output format (json, dot, html)
        output_path: Optional output file path

    Returns:
        Exported data as string
    """
    visualizer = TopologyVisualizer()
    visualizer.build_from_session(session)
    visualizer.calculate_layout(layout)

    if export_format == "json":
        return visualizer.export_json(output_path)
    elif export_format == "dot":
        return visualizer.export_dot(output_path)
    elif export_format == "html":
        return visualizer.export_html(output_path)
    else:
        raise ValueError(f"Unsupported export format: {export_format}")
