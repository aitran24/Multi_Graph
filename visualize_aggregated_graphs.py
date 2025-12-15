"""
Aggregated Graph Visualizer - Detection Template Edition
========================================================
Visualize aggregated graphs (v3.0) for real-time detection templates.
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
from typing import Dict
import textwrap

# Configuration
INPUT_DIR = Path(r"d:\nckh\auditlog\output_aggregated")
VIZ_DIR = Path(r"d:\nckh\auditlog\aggregation_visual")
VIZ_DIR.mkdir(exist_ok=True)

# Node Styles (Black & White / Paper Style)
NODE_STYLES = {
    'Process': {
        'boxstyle': 'square,pad=0.5',
        'ec': 'black',
        'fc': 'white',
        'lw': 2.0
    },
    'File': {
        'boxstyle': 'circle,pad=0.5',
        'ec': 'black',
        'fc': 'white',
        'lw': 2.0
    },
    'Registry': {
        'boxstyle': 'round4,pad=0.5,rounding_size=0.5',
        'ec': 'black',
        'fc': 'white',
        'lw': 2.0
    },
    'Network': {
        'boxstyle': 'round4,pad=0.5,rounding_size=0.2',
        'ec': 'black',
        'fc': 'white',
        'lw': 2.0
    },
    'Image': {
        'boxstyle': 'circle,pad=0.5',
        'ec': 'black',
        'fc': 'lightgray',
        'lw': 2.0
    },
    'Unknown': {
        'boxstyle': 'round,pad=0.5',
        'ec': 'black',
        'fc': 'white',
        'lw': 2.0
    }
}

def load_aggregated_graph(technique_id: str) -> Dict:
    """Load aggregated graph v3.0"""
    graph_file = INPUT_DIR / f"{technique_id}_graph_v3.0.json"
    
    if not graph_file.exists():
        print(f"⚠️  File not found: {graph_file}")
        return None
    
    with open(graph_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_label(node_data: Dict) -> str:
    """Extract concise label from node"""
    props = node_data.get('properties', {})
    node_type = node_data.get('type', 'Unknown')
    
    # Try different property names
    candidates = [
        props.get('label'),
        props.get('path'),
        props.get('image'),
        props.get('key'),
        props.get('commandLine'),
    ]
    
    raw_label = None
    for candidate in candidates:
        if candidate:
            raw_label = candidate
            break
    
    # Special case: Network nodes
    if not raw_label and node_type == 'Network':
        raw_label = props.get('address', props.get('ip', ''))
        if props.get('port'):
            raw_label = f"{raw_label}:{props['port']}"
    
    # Fallback
    if not raw_label:
        raw_label = node_data.get('id', 'Unknown')
    
    # Shorten path (get filename only)
    if '\\' in raw_label or '/' in raw_label:
        raw_label = Path(raw_label).name
    
    # Special cleanup for common processes
    if 'powershell' in raw_label.lower():
        raw_label = 'powershell.exe'
    elif 'cmd' in raw_label.lower() and '.exe' in raw_label.lower():
        raw_label = 'cmd.exe'
    
    # Wrap long text
    label = "\n".join(textwrap.wrap(raw_label, width=15))
    
    return label

def build_hierarchy(G):
    """Build hierarchical layout (left to right)"""
    # Find roots (nodes with no incoming edges)
    roots = [n for n, d in G.in_degree() if d == 0]
    
    if not roots:
        # If no roots, use node with highest out-degree
        if G.number_of_nodes() > 0:
            roots = [max(G.nodes(), key=lambda n: G.out_degree(n))]
        else:
            return G
    
    # Assign layers based on shortest path from root
    layers = {}
    for root in roots:
        lengths = nx.single_source_shortest_path_length(G, root)
        for node, length in lengths.items():
            layers[node] = max(layers.get(node, 0), length)
    
    # Assign layer 0 to unreachable nodes
    for node in G.nodes():
        if node not in layers:
            layers[node] = 0
    
    # Push non-Process nodes one layer further
    for node, data in G.nodes(data=True):
        if data.get('type') != 'Process':
            preds = list(G.predecessors(node))
            if preds:
                max_pred_layer = max(layers[p] for p in preds)
                layers[node] = max(layers[node], max_pred_layer + 1)
    
    # Network nodes go to the end
    for node, data in G.nodes(data=True):
        if data.get('type') == 'Network':
            layers[node] = max(layers.values(), default=0) + 1
    
    nx.set_node_attributes(G, layers, 'subset')
    return G

def visualize_aggregated_graph(technique_id: str):
    """Generate visualization for aggregated graph"""
    print(f"\n🎨 Visualizing {technique_id}...")
    
    data = load_aggregated_graph(technique_id)
    if not data:
        return
    
    G = nx.DiGraph()
    
    # Add nodes
    for node in data.get('nodes', []):
        node_id = node['id']
        node_type = node.get('type', 'Unknown')
        label = extract_label(node)
        
        G.add_node(node_id, type=node_type, label=label)
    
    # Add edges
    for edge in data.get('edges', []):
        source = edge['source']
        target = edge['target']
        
        if source in G.nodes() and target in G.nodes():
            G.add_edge(source, target)
    
    # Remove isolated nodes
    G.remove_nodes_from(list(nx.isolates(G)))
    
    if G.number_of_nodes() == 0:
        print(f"  ⚠️  Graph is empty after filtering")
        return
    
    # Filter disconnected components (keep only main component)
    if G.number_of_nodes() > 0:
        components = list(nx.weakly_connected_components(G))
        
        if len(components) > 1:
            print(f"  📊 Graph has {len(components)} components, keeping largest")
            largest = max(components, key=len)
            nodes_to_remove = set(G.nodes()) - largest
            G.remove_nodes_from(list(nodes_to_remove))
    
    # Build hierarchy and layout
    G = build_hierarchy(G)
    pos = nx.multipartite_layout(G, subset_key='subset', align='horizontal')
    
    # Scale positions for better spacing
    for node in pos:
        x, y = pos[node]
        pos[node] = (x * 4, y * 6)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(28, 16))
    
    # Draw invisible scatter for auto-scaling
    xs = [pos[n][0] for n in G.nodes()]
    ys = [pos[n][1] for n in G.nodes()]
    ax.scatter(xs, ys, s=0, alpha=0)
    
    # Draw edges (arrows)
    for u, v in G.edges():
        x_start, y_start = pos[u]
        x_end, y_end = pos[v]
        
        ax.annotate("",
                    xy=(x_end, y_end), xycoords='data',
                    xytext=(x_start, y_start), textcoords='data',
                    arrowprops=dict(
                        arrowstyle="-|>",
                        color="black",
                        shrinkA=20, shrinkB=20,
                        connectionstyle="arc3,rad=-0.1",
                        linewidth=1.5
                    ),
                    zorder=1)
    
    # Draw nodes
    for node, data in G.nodes(data=True):
        x, y = pos[node]
        label = data['label']
        node_type = data['type']
        
        style = NODE_STYLES.get(node_type, NODE_STYLES['Unknown'])
        
        ax.text(x, y, label,
                ha='center', va='center',
                fontsize=11, fontweight='bold',
                color='black',
                bbox=style,
                zorder=2)
    
    # Add metadata info
    metadata = data.get('metadata', {})
    if 'aggregation_stats' in metadata:
        stats = metadata['aggregation_stats']
        info_text = (
            f"Aggregated Detection Template (v3.0)\n"
            f"Original: {stats.get('original_nodes', 0)} nodes, {stats.get('original_edges', 0)} edges\n"
            f"Final: {stats.get('final_nodes', 0)} nodes (-{stats.get('removed_noise_nodes', 0)} noise, "
            f"-{stats.get('merged_nodes', 0)} merged)\n"
            f"Ready for real-time detection"
        )
        
        plt.text(0.02, 0.98, info_text,
                 transform=ax.transAxes,
                 fontsize=10,
                 verticalalignment='top',
                 bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
    
    # Add legend
    legend_text = "□ Process\n○ File/Image\n◇ Registry\n⬢ Network"
    plt.text(0.98, 0.02, legend_text,
             transform=ax.transAxes,
             fontsize=12,
             verticalalignment='bottom',
             horizontalalignment='right',
             bbox=dict(boxstyle='round', facecolor='white', alpha=0.9))
    
    # Title
    plt.title(f"Detection Template: {technique_id} (Aggregated v3.0)",
              fontsize=22, fontweight='bold', pad=20)
    plt.axis('off')
    plt.tight_layout()
    
    # Save
    save_path = VIZ_DIR / f"{technique_id}_aggregated.png"
    plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"  ✅ Saved: {save_path}")
    plt.close()

def main():
    """Generate visualizations for all aggregated graphs"""
    techniques = [
        'T1003.001', 'T1003.002', 'T1059.001', 'T1112', 'T1204.002',
        'T1218.005', 'T1218.011', 'T1482', 'T1547.001', 'T1548.002'
    ]
    
    print("="*80)
    print("🎨 Generating Visualizations for Aggregated Detection Templates")
    print("="*80)
    
    success_count = 0
    for technique_id in techniques:
        try:
            visualize_aggregated_graph(technique_id)
            success_count += 1
        except Exception as e:
            print(f"  ❌ Error visualizing {technique_id}: {e}")
    
    print("\n" + "="*80)
    print(f"✅ Visualization Complete: {success_count}/{len(techniques)} graphs generated")
    print(f"📁 Output directory: {VIZ_DIR}")
    print("="*80)

if __name__ == "__main__":
    main()
