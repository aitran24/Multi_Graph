"""
MultiKG Graph Visualizer - Paper Style Edition (Black & White / Text-in-Node)
=============================================================================
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
from typing import Dict
import textwrap

# Configuration
OUTPUT_DIR = Path(r"d:\nckh\auditlog\output")
VIZ_DIR = Path(r"d:\nckh\auditlog\visualizations_paper_style")
VIZ_DIR.mkdir(exist_ok=True)

# --- CONFIGURATION STYLE ---

# Cấu hình hình dáng cho từng loại Node (Matplotlib BoxStyle)
# Tham khảo: https://matplotlib.org/stable/gallery/shapes_and_collections/fancybox_demo.html
NODE_STYLES = {
    'Process': {
        'boxstyle': 'square,pad=0.5',  # Hình chữ nhật/Vuông
        'ec': 'black',                 # Màu viền
        'fc': 'white',                 # Màu nền
        'lw': 1.5                      # Độ dày viền
    },
    'File': {
        'boxstyle': 'circle,pad=0.5',  # Hình tròn/Elip
        'ec': 'black',
        'fc': 'white', 
        'lw': 1.5
    },
    'Registry': {
        'boxstyle': 'darrow,pad=0.3',  # Hình thoi (Xấp xỉ) hoặc dùng 'diamond' nếu bản mới hỗ trợ
        # Mẹo: boxstyle 'diamond' căn text hơi khó, ta dùng 'square' xoay hoặc L-arrow.
        # Ở đây ta dùng 'sawtooth' hoặc 'round4' để khác biệt, hoặc quay về 'square' xoay 45 độ (phức tạp).
        # Tốt nhất cho báo cáo: Dùng hình thoi chuẩn. Matplotlib text boxstyle 'diamond' có sẵn.
        'boxstyle': 'rarrow,pad=0.3', # Tạm dùng mũi tên hoặc diamond nếu có
        'ec': 'black',
        'fc': 'white',
        'lw': 1.5
    },
    'Network': {
        'boxstyle': 'round4,pad=0.5,rounding_size=0.2', # Hình chữ nhật bo góc hoặc xiên
        'ec': 'black',
        'fc': 'white',
        'lw': 1.5
    },
    'Unknown': {
        'boxstyle': 'round,pad=0.5',
        'ec': 'black',
        'fc': 'white',
        'lw': 1.5
    }
}

# Override riêng cho Registry để ra hình thoi chuẩn hơn nếu cần
def get_node_style(node_type):
    style = NODE_STYLES.get(node_type, NODE_STYLES['Unknown']).copy()
    if node_type == 'Registry':
        # Matplotlib boxstyle không có hình thoi hoàn hảo bao quanh text dễ dàng
        # Ta dùng lục giác hoặc vuông tạm, hoặc 'round4'
        style['boxstyle'] = 'round4,pad=0.5,rounding_size=0.5' 
    return style

def load_graph(technique_id: str) -> Dict:
    graph_file = OUTPUT_DIR / f"{technique_id}_graph_v2.2.json"
    if not graph_file.exists():
        graph_file = OUTPUT_DIR / f"{technique_id}_graph.json"
        
    if not graph_file.exists():
        print(f"File not found: {graph_file}")
        return None
        
    with open(graph_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def build_hierarchy(G):
    """Phân tầng node để vẽ trái qua phải (Process cha -> con -> file)"""
    roots = [n for n, d in G.in_degree() if d == 0]
    if not roots:
        roots = [sorted(G.nodes(), key=lambda n: G.out_degree(n), reverse=True)[0]]

    layers = {node: 0 for node in G.nodes()}
    
    # Gán layer cơ bản
    for root in roots:
        lengths = nx.single_source_shortest_path_length(G, root)
        for node, length in lengths.items():
            layers[node] = max(layers.get(node, 0), length)

    # Tinh chỉnh: Đẩy File/Registry/Network ra sau Process
    for node, data in G.nodes(data=True):
        if data['type'] != 'Process':
            preds = list(G.predecessors(node))
            if preds:
                layers[node] = layers[preds[0]] + 1
    
    # Tinh chỉnh: Network node nên ở layer cuối cùng hoặc layer riêng
    for node, data in G.nodes(data=True):
        if data['type'] == 'Network':
            layers[node] = max(layers.values()) + 1

    nx.set_node_attributes(G, layers, 'subset')
    return G

# --- HÀM LỌC NHIỄU (QUAN TRỌNG ĐỂ HÌNH ĐẸP) ---
def is_noise(node_data):
    # Danh sách từ khóa rác
    NOISE_KEYWORDS = ["Write-Host", "Start-Sleep", "Get-Prereqs", "Check-Prereqs", 
                      "Get-PackageProvider", "btool", "splunkd", "amazon-ssm"]
    
    cmd = node_data.get('properties', {}).get('command_line', '')
    label = node_data.get('properties', {}).get('label', '')
    
    if cmd:
        for kw in NOISE_KEYWORDS:
            if kw.lower() in cmd.lower(): return True
    if "svchost" in label and not cmd: return True # Lọc svchost nền
    
    return False

def draw_paper_style(technique_id: str):
    data = load_graph(technique_id)
    if not data: return

    G = nx.DiGraph()
    
    # 1. Thêm Node (Có lọc nhiễu)
    valid_ids = set()
    for node in data['nodes']:
        if not is_noise(node):
            valid_ids.add(node['id'])
            
            props = node.get('properties', {})
            # Lấy tên ngắn gọn nhất
            raw_label = props.get('label') or props.get('path') or props.get('image')
            
            # Xử lý riêng cho Network node
            if not raw_label and node['type'] == 'Network':
                raw_label = props.get('address')
                if props.get('port'):
                    raw_label = f"{raw_label}:{props['port']}"
            
            # Fallback
            if not raw_label:
                raw_label = node['id']

            raw_label = str(Path(raw_label).name)
            
            # Xử lý tên đặc biệt
            if "powershell" in raw_label.lower(): raw_label = "Powershell.exe"
            if "cmd" in raw_label.lower(): raw_label = "cmd.exe"
            
            # Ngắt dòng nếu tên quá dài
            label = "\n".join(textwrap.wrap(raw_label, width=12))
            
            G.add_node(node['id'], type=node['type'], label=label)

    # 2. Thêm Cạnh
    for edge in data['edges']:
        if edge['source'] in valid_ids and edge['target'] in valid_ids:
            G.add_edge(edge['source'], edge['target'])

    # Xóa node cô lập sau khi lọc
    G.remove_nodes_from(list(nx.isolates(G)))

    # --- LỌC THÀNH PHẦN LIÊN THÔNG (CONNECTED COMPONENTS) ---
    # Chỉ giữ lại thành phần lớn nhất hoặc các thành phần chứa node quan trọng
    if G.number_of_nodes() > 0:
        # Lấy danh sách các thành phần liên thông yếu (Weakly Connected Components)
        components = list(nx.weakly_connected_components(G))
        
        # Nếu có nhiều hơn 1 thành phần, ta cần lọc
        if len(components) > 1:
            print(f"Graph {technique_id} has {len(components)} disconnected components. Filtering...")
            
            # Định nghĩa các node "quan trọng" (Attack Indicators)
            IMPORTANT_KEYWORDS = ['cmd.exe', 'powershell', 'rundll32', 'reg.exe', 'mimikatz', 'procdump', 'test.bat', 'atomic']
            
            kept_nodes = set()
            
            # 1. Luôn giữ thành phần lớn nhất (Main Component)
            largest_comp = max(components, key=len)
            kept_nodes.update(largest_comp)
            
            # 2. Giữ các thành phần khác NẾU chúng chứa node quan trọng
            for comp in components:
                if comp == largest_comp: continue
                
                is_important = False
                for node_id in comp:
                    node_data = G.nodes[node_id]
                    label = node_data.get('label', '').lower()
                    if any(kw in label for kw in IMPORTANT_KEYWORDS):
                        is_important = True
                        break
                
                if is_important:
                    kept_nodes.update(comp)
                else:
                    # Debug: In ra thành phần bị loại bỏ để kiểm tra
                    # print(f"Removed noise component with {len(comp)} nodes: {[G.nodes[n]['label'] for n in comp]}")
                    pass
            
            # Xóa các node không được giữ
            all_nodes = set(G.nodes())
            nodes_to_remove = all_nodes - kept_nodes
            G.remove_nodes_from(list(nodes_to_remove))

    if G.number_of_nodes() == 0: 
        print(f"Graph {technique_id} is empty after filtering.")
        return

    # 3. Layout (Phân cấp Trái -> Phải)
    G = build_hierarchy(G)
    pos = nx.multipartite_layout(G, subset_key="subset", align='horizontal')
    
    # Tăng khoảng cách giữa các node để không bị đè
    # Scale x và y thủ công
    for node, coords in pos.items():
        pos[node] = (coords[0] * 3, coords[1] * 5) # Kéo giãn ra

    # 4. Vẽ (Matplotlib Style)
    plt.figure(figsize=(24, 14)) # Khổ ảnh rộng
    ax = plt.gca()
    
    # Hack: Vẽ scatter vô hình để Matplotlib tự căn chỉnh khung hình (Auto-scale)
    # Nếu chỉ dùng text() và annotate(), Matplotlib đôi khi không tự scale đúng.
    xs = [pos[n][0] for n in G.nodes()]
    ys = [pos[n][1] for n in G.nodes()]
    ax.scatter(xs, ys, s=0, alpha=0) # Điểm vô hình

    # Vẽ Edges trước (Mũi tên đen)
    for u, v in G.edges():
        x_start, y_start = pos[u]
        x_end, y_end = pos[v]
        
        # Vẽ mũi tên
        ax.annotate("",
                    xy=(x_end, y_end), xycoords='data',
                    xytext=(x_start, y_start), textcoords='data',
                    arrowprops=dict(arrowstyle="-|>", color="black", 
                                    shrinkA=15, shrinkB=15, # Khoảng cách mũi tên với node
                                    connectionstyle="arc3,rad=-0.1", # Đường cong nhẹ
                                    linewidth=1.2),
                    zorder=1)

    # Vẽ Nodes (Dùng Text Box thay vì Marker)
    for node, data in G.nodes(data=True):
        x, y = pos[node]
        label = data['label']
        n_type = data['type']
        
        style = get_node_style(n_type)
        
        # Vẽ Text Box
        ax.text(x, y, label,
                ha='center', va='center',
                fontsize=10, fontweight='bold',
                color='black',
                bbox=style, # Đây là phần tạo hình dáng (Vuông/Tròn/...)
                zorder=2)

    # 5. Legend thủ công (Để khớp với hình dáng)
    # Tạo các patch giả để làm chú thích
    legend_patches = [
        mpatches.Patch(facecolor='white', edgecolor='black', label='Process (Rect)'),
        mpatches.Circle((0,0), facecolor='white', edgecolor='black', label='File/Image (Circle)'),
        mpatches.RegularPolygon((0,0), 5, radius=5, facecolor='white', edgecolor='black', label='Network/Reg (Poly)')
    ]
    # Do matplotlib legend khó hiển thị đúng boxstyle của text, ta dùng custom legend đơn giản
    # Hoặc vẽ legend "giả" bằng text bên góc
    
    # Vẽ Legend giả ở góc dưới phải
    plt.text(0.95, 0.05, 
             "□ Process/Thread\n○ File/Image\n◇ Registry/Network", 
             transform=ax.transAxes, 
             fontsize=14, 
             verticalalignment='bottom', horizontalalignment='right',
             bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

    plt.title(f"Attack Graph: {technique_id}", fontsize=20, fontweight='bold', pad=20)
    plt.axis('off')
    plt.tight_layout()
    
    save_path = VIZ_DIR / f"{technique_id}_report_style.png"
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"Generated: {save_path}")
    plt.close()

if __name__ == "__main__":
    techniques = [
        'T1003.001', 'T1003.002', 'T1059.001', 'T1112', 'T1204.002',
        'T1218.005', 'T1218.011', 'T1482', 'T1547.001', 'T1548.002'
    ]
    
    print("Generating Report-Style Graphs...")
    for tid in techniques:
        try:
            draw_paper_style(tid)
        except Exception as e:
            print(f"Error drawing {tid}: {e}")