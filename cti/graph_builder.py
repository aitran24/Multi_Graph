import json
import networkx as nx
import os
import matplotlib.pyplot as plt
from pyvis.network import Network

from CONSTANTS import CSS_VIEW

class GraphBuilder:
    def __init__(self):
        pass

    def build_graph_from_json(self, graph_data):
        G = nx.DiGraph()
        
        for ent in graph_data.get('entities', []):
            node_id = ent['id']
            G.add_node(node_id, **ent)
            
        for rel in graph_data.get('relationships', []):
            src = rel['source']
            dst = rel['target']
            action = rel['action']
            
            if G.has_node(src) and G.has_node(dst):
                G.add_edge(src, dst, action=action)

                
        return G

    def normalize_root_node(self, G):
        if len(G.nodes) == 0:
            return G
        
        roots = [n for n, d in G.in_degree() if d == 0]
        
        attacker_roots = [n for n in roots if G.nodes[n].get('type') in ['Attacker',]]
        
        if attacker_roots:
            pass
        else:
            
            virtual_root_id = "virtual_attacker_root"
            
            G.add_node(virtual_root_id, 
                       id=virtual_root_id, 
                       name="Attacker", 
                       type="Attacker", 
                       is_virtual=True)
            
            for r in roots:
                G.add_edge(virtual_root_id, r, action="uses/deploys")
                
        return G

    def calculate_levels(self, G):
        roots = [n for n, d in G.in_degree() if d == 0]
        
        nx.set_node_attributes(G, -1, 'level')
        
        for root in roots:
            try:
                levels = nx.single_source_shortest_path_length(G, root)
                
                for node_id, level in levels.items():

                    current_lvl = G.nodes[node_id]['level']
                    if current_lvl == -1 or level < current_lvl:
                        G.nodes[node_id]['level'] = level
                        
            except Exception as e:
                print(f"BFS Error: {e}")
                
        return G

    def process_technique_graphs(self, technique_id, graphs_list):
        processed_graphs = []
        
        for g_data in graphs_list:
            G = self.build_graph_from_json(g_data)
            
            G = self.normalize_root_node(G)
            
            G = self.calculate_levels(G)
            
            G.graph['source_text'] = g_data.get('source_text_snippet', '')
            G.graph['technique_id'] = technique_id
            
            processed_graphs.append(G)
            
        return processed_graphs

def serialize_graph(G):
    return nx.node_link_data(G)


def visualize_graph_static(G, title="Attack Graph"):
    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G, seed=42) 
    levels = [G.nodes[n].get('level', 0) for n in G.nodes]
    
    nx.draw(G, pos, 
            with_labels=True, 
            node_color=levels, 
            cmap=plt.cm.Pastel1, 
            node_size=1500, 
            font_size=10, 
            font_weight='bold',
            arrows=True)
    
    edge_labels = nx.get_edge_attributes(G, 'action')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    
    plt.title(title)
    plt.show()

def visualize_graph_interactive(G, output_file="graph.html"):
    """
    Vẽ động bằng Pyvis (Giao diện Overlay chuyên nghiệp)
    """
    # 1. Tạo thư mục
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 2. Cấu hình
    # TẮT filter_menu (vì nó tạo ra nhiều ô rác), chỉ giữ select_menu (tìm node)
    net = Network(height="100%", width="100%", directed=True, notebook=False, 
                  cdn_resources='remote', 
                  select_menu=True, filter_menu=False, # Tắt Filter cho gọn
                  bgcolor="#222222", font_color="white")
    
    # 3. Add Data (Giữ nguyên logic cũ)
    for n, attrs in G.nodes(data=True):
        label = attrs.get('label', attrs.get('name', str(n)))
        
        # Tooltip
        orig_names = "<br>".join(attrs.get('original_names', [])[:15])
        title_html = (
            f"<b>ID:</b> {n}<br>"
            f"<b>Type:</b> {attrs.get('type')}<br>"
            f"<b>Level:</b> {attrs.get('level')}<br>"
            f"<b>Sources:</b> {len(attrs.get('sources', []))}<br>"
            f"<hr><b>Variants:</b><br>{orig_names}"
        )

        color = "#97c2fc"
        n_type = attrs.get('type')
        if n_type == 'Attacker': color = "#ff6666"
        elif n_type == 'User': color = "#7be141"
        elif n_type == 'Process': color = "#66b3ff"
        elif n_type == 'File': color = "#ffff66"
        elif n_type == 'Registry': color = "#ffb366"
        elif n_type == 'Network': color = "#d279d2"

        size = 20 + (len(attrs.get('original_names', [])) * 2)
        size = min(size, 60)

        net.add_node(n, label=label, title=title_html, color=color, shape="dot", size=size)

    for src, dst, attrs in G.edges(data=True):
        actions = attrs.get('actions', [])
        label = ", ".join(actions) if isinstance(actions, list) else str(actions)
        net.add_edge(src, dst, label=label, title=label, arrows="to", color={"color": "white", "opacity": 0.5})

    # 4. Physics
    # Tinh chỉnh lực để đồ thị bung rộng ra
    net.barnes_hut(gravity=-3000, central_gravity=0.1, spring_length=250, spring_strength=0.04, damping=0.09)
    
    # QUAN TRỌNG: Tắt cái bảng điều khiển Physics khổng lồ đi
    # Nếu bạn muốn bật lại để debug, hãy uncomment dòng dưới, nhưng nó sẽ làm xấu giao diện
    # net.show_buttons(filter_=['physics']) 

    # 5. Lưu và Inject CSS Overlay
    try:
        net.save_graph(output_file)
        
        # Đọc file vừa sinh ra
        with open(output_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        # --- BƯỚC FIX LỖI GIAO DIỆN ---
        
        # 1. Xóa thẻ H1 rỗng và Center vô duyên của Pyvis
        html_content = html_content.replace('<center>\n<h1></h1>\n</center>', '')
        
        # 2. Xóa style mặc định gây lỗi (float: left, border...)
        # Pyvis thường sinh ra đoạn style id="mynetwork" mặc định, ta xóa nó đi để CSS của mình có tác dụng
        # Mẹo: Thay thế toàn bộ thẻ <style> cũ bằng <style> mới
        
        overlay_css = CSS_VIEW
        
        # Thay thế CSS cũ bằng CSS mới
        # Tìm vị trí đóng </style> cuối cùng để chèn đè hoặc chèn sau
        # Cách an toàn nhất: Chèn vào trước </head> và dùng !important để ghi đè mọi thứ
        html_content = html_content.replace('</head>', overlay_css + '</head>')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
    except Exception as e:
        print(f"Error saving HTML graph: {e}")
# ==========================================
# MAIN EXECUTION
# ==========================================

def run_construction_phase(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            refined_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
        return

    builder = GraphBuilder()
    constructed_data = {} 

    print(f"--- Starting Graph Construction & Leveling ---")

    for tech_code, graphs_list in refined_data.items():
        print(f"Constructing {tech_code}...")
        
        nx_graphs = builder.process_technique_graphs(tech_code, graphs_list)
        
        constructed_data[tech_code] = [serialize_graph(g) for g in nx_graphs]

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(constructed_data, f, ensure_ascii=False, indent=4)
    
    print(f"--- Construction Complete. Saved to {output_file} ---")


class GraphAggregator:
    def __init__(self):
        self.unified_graph = nx.DiGraph()
        self.node_registry = {} 

    def reset(self):
        self.unified_graph = nx.DiGraph()
        self.node_registry = {}

    def get_node_signature(self, node_data):
        level = node_data.get('level', -1)
        n_type = node_data.get('type', 'Unknown')
        name = node_data.get('name', '').lower() 
        ext = node_data.get('extension', '').lower()

        if level == 0 or n_type in ['Attacker']:
            return (0, 'Attacker', 'ROOT')

        if n_type == 'Process' or n_type == 'Process':
            return (level, n_type, name)

        if ext:
            return (level, n_type, ext, 'EXTENSION_GROUP')
        if node_data.get('subtype'):
            if node_data['subtype'] == 'IP_or_URL':
                return (level, n_type, name, 'NETWORK_GROUP')
            return (level, n_type, name,'GENERIC_GROUP')
        
        return (level, n_type, name, 'GENERIC_GROUP')

    def merge_single_graph(self, G_partial):
        local_to_unified = {}

        for nid, attrs in G_partial.nodes(data=True):
            signature = self.get_node_signature(attrs)
            
            if signature in self.node_registry:
                uid = self.node_registry[signature]
                
                u_node = self.unified_graph.nodes[uid]
                
                if attrs['name'] not in u_node['original_names']:
                    u_node['original_names'].append(attrs['name'])
                
            else:
                uid = f"U_{len(self.unified_graph)}" 
                self.node_registry[signature] = uid
                
                self.unified_graph.add_node(uid, 
                    type=attrs['type'],
                    level=attrs['level'],
                    label=attrs["name"], 
                    original_names=[attrs['name']],
                    is_generic=False
                )
            
            local_to_unified[nid] = self.node_registry[signature]

        for u, v, k in G_partial.edges(data=True): # k chứa attributes của edge
            u_uid = local_to_unified[u]
            v_uid = local_to_unified[v]
            
            action = k.get('action', 'unknown')

            if self.unified_graph.has_edge(u_uid, v_uid):
                if action not in self.unified_graph[u_uid][v_uid]['actions']:
                    self.unified_graph[u_uid][v_uid]['actions'].append(action)
            else:
                self.unified_graph.add_edge(u_uid, v_uid, actions=[action]) 


    def merge_across_layers(self):
        content_map = {}
        
        nodes_to_check = list(self.unified_graph.nodes(data=True))
        
        for nid, attrs in nodes_to_check:
            if attrs['type'] in ['Attacker', 'Threat Group']:
                continue
                
            ## For more robust merging
            # all_names = tuple(sorted([n.lower() for n in attrs['original_names']]))
            # key = (attrs['type'], all_names)

            primary_name = attrs['original_names'][0].lower()
            key = (attrs['type'], primary_name)
            
            if key not in content_map:
                content_map[key] = []
            content_map[key].append(nid)
            
        for key, nids in content_map.items():
            if len(nids) < 2:
                continue
                
            target_nid = nids[0]
            
            # Các nút còn lại sẽ bị gộp vào Target
            nodes_to_merge = nids[1:]
            
            for source_nid in nodes_to_merge:
                # A. Chuyển cạnh (Redirect Edges)
                
                # Cạnh đi vào (In-edges): Nối cha của Source vào Target
                for u, _, edge_attrs in self.unified_graph.in_edges(source_nid, data=True):
                    # Tránh tạo vòng lặp (Self-loop) nếu cha cũng là target
                    if u != target_nid:
                        if not self.unified_graph.has_edge(u, target_nid):
                            self.unified_graph.add_edge(u, target_nid, actions=edge_attrs['actions'])
                        else:
                            # Gộp action
                            self.unified_graph[u][target_nid]['actions'].extend(edge_attrs['actions'])
                            
                # Cạnh đi ra (Out-edges): Nối Target vào con của Source
                for _, v, edge_attrs in self.unified_graph.out_edges(source_nid, data=True):
                    if v != target_nid:
                        if not self.unified_graph.has_edge(target_nid, v):
                            self.unified_graph.add_edge(target_nid, v, actions=edge_attrs['actions'])
                        else:
                            self.unified_graph[target_nid][v]['actions'].extend(edge_attrs['actions'])
                
                # B. Gộp thuộc tính (Merge Attributes)
                target_attrs = self.unified_graph.nodes[target_nid]
                source_attrs = self.unified_graph.nodes[source_nid]
                
                # Gộp original_names (loại bỏ trùng lặp)
                new_names = set(target_attrs['original_names']) | set(source_attrs['original_names'])
                target_attrs['original_names'] = list(new_names)
                
                self.unified_graph.remove_node(source_nid)

    def finalize_graph(self):
        for nid, attrs in self.unified_graph.nodes(data=True):
            names = attrs['original_names']
            n_type = attrs['type']
            
            if len(names) > 1:
                if n_type == 'File':
                    exts = set()
                    for n in names:
                        if '.' in n: exts.add(f".{n.split('.')[-1]}")
                    
                    if exts:
                        ext_str = ", ".join(list(exts))
                        attrs['label'] = f"File (*{ext_str})"
                    else:
                        attrs['label'] = "File (Generic)"
                    
                    attrs['is_generic'] = True
                    
                elif n_type == 'Attacker':
                    attrs['label'] = "Attacker / Threat Group"

                
                else:
                    # Registry, Network...
                    attrs['label'] = f"{n_type} (Various)"
                    attrs['is_generic'] = True

            else:
                attrs['label'] = names[0]

        return self.unified_graph

    def aggregate_technique(self, nx_graphs_list):
        self.reset()
        
        for G in nx_graphs_list:
            self.merge_single_graph(G)

        self.merge_across_layers()
            
        return self.finalize_graph()

# ==========================================
# MAIN EXECUTION
# ==========================================

def run_aggregation_phase(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            constructed_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
        return

    aggregator = GraphAggregator()
    unified_results = {} 

    print(f"--- Starting Aggregation Phase ---")

    for tech_code, graphs_json_list in constructed_data.items():
        print(f"Aggregating {tech_code} ({len(graphs_json_list)} partial graphs)...")
        
        nx_graphs = [nx.node_link_graph(g_data) for g_data in graphs_json_list]
        
        unified_G = aggregator.aggregate_technique(nx_graphs)
        visualize_graph_interactive(unified_G, output_file=f"output/graphs/{tech_code}_unified_graph.html")
        
        unified_results[tech_code] = nx.node_link_data(unified_G)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(unified_results, f, ensure_ascii=False, indent=4)
    
    print(f"--- Aggregation Complete. Saved to {output_file} ---")

# --- CHẠY ---
if __name__ == "__main__":
    INPUT_PATH = 'output/constructed_res.json'
    OUTPUT_PATH = 'output/unified_res.json'
    
    run_aggregation_phase(INPUT_PATH, OUTPUT_PATH)