import json
import re
import os

class IOCRefiner:
    def __init__(self):
        self.patterns = {
            'IP': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Registry': r'(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|SYSTEM\\CurrentControlSet)\\',
            'File_Extension': r'\.([a-zA-Z0-9]{2,4})$',
            'Process': r'\.exe$', 
            'URL': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        }

        # 2. Từ điển ánh xạ (Domain Knowledge) để suy luận đuôi file
        self.extension_inference = {
            'powershell': ['.ps1'],
            'script': ['.ps1', '.vbs', '.js', '.bat', '.cmd'],
            'executable': ['.exe'],
            'binary': ['.exe', '.dll'],
            'dll': ['.dll'],
            'document': ['.docx', '.doc', '.pdf', '.rtf'],
            'word': ['.docx', '.doc'],
            'excel': ['.xlsx', '.xls'],
            'shortcut': ['.lnk'],
            'archive': ['.zip', '.rar', '.7z', '.tar'],
            'iso': ['.iso'],
            'img': ['.img'],
            'library': ['.dll']
        }

        self.process_mapping = {
            'powershell': 'powershell.exe',
            'cmd': 'cmd.exe',
            'wscript': 'wscript.exe',
            'cscript': 'cscript.exe',
            'rundll32': 'rundll32.exe',
            'regsvr32': 'regsvr32.exe',
            'mshta': 'mshta.exe'
        }

    def refine_entity(self, entity):
        """
        Hàm chính để tinh chỉnh một entity.
        Input: Entity dict (id, name, type)
        Output: Refined Entity dict (thêm fields: subtype, extension, normalized_name...)
        """
        original_name = entity.get('name', '').strip()
        original_type = entity.get('type', 'Unknown')
        
        refined = entity.copy()
        
        lower_name = original_name.lower()
        
        if original_type in ['Process', 'File']:
            for key, val in self.process_mapping.items():
                if lower_name == key or lower_name == val:
                    refined['name'] = val 
                    refined['type'] = 'Process' 
                    break
        
        if re.search(self.patterns['IP'], original_name) or re.search(self.patterns['URL'], original_name):
            refined['type'] = 'Network'
            refined['subtype'] = 'IP_or_URL'
            
        elif re.search(self.patterns['Registry'], original_name, re.IGNORECASE):
            refined['type'] = 'Registry'
            
        elif re.search(self.patterns['Email'], original_name):
            refined['type'] = 'Network' 
            refined['subtype'] = 'EmailAddress'
        
        if refined['type'] in ['File']:
            ext_match = re.search(self.patterns['File_Extension'], original_name)
            
            if ext_match:
                refined['extension'] = f".{ext_match.group(1).lower()}"
                
                if refined['extension'] == '.exe':
                    refined['is_executable'] = True
            
            else:
                found_ext = False
                for keyword, exts in self.extension_inference.items():
                    if keyword in lower_name:
                        refined['extension'] = exts[0] 
                        refined['potential_extensions'] = exts 
                        refined['name'] += exts[0]
                        found_ext = True
                        break
                
                if not found_ext:
                    refined['extension'] = 'generic'

        abstract_terms = ['payload', 'malware', 'implant', 'tool', 'agent', 'backdoor', 'shellcode']
        if any(term in lower_name for term in abstract_terms) and refined['type'] not in ['Process', 'Attacker']:
            refined['type'] = 'File' # 
            refined['is_generic'] = True

        return refined

    def process_graph_list(self, technique_id, graphs):
        refined_graphs = []
        for g in graphs:
            refined_g = g.copy()
            refined_g['entities'] = [self.refine_entity(ent) for ent in g['entities']]
            refined_graphs.append(refined_g)
        return refined_graphs


def run_refinement_phase(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
        return

    refiner = IOCRefiner()
    refined_data = {}

    print(f"--- Starting Refinement Phase on {len(raw_data)} techniques ---")

    for tech_code, graphs_list in raw_data.items():
        print(f"Processing {tech_code} ({len(graphs_list)} graphs)...")
        
        refined_list = refiner.process_graph_list(tech_code, graphs_list)
        refined_data[tech_code] = refined_list

 
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(refined_data, f, ensure_ascii=False, indent=4)
    
    print(f"--- Refinement Complete. Saved to {output_file} ---")


if __name__ == "__main__":
    INPUT_PATH = 'output/full_res.json' 
    OUTPUT_PATH = 'output/refined_res.json'
    
    run_refinement_phase(INPUT_PATH, OUTPUT_PATH)