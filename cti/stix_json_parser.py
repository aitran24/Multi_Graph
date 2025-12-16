import json 
import os
import sys

def read_stix_json(file_path) -> dict:
    """Reads a STIX JSON file and returns its content as a Python dictionary."""
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data['objects']

def extract_attack_ids(json_data: dict) -> dict:
    """Extract a list of attack technique from MITRE ATT&CK framework"""
    techniques = {
        'techniques': [],
        'extend_mitre': {},
        '__helper__': 'Use "techniques" key to access the list of techniques with their IDs and MITRE codes. Use "extend_mitre" key to access the list of techniques without MITRE codes.'
    }
    
    for item in json_data:
        if item.get('type') != 'attack-pattern':
            continue

        if not item.get('id'):
            print("Warning: 'attack-pattern' item without 'id' found.")

        mitre_code = item.get('external_references', [])
        if mitre_code:
            mitre_code = mitre_code[0].get('external_id', '')
            if 'T1' not in mitre_code:
                print(f"Warning: 'attack-pattern' item with id {item['id']} has no 'external_id' in 'external_references'.")
                techniques['extend_mitre'].append({
                    'url': mitre_code[0].get('url', ''),
                    'technique': mitre_code.get('external_id', ''),
                })
                
        temp_dict = {
            'id': item['id'],
            'mitre_code': mitre_code
        }
        techniques['techniques'].append(temp_dict)

    return techniques


def get_procedure_examples(json_data: dict, technique_id:  str) -> dict:
    """Extract procedure examples for a given technique ID from the STIX JSON data."""
    atomic_attack = {
        'decriptions': [],
        'atomic_attacks': [],
        '__helper__': 'Use "atomic_attacks" key to access the list of procedure examples. Use "decriptions" key to access the list of descriptions only.'
    }
    
    for item in json_data:
        if item.get('type') == 'relationship':
            if item.get('target_ref') == technique_id and item.get('relationship_type') == 'uses':
                attack_info = {
                    'description': item.get('description', 'No description available'),
                    'parrent_technique': technique_id,
                    'external_refs': item.get('external_references', [])
                }
                atomic_attack['atomic_attacks'].append(attack_info)
                atomic_attack['decriptions'].append(attack_info['description'])

    return atomic_attack


def load_full_technique_examples(file_path: str) -> dict:
    """Load existing full_technique.json file if it exists."""
    print("\n" + "="*50 + "\n")
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            print(data['__helper__'])

            first_element = next(iter(data))
            print(data[first_element]['__helper__'])

            return data

    print("No existing full_technique.json file found. A new one will be created.")
    return {}


def main():
    print("Starting STIX JSON parsing...")
    json_data = read_stix_json('enterprise-attack.json')

    print("Extracting technique IDs...")
    mitre_techniques, extend_mitre = extract_attack_ids(json_data)['techniques'], extract_attack_ids(json_data)['extend_mitre']
    print(f"Found {len(mitre_techniques)} technique IDs.")


    print("Extracting procedure examples for each technique...")
    full_technique_examples = {}
    for technique in mitre_techniques:
        technique_id = technique['id']
        mitre_code = technique['mitre_code']
        examples = get_procedure_examples(json_data, technique_id)
        full_technique_examples[mitre_code] = examples

    # Count inner number of atomic attack
    total_atomic_attacks = sum(len(examples['atomic_attacks']) for examples in full_technique_examples.values() if isinstance(examples, dict))
    print(f"Total number of atomic attacks: {total_atomic_attacks}")

    full_technique_examples['extend_mitre'] = extend_mitre

    full_technique_examples['__helper__'] = 'Use technique MITRE code as keys to access procedure examples for each technique.'

    if not os.path.exists('output'):
        os.makedirs('output')

    output_file_path = os.path.join('output', 'full_technique.json')
    with open(output_file_path, 'w') as outfile:
        json.dump(full_technique_examples, outfile, indent=4)


if __name__ == "__main__":
    main()

    json_data = load_full_technique_examples('output/full_technique.json') 