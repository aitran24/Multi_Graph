import os
import json
import time
import asyncio
import google.generativeai as genai
from dotenv import load_dotenv
from typing import Dict, List, Any
import CONSTANTS as prompts_config

API_CALLING_ERROR = False

# ==================== NEW GLOBAL VARIABLE ====================
failed_chunks = {} 
# =============================================================

load_dotenv()
GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")

genai.configure(api_key=GOOGLE_API_KEY)

def extract_cti_from_technique(technique_data: Dict[str, Any], model_name: str = "gemini-2.5-pro") -> Dict[str, Any]:
    """
    Function to extract Entities and Relationships from a list of CTI descriptions for a technique.
    
    Args:
        technique_data (dict): Dictionary containing technique data (e.g., key "decriptions").
        model_name (str): Model name (gemini-2.5-pro, gemini-2.5-flash).
    
    Returns:
        dict: JSON object containing the list of extracted graphs.
    """
    
    # 1. Get the descriptions list
    # Handle misspelled key "decriptions" in sample data or the correct "descriptions"
    descriptions_list = technique_data.get("decriptions", technique_data.get("descriptions", []))
    
    if not descriptions_list:
        print("Warning: Không tìm thấy mô tả nào trong dữ liệu đầu vào.")
        return {"graphs": []}

    descriptions_json_str = json.dumps(descriptions_list, ensure_ascii=False)

    prompt = prompts_config.CTI_PARSER_PROMPT + f"""\n 
    ### INPUT DATA (JSON List):
    {descriptions_json_str}
    """

    generation_config = prompts_config.GENAI_CONFIG

    try:
        model = genai.GenerativeModel(
            model_name=model_name,
            generation_config=generation_config,
        )
 
        # Send request
        response = model.generate_content(prompt)
        
        # Parse the returned result
        result_json = json.loads(response.text)
        return result_json

    except Exception as e:
        global API_CALLING_ERROR
        API_CALLING_ERROR = True
        print(f"Error calling Gemini API: {e}")
        # Throw exception to be caught in send_request
        raise e 
    

async def send_request(descriptions: dict) -> Dict[str, Any]:
    current_tech_code = descriptions.get('tech_code', 'unknown_technique')
    desc_list = descriptions.get('descriptions', [])

    # Hàm con để xử lý từng chunk độc lập (Wrapper)
    async def process_single_chunk(chunk):
        try:
            technique_data = {
                "descriptions": chunk,
                'tech_code': current_tech_code
            }
            response = await asyncio.to_thread(extract_cti_from_technique, technique_data)
            
            print(f"Processed chunk for {current_tech_code}") 
            
            return response.get('graphs', [])
            
        except Exception as e:
            print(f"Error processing chunk for {current_tech_code}: {e}")
            if current_tech_code not in failed_chunks:
                failed_chunks[current_tech_code] = []
            failed_chunks[current_tech_code].append(chunk)
            return [] # Trả về list rỗng nếu lỗi

    # ---------------------------------------------------------
    
    if len(desc_list) >= 5:
        chunk_size = 15
        chunks = [desc_list[i:i + chunk_size] for i in range(0, len(desc_list), chunk_size)]
        
        tasks = []
        for chunk in chunks:
            task = process_single_chunk(chunk)
            tasks.append(task)
            
            await asyncio.sleep(2) 

        results_list = await asyncio.gather(*tasks)
        

        final_results = []
        for res in results_list:
            final_results.extend(res)

        return {"graphs": final_results, "tech_code": current_tech_code}


    try: 
        technique_data = descriptions
        response = await asyncio.to_thread(extract_cti_from_technique, technique_data)
        return response
        
    except Exception as e: # ==================== ADDED CATCH ====================
        print(f"Error processing single request for {current_tech_code}: {e}")
        if current_tech_code not in failed_chunks:
            failed_chunks[current_tech_code] = []
        failed_chunks[current_tech_code].append(desc_list)
        return {"graphs": [], "tech_code": current_tech_code}


# ========================================== HANDLE PHASE ==========================================

def load_full_technique_examples(file_path: str) -> dict:
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



full_res = {}
async def main():
    json_data = load_full_technique_examples('output/full_technique.json')

    needed_techniques = ['T1059.001', 'T1204.002', 'T1218.005', 'T1218.011', 'T1003.001', 'T1003.002', 'T1112', 'T1547.001', 'T1548.002', 'T1482'] 

    tasks = []

    for tech_code in needed_techniques:
        full_res[tech_code] = {} 

    for tech_code in needed_techniques:
        technique_data = json_data.get(tech_code, {})
        descriptions = technique_data.get('decriptions', technique_data.get('descriptions', []))

        if not descriptions:
            print(f"Warning: No descriptions found for technique {tech_code}. Skipping.")
            continue

        technique_info = {
            "descriptions": descriptions,
            "tech_code": tech_code
        }

        print(technique_info)

        print(f"Processing technique {tech_code} with {len(descriptions)} descriptions...")

        task = asyncio.create_task(send_request(technique_info))
        tasks.append(task)

    for future in asyncio.as_completed(tasks):
        response = await future
        tech_code = response.get('tech_code', 'unknown_technique')
        full_res[tech_code] = response.get('graphs', [])
        print(f"Completed processing for technique {tech_code}.")

    print("\nSaving failed chunks to output/failed_chunks.json...")
    with open('output/failed_chunks.json', 'w', encoding='utf-8') as f:
        json.dump(failed_chunks, f, ensure_ascii=False, indent=4)

asyncio.run(main())

# Save the full_res to json
with open('output/full_res.json', 'w', encoding='utf-8') as f:
    json.dump(full_res, f, ensure_ascii=False, indent=4)