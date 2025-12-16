CTI_PARSER_PROMPT = f"""
    You are an expert Cyber Threat Intelligence (CTI) Analyst and Knowledge Graph Engineer.
    
    ### TASK:
    I will provide a list of "Procedure Examples" (descriptions of attack behaviors) and the MITRE techcode of it. 
    For EACH description in the list, you must extract a structured "Partial Attack Graph".

    ### EXTRACTION RULES:
    1. **Entities (Nodes):** 
       - Identify technical objects involved (e.g., cmd.exe, invoice.zip, 192.168.1.1).
       - **Types:** Strictly assign one of these types: `Process`, 'Thread', 'Image', `File`, `Registry`, `Network`, 'Attacker', 'User'. Only one attacker per description
       - **Naming:** 
         - Use specific names if present (e.g., "powershell.exe").
         - Use generic names if vague (e.g., "Malicious File", "Office Document").
         - **IMPORTANT:** Preserve file extensions if mentioned (e.g., .zip, .iso, .lnk). Check carefully the type of of entities
         - If we can directly infer the extension from names (e.g., "Word document" will have .docx extension), add extension to name. Only infer those names that are unambiguous.
         - If we can infer the type from names or behavior (e.g., ''execute' action implies 'file' type, 'malware' implies 'file' type), assign type accordingly.
    
    2. **Relationships (Edges):** 
       - Identify actions: [Source ID] -> [Action] -> [Target ID].
       - Examples: `downloads`, `drops`, `executes`, `clicks`, `contains`, `modifies`, `connects_to`.

    **IMPORTANT NOTES: **: No need to use quotes or any special formatting in response, plain text is okay.

    ### OUTPUT FORMAT:
    Return a valid JSON object containing a list `graphs`. The order must match the input list.
    
    JSON Schema:
    {{
      "graphs": [
        {{
          "index": 0,
          "source_text_snippet": "First few words of the description...",
          "entities": [
            {{"id": "e1", "name": "string", "type": "string"}}
          ],
          "relationships": [
            {{"source": "e1", "target": "e2", "action": "string"}}
          ]
        }}
      ],
      "tech_code": tech_code_of_technique   
    }}
    """


GENAI_CONFIG = {
        "temperature": 0.1,        # Lower creativity to improve technical accuracy
        "top_p": 0.95,
        "top_k": 64,
        "max_output_tokens": 65000, # Large enough for long lists
        "response_mime_type": "application/json", # Force valid JSON output
    }


CSS_VIEW = """
        <style>
            /* Reset CSS */
            * { box-sizing: border-box; }
            body, html { 
                margin: 0; 
                padding: 0; 
                width: 100vw; 
                height: 100vh; 
                overflow: hidden; 
                background-color: #222222; 
            }
            
            /* Container chính */
            .card {
                position: relative;
                width: 100% !important;
                height: 100% !important;
                border: none !important;
                background: transparent !important;
            }
            
            .card-body {
                padding: 0 !important;
                width: 100%;
                height: 100%;
            }

            /* Đồ thị */
            #mynetwork { 
                position: absolute; 
                top: 0; 
                left: 0; 
                width: 100% !important; 
                height: 100% !important; 
                border: none !important; 
                outline: none !important;
                z-index: 1; /* Nằm dưới */
            }

            /* Menu chọn (Nổi lên trên) */
            #select-menu {
                position: absolute;
                top: 20px;
                left: 20px;
                z-index: 9999; /* Luôn nằm trên cùng */
                background: rgba(40, 40, 40, 0.8); /* Nền tối mờ */
                padding: 10px;
                border-radius: 8px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.5);
                border: 1px solid #444;
                width: auto !important; /* Ghi đè bootstrap */
                max-width: 400px;
            }
            
            /* Tinh chỉnh các phần tử bên trong menu cho đẹp */
            .card-header { border: none !important; background: transparent !important; padding: 0 !important; }
            .row { margin: 0 !important; display: flex; flex-direction: column; gap: 10px; }
            .col-10, .col-2 { width: 100% !important; padding: 0 !important; max-width: none !important; flex: none !important;}
            
            /* Nút Reset */
            .btn-primary {
                width: 100%;
                background-color: #ff6666 !important;
                border-color: #ff6666 !important;
                font-weight: bold;
            }
            .btn-primary:hover { background-color: #ff4444 !important; }
            
            /* TomSelect (Dropdown) */
            .ts-control {
                background-color: #333 !important;
                color: white !important;
                border: 1px solid #555 !important;
            }
            .ts-dropdown {
                background-color: #333 !important;
                color: white !important;
                border: 1px solid #555 !important;
            }
            .ts-dropdown .option { color: white !important; }
            .ts-dropdown .active { background-color: #555 !important; }
            .item { color: white !important; }

        </style>
        """