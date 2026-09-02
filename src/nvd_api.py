import requests
import json
import os
from dotenv import load_dotenv

# Load variables from the .env file (if it exists)
load_dotenv()

# The base URL for the NVD REST API v2.0
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cve_data(cve_id: str) -> dict:
    """
    Fetches raw JSON data for a specific CVE from the National Vulnerability Database.
    
    Args:
        cve_id (str): The CVE identifier (e.g., 'CVE-2021-44228')
        
    Returns:
        dict: The parsed JSON response, or an empty dict if it fails.
    """
    # 1. We construct the full URL, adding the cveId parameter
    url = f"{NVD_BASE_URL}?cveId={cve_id}"
    
    # 2. We can optionally attach our API key in the headers if we have one
    api_key = os.getenv("NVD_API_KEY")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        
    print(f"[*] Fetching data for '{cve_id}' from NVD...")
    
    try:
        # 3. Make the HTTP GET request
        response = requests.get(url, headers=headers)
        
        # 4. Check if the request was successful (HTTP Status Code 200)
        response.raise_for_status()
        
        # 5. Convert the text response into a Python dictionary
        data = response.json()
        return data
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching CVE data: {e}")
        return {}

def parse_cve_data(raw_data: dict) -> dict:
    """
    Extracts the essential fields (Description, CVSS Score, Publish Date) 
    from the massive NVD (National Vulnerability Database) JSON payload.
    """
    # 1. Grab the list of vulnerabilities
    vulnerabilities = raw_data.get("vulnerabilities", [])
    
    # 2. If the list is empty, return an error dictionary
    if not vulnerabilities:
        return {"error": "No vulnerability data found."}
        
    # 3. Get the first (and usually only) CVE item in the list
    cve_item = vulnerabilities[0].get("cve", {})
    
    # 4. Extract the published date
    published_date = cve_item.get("published", "Unknown Date")
    
    # 5. Extract the English description
    descriptions = cve_item.get("descriptions", [])
    description_text = "No description available."
    # Loop through the descriptions to find the English one
    for desc in descriptions:
        if desc.get("lang") == "en":
            description_text = desc.get("value")
            break
            
    # 6. Extract the CVSS Base Score (Checking V3.1 first, then fallback to older formats)
    cvss_score = "Unknown"
    metrics = cve_item.get("metrics", {})
    
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV3" in metrics:
        cvss_score = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    # 7. Package everything into a clean dictionary
    return {
        "id": cve_item.get("id", "Unknown ID"),
        "published_date": published_date,
        "description": description_text,
        "cvss_score": cvss_score
    }

# ---------------------------------------------------------
# Let's test our function!
# When you run this file directly, the code below will execute.
if __name__ == "__main__":
    # Log4j CVE
    test_cve = "CVE-2021-44228"
    
    # Call our function
    raw_data = fetch_cve_data(test_cve)
    
    # Print the raw JSON payload nicely formatted
    # print("--- RAW JSON PAYLOAD ---")
    # print(json.dumps(raw_data, indent=2))
    
    # Parse the data to get only what we care about
    parsed_data = parse_cve_data(raw_data)
    
    # Print parsed, clean data
    print("\n--- CLEAN PARSED DATA ---")
    print(json.dumps(parsed_data, indent=2))
