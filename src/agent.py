import json
from typing import TypedDict, Optional, Dict, Any
from langgraph.graph import StateGraph, START, END
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

# Support running both directly (python src/agent.py) and as a package
try:
    from src.nvd_api import fetch_cve_data, parse_cve_data
except ModuleNotFoundError:
    from nvd_api import fetch_cve_data, parse_cve_data


# =========================================================
# 1. GRAPH STATE DEFINITION
# =========================================================
# The State acts as the shared memory (clipboard) passed
# from node to node throughout the agent's workflow.
class AgentState(TypedDict):
    cve_id: str                   # What CVE we are investigating
    cve_data: Optional[Dict]      # Populated by fetch_node
    final_report: Optional[str]   # Populated by analyze_node
    error: Optional[str]          # Populated if anything fails


# =========================================================
# 2. NODES (AGENT WORKERS)
# =========================================================

def fetch_node(state: AgentState) -> Dict[str, Any]:
    """
    Worker 1: Retrieves raw CVE data from NVD and extracts clean metrics.
    """
    cve_id = state.get("cve_id", "").strip()
    print(f"\n[Node: fetch_node] 📡 Fetching vulnerability data for: {cve_id}")
    
    if not cve_id:
        return {"error": "No CVE ID provided to fetch_node."}

    raw_json = fetch_cve_data(cve_id)
    if not raw_json:
        return {"error": f"Failed to retrieve data from NVD for {cve_id}."}

    parsed = parse_cve_data(raw_json)
    if "error" in parsed:
        return {"error": parsed["error"]}

    print(f"[Node: fetch_node] ✅ Successfully parsed data (CVSS: {parsed.get('cvss_score')})")
    return {"cve_data": parsed, "error": None}


def analyze_node(state: AgentState) -> Dict[str, Any]:
    """
    Worker 2: Sends parsed threat data to local Ollama LLM with an expert persona.
    """
    # If a previous node failed, we skip LLM analysis
    if state.get("error"):
        print(f"[Node: analyze_node] ⚠️ Skipping analysis due to earlier error: {state['error']}")
        return {"final_report": f"Analysis aborted: {state['error']}"}

    cve_data = state.get("cve_data", {})
    print(f"[Node: analyze_node] 🧠 Feeding data into local LLM (llama3.1)...")

    # Prompt Engineering: Giving the model a clear persona and structured output format
    system_prompt = (
        "You are a Senior Cyber Threat Analyst and DevSecOps Specialist. "
        "Your task is to analyze technical CVE vulnerability data and translate it into "
        "an actionable, executive-ready threat advisory for IT System Administrators."
    )

    user_template = """
Here is the vulnerability data from the National Vulnerability Database (NVD):
- **CVE ID**: {id}
- **Published Date**: {published_date}
- **CVSS Base Score**: {cvss_score} / 10.0
- **Technical Description**: {description}

Please generate a structured threat advisory in Markdown following this exact structure:

## 🚨 Threat Advisory: {id}

### 1. Executive Summary
(Explain in plain, non-jargon language what this vulnerability is and why it matters.)

### 2. Technical Risk & Attack Vector
(Explain how an attacker exploits this and what assets/privileges are at risk.)

### 3. Severity Assessment
(Interpret the CVSS score: Low / Medium / High / Critical, and state immediate urgency.)

### 4. Actionable Mitigation Checklist
(Provide concrete, numbered action items for IT Administrators to patch or protect systems.)
"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("user", user_template)
    ])

    # Connect to our local Ollama instance
    # temperature=0.2 keeps the model deterministic, analytical, and low on hallucinations
    llm = ChatOllama(
        model="llama3.1",
        temperature=0.2
    )

    # Chain the prompt and the LLM
    chain = prompt | llm

    # Execute the chain
    response = chain.invoke({
        "id": cve_data.get("id", "Unknown"),
        "published_date": cve_data.get("published_date", "Unknown"),
        "cvss_score": cve_data.get("cvss_score", "Unknown"),
        "description": cve_data.get("description", "No description provided.")
    })

    print(f"[Node: analyze_node] ✨ Threat report successfully generated!")
    return {"final_report": response.content}


# =========================================================
# 3. GRAPH COMPILATION (STATE MACHINE)
# =========================================================

def build_threat_analyst_graph():
    """
    Assembles the nodes and defines the execution flow.
    """
    # Create the state graph tied to our AgentState schema
    workflow = StateGraph(AgentState)

    # Add our worker nodes
    workflow.add_node("fetch_node", fetch_node)
    workflow.add_node("analyze_node", analyze_node)

    # Define edges (The Execution Flow: START -> fetch -> analyze -> END)
    workflow.add_edge(START, "fetch_node")
    workflow.add_edge("fetch_node", "analyze_node")
    workflow.add_edge("analyze_node", END)

    # Compile the graph into an executable application
    return workflow.compile()


# ---------------------------------------------------------
# Test runner when executing `python src/agent.py`
# ---------------------------------------------------------
if __name__ == "__main__":
    app = build_threat_analyst_graph()

    test_cve = "CVE-2021-44228"  # Log4Shell
    # test_cve = "CVE-2024-3094"  # The infamous 2024 XZ Utils backdoor
    print(f"=== Starting Cyber Threat Analyst Agent for {test_cve} ===")

    # Initial input state
    initial_state: AgentState = {
        "cve_id": test_cve,
        "cve_data": None,
        "final_report": None,
        "error": None
    }

    # Run the pipeline!
    result = app.invoke(initial_state)

    print("\n" + "="*60)
    print("FINAL AGENT OUTPUT (THREAT ADVISORY)")
    print("="*60)
    print(result.get("final_report"))
