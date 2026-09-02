# 🛡️ Cyber-Threat Analyst Agent

An AI-driven cybersecurity tool designed to bridge the gap between complex vulnerability data and actionable IT operations.

## 📖 Project Overview

Cybersecurity databases (like the NVD) output dense, jargon-heavy JSON files when reporting vulnerabilities. This project automates the retrieval of that data and uses a local Large Language Model (LLM) orchestrated by **LangGraph** to translate it into a clear, concise, and actionable threat report.

### 🌟 Key Features

- **Automated Data Retrieval:** Fetches real-time CVE data from the NIST National Vulnerability Database (NVD) REST API.
- **Intelligent Parsing:** Extracts and sanitizes critical fields (Description, CVSS Severity Score, Published Date) from massive JSON payloads.
- **Local AI Analysis:** Utilizes a local LLM (via Ollama) to guarantee data privacy and zero API costs.
- **Agentic Workflow:** Built with LangGraph to orchestrate a state-machine that fetches, analyzes, and formats the final report.

## 🛠️ Architecture & Tech Stack

- **Language:** Python 3.10+
- **Data Source:** [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- **AI Orchestration:** LangChain & LangGraph
- **LLM Provider:** Ollama (Local Execution)
- **Environment Management:** `venv`, `python-dotenv`

## 🚀 Getting Started

_(Installation and usage instructions will be added as the project progresses)_
