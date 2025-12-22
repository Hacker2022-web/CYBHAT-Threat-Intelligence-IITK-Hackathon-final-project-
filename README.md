# CYBHAT-Threat-Intelligence-IITK-Hackathon-final-project-
# CYBHAT: Automated Threat Intelligence Extractor

![Status](https://img.shields.io/badge/Status-Prototype-blue) ![Python](https://img.shields.io/badge/Python-3.7%2B-green) ![License](https://img.shields.io/badge/License-MIT-lightgrey)

## 📋 Overview

**CYBHAT** is an automated tool designed to extract actionable threat intelligence from unstructured data sources. [cite_start]It processes reports in **PDF, DOCX, and TXT** formats to identify and classify key threat indicators using Natural Language Processing (NLP) and Machine Learning[cite: 3, 20].

[cite_start]Manual analysis struggles to keep pace with the volume of cyber threat data[cite: 166]. [cite_start]This tool bridges that gap by rapidly identifying Indicators of Compromise (IoCs), TTPs, and threat actors, transforming reactive defenses into proactive strategies[cite: 311].


## ✨ Key Features

* [cite_start]**Multi-Format Support:** Extracts text and intelligence from PDF (including scanned docs via OCR), DOCX, and TXT files[cite: 3, 122].
* [cite_start]**IoC Extraction:** Uses regex to identify IPs, MAC addresses, Domains, URLs, File Hashes (MD5/SHA), and Registry Keys[cite: 63, 64, 69].
* [cite_start]**MITRE ATT&CK Mapping:** Automatically maps text to specific tactics and techniques (e.g., Phishing, T1566) within the MITRE framework[cite: 75, 76].
* [cite_start]**Malware & Actor Detection:** Leverages SpaCy NER and Transformer models to identify malware names and threat actors[cite: 79, 84].
* [cite_start]**Data Enrichment:** Integrates with the VirusTotal API to enrich extracted malware data with metadata[cite: 81].
* [cite_start]**JSON Export:** Outputs structured JSON files for easy integration with other security tools[cite: 5].

## 🏗️ Architecture

The application follows a linear pipeline: **Input Validation -> Text Extraction -> Intelligence Mining -> Output Generation**.


> [cite_start]**Note:** The logic combines regex precision for IoCs with the flexibility of Transformer models for Named Entity Recognition[cite: 296].

## ⚙️ Prerequisites

Ensure you have the following installed:
* [cite_start]Python 3.7+ [cite: 29]
* [cite_start]Tesseract OCR (for scanning non-machine-readable PDFs) [cite: 122]

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Hacker2022-web/CYBHAT-Threat-Extractor.git](https://github.com/Hacker2022-web/CYBHAT-Threat-Extractor.git)
    cd CYBHAT-Threat-Extractor
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *Dependencies include: `pymupdf`, `spacy`, `transformers`, `docx2txt`, `requests`*[cite: 9, 10, 14, 15, 16].

3.  **Download the SpaCy language model:**
    ```bash
    python -m spacy download en_core_web_sm
    ```
    **

## 💻 Usage

You can run the extractor via the Command Line Interface (CLI) or the Web Dashboard.

### Option 1: CLI
Run the main script and follow the prompts to provide a file or folder path:
```bash
python threat_extractor.py
