# SecretHunter X: A Cognitive SAST Framework for Intelligent Android Secret Detection

**SecretHunter X** is an advanced open-source Static Analysis Security Testing (SAST) framework built for Android application auditing. It combines traditional static analysis techniques with a local cognitive AI engine to identify exposed secrets, API keys, tokens, and insecure configurations with improved accuracy and reduced false positives.

Designed for both researchers and DevSecOps environments, the framework supports automated analysis pipelines as well as interactive security audits through a modern web interface.

---

#  Core Features

##  Cognitive AI Validation

Unlike conventional secret scanners that rely only on regular expressions and entropy detection, SecretHunter X integrates a local **Phi-3 language model** through Ollama to analyze the contextual usage of discovered values.

This allows the framework to:
- Distinguish real secrets from random strings
- Reduce entropy-based false positives
- Validate whether credentials appear operational or inactive
- Provide contextual explanations for findings

---

##  Advanced Android Static Analysis

The framework performs deep APK inspection using JADX for:
- DEX to Java decompilation
- Resource extraction
- Manifest inspection
- Configuration analysis
- Embedded asset scanning

Supported detections include:
- Firebase credentials
- Google API keys
- OAuth tokens
- JWT secrets
- AWS credentials
- Hardcoded passwords
- Certificates and private keys
- Backend endpoints and hidden configurations

---

##  Dual Interface Architecture

### CLI Engine
A lightweight command-line interface optimized for:
- CI/CD integration
- Automated mobile security pipelines
- Batch APK analysis
- Headless environments

### Web Dashboard
A FastAPI-powered web interface featuring:
- Drag-and-drop APK upload
- Real-time scan visualization
- Severity classification
- AI-assisted explanations
- Interactive audit workflow

---

##  OWASP MASVS Mapping

Each finding is automatically associated with relevant controls from the OWASP Mobile Application Security Verification Standard (MASVS), helping security teams align results with recognized mobile security practices.

---

##  Professional Reporting Engine

SecretHunter X can generate structured PDF audit reports containing:
- Severity scoring
- Technical evidence
- Affected files
- Risk explanations
- MASVS references
- Remediation guidance

---

#  Framework Architecture

The framework follows a modular privacy-first design:

## 1. Extraction Layer
Responsible for APK unpacking and decompilation using JADX.

## 2. Detection Layer
Combines:
- RegEx pattern matching
- Entropy analysis
- Heuristic filtering
- Multi-format secret detection

## 3. Reasoning Layer
Performs local AI inference using Phi-3 to cognitively validate findings without transmitting data externally.

## 4. Presentation Layer
Provides:
- FastAPI backend services
- Tailwind CSS frontend
- Interactive visualization
- Real-time reporting

---

#  Installation & Setup

## Prerequisites

- Python 3.10+
- JADX installed and added to PATH
- Ollama running locally
- Phi-3 model installed

---

## Clone the Repository

```bash
git clone https://github.com/AliBenrioui/SecretHunterX.git
cd SecretHunterX
```

---

## Create a Virtual Environment

### Windows

```bash
python -m venv venv
.\venv\Scripts\activate
```

### Linux / macOS

```bash
python -m venv venv
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Prepare the AI Model

```bash
ollama pull phi3
```

---

#  Usage

## Web Dashboard (Recommended)

Launch the web interface:

```bash
python web_server.py
```

Then open:

```text
http://127.0.0.1:8000
```

Features include:
- APK drag-and-drop upload
- Live cognitive analysis
- Finding categorization
- Interactive reporting

---

## CLI Mode

Run a direct APK scan:

```bash
python main.py --path /path/to/app.apk
```

Example:

```bash
python main.py --path samples/fireinthehole.apk
```

---

#  Research & Validation

SecretHunter X has been tested against intentionally vulnerable Android environments and real-world exposed configurations.

## Example Validation Cases

### FireInTheHole

Detected:
- Exposed Firebase configurations
- Google API keys
- Insecure backend references

### Firestorm

Detected:
- OAuth tokens
- Embedded certificates
- Hardcoded authentication material

---

#  Privacy & Security Philosophy

SecretHunter X is designed with a local-first approach:
- No cloud processing
- No external API transmission
- Fully offline AI inference
- Suitable for sensitive APK audits and enterprise environments

---

## 👥 Authors
* **Ali Benrioui** - Cybersecurity Student
* **Rajaa Eddanir** - Cybersecurity Student

---

#  License

This project is distributed under the MIT License.

---

Developed at École Marocaine des Sciences de l'Ingénieur (EMSI), Marrakesh
