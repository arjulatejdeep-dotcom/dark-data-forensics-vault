# Dark-Data-Forensics-Vault

> **Zero-Budget, Local Multi-AI Java Stack for Air-Gapped Dark Data Forensics & Audit Intelligence**

A production-grade, 100% offline, air-gapped forensic AI platform powered by **Java 21**, **LangChain4j**, native **ONNX** embeddings (`bge-small-en-v1.5`), and local **Ollama** LLMs (`mistral` / `llama3`).

---

## 🏛 Multi-AI Agent Topology

The vault is designed across three distinct operational agent tiers:

```
+---------------------------------------------------------------------------------------+
|                                DARK-DATA INGESTION                                    |
| [Untagged PDFs]  [Mock Slack JSON Dumps]  [Financial CSV Ledgers]  [Corrupted Dumps] |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| 1. INGESTION & MULTI-MODAL PARSING AGENT                                              |
| - Format-specific extraction (Slack conversation threads, CSV tabular rows, text)      |
| - Cryptographic Tracking Pipeline: Computes SHA-256 for original files & every chunk  |
| - Strict evidentiary audit trail ledger                                               |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| 2. LOCAL EMBEDDING & KNOWLEDGE GRAPH SPECIALIST                                       |
| - Standardized on bge-small-en-v1.5 running natively in-process via ONNX runtime       |
| - Recursive document chunking: 1000-token window with 150-token recursive overlap     |
| - InMemoryEmbeddingStore vector memory mapping (Zero external egress)                 |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| 3. FORENSIC EXAMINER & LIABILITY SCANNER (Ollama Agent)                               |
| - Local RAG query engine mapped to localhost:11434 (mistral / llama3)                 |
| - Strict programmatic prompt modifier enforcing source SHA-256 & block index output   |
| - Unvarnished disclosure of unrecorded liabilities & reconstructed IP fragments       |
+---------------------------------------------------------------------------------------+
```

---

## 🔒 Operational Constraints & Air-Gap Compliance

- **Zero Budget ($0):** 100% local and open-source. No OpenAI API keys, Pinecone tokens, or cloud billing.
- **Air-Gapped Privacy:** In-process ONNX vectorization via DJL/HuggingFace tokenizers and localhost Ollama daemon. No telemetry or internet egress during document processing or search.
- **Evidentiary Integrity:** Strict cryptographic SHA-256 hash preservation at both file and block levels. Every LLM response is forced by a prompt modifier to cite source hash coordinates.

---

## 📁 Repository Structure

```
dark-data-forensics-vault/
├── pom.xml                                      # LangChain4j BOM, ONNX bge-small, Ollama, Tika, Jackson
├── dark_data_samples/                           # Staging folder for dark data & downloaded SEC filings
│   ├── internal_slack_dev_channel.json          # Uncommitted IP & unrecorded licensing debt
│   ├── offshore_unrecorded_liabilities.csv      # Off-balance sheet transaction ledger
│   ├── corrupted_backup_node9.log               # Memory core dump with proprietary algorithm
│   └── sec_8-k_0000320193_aapl-*.txt            # Real-time SEC filings downloaded via SecEdgarClient
├── src/
│   ├── main/java/com/forensics/
│   │   ├── SecEdgarClient.java                  # Zero-cost SEC EDGAR REST API downloader & HTML scrubber
│   │   ├── ForensicDataVault.java               # Ingestion, SHA-256 custody, ONNX embedding & store
│   │   └── ForensicQueryEngine.java             # RAG retrieval, strict prompt modifier, stdin CLI
│   └── test/java/com/forensics/
│       ├── SecEdgarClientTest.java              # Unit tests for CIK resolution and HTML sanitization
│       └── ForensicVaultTest.java               # Automated offline verification test suite
└── README.md
```

---

## 🚀 Quickstart & Execution

### Prerequisites
- **Java 21+** (e.g. Temurin-21 LTS)
- **Maven 3.9+**
- **Ollama** installed locally (`ollama run mistral` or `ollama run llama3`)

### 1. Run Automated Test Suite
Verify local ONNX model loading, SHA-256 hashing, and vector search offline:
```bash
mvn test
```

### 2. Start Local Ollama Daemon (Optional for full LLM analysis)
In a separate terminal:
```bash
ollama run mistral
```
*(If Ollama is not active, the system automatically falls back to local vector retrieval and outputs matched cryptographic evidence blocks.)*

### 3. Launch Interactive Forensic Examiner CLI
```bash
mvn compile exec:java
```

### 4. Commands Available in Interactive CLI:
- Any natural language query (e.g. `What unrecorded liabilities or off-balance sheet debts exist?`)
- `edgar <ticker> <form>` — Live downloads and ingests real SEC filings (e.g. `edgar AAPL 10-K` or `edgar TSLA 8-K`).
- `audit` — Dumps the live SHA-256 chain of custody ledger with timestamps and block hashes.
- `exit` — Clears memory and cleanly shuts down the vault.
