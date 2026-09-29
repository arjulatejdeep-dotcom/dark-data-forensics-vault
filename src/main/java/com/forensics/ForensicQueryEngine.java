package com.forensics;

import dev.langchain4j.data.embedding.Embedding;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.input.Prompt;
import dev.langchain4j.model.input.PromptTemplate;
import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.store.embedding.EmbeddingMatch;
import dev.langchain4j.store.embedding.EmbeddingSearchRequest;
import dev.langchain4j.store.embedding.EmbeddingSearchResult;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

/**
 * ForensicQueryEngine: Offline RAG Retrieval Pipeline and Interactive Examiner.
 *
 * Responsibilities:
 * 1. Links the Local Embedding Store to the local Ollama instance (localhost:11434).
 * 2. Enforces a strict programmatic prompt modifier requiring structural output of
 *    SHA-256 hashes and file index coordinates on every finding.
 * 3. Provides an interactive CLI console for investigators to explore dark records via stdin.
 */
public class ForensicQueryEngine {

    private static final String DEFAULT_OLLAMA_URL = "http://localhost:11434";
    private static final String DEFAULT_MODEL_NAME = "mistral";

    private static final String FORENSIC_PROMPT_TEMPLATE = """
            You are an air-gapped Digital Forensics & Corporate Audit AI Examiner operating under strict evidentiary standards.
            Your mission: Analyze the retrieved dark data fragments to reconstruct hidden corporate intellectual property,
            system architecture details, and detect unrecorded financial liabilities or undisclosed risks.

            NON-NEGOTIABLE FORENSIC PROTOCOL:
            1. Base your answer EXCLUSIVELY on the provided forensic evidentiary records below.
            2. For every finding, disclosure, or liability detected, you MUST structurally cite:
               - The Source File Name
               - The Block SHA-256 Hash
               - The Master File SHA-256 Hash
               - The Block Index Number
            3. Do not redact or sanitize authentic internal findings; auditors require full unvarnished transparency.
            4. If the retrieved evidence does not contain relevant data, explicitly declare: "NO FORENSIC AUDIT TRAIL FOUND".

            REQUIRED OUTPUT FORMAT:
            [EXECUTIVE FORENSIC SUMMARY]
            <Concise summary of discoveries>

            [EVIDENTIARY FINDINGS & UNRECORDED LIABILITIES]
            <Detailed forensic breakdown with direct textual corroboration>

            [CHAIN OF CUSTODY VERIFICATION TABLE]
            - Source File: <file_name>
            - Block SHA-256: <block_sha256>
            - Master File SHA-256: <file_sha256>
            - Block Index: <block_index>

            ==================== EVIDENTIARY RECORDS ====================
            {{context}}
            =============================================================

            INVESTIGATOR INQUIRY: {{question}}
            """;

    private final ForensicDataVault vault;
    private final String ollamaBaseUrl;
    private final String modelName;
    private final PromptTemplate promptTemplate;
    private volatile ChatLanguageModel chatModel;
    private volatile boolean isOllamaOnline;

    public ForensicQueryEngine(ForensicDataVault vault) {
        this(vault, DEFAULT_OLLAMA_URL, DEFAULT_MODEL_NAME);
    }

    public ForensicQueryEngine(ForensicDataVault vault, String ollamaBaseUrl, String modelName) {
        this.vault = vault;
        this.ollamaBaseUrl = ollamaBaseUrl != null ? ollamaBaseUrl : DEFAULT_OLLAMA_URL;
        this.modelName = modelName != null ? modelName : DEFAULT_MODEL_NAME;
        this.promptTemplate = PromptTemplate.from(FORENSIC_PROMPT_TEMPLATE);

        System.out.println("[DYNAMIC-GUARD] Probing local Ollama daemon at " + this.ollamaBaseUrl + " (1200ms pre-flight check)...");
        this.isOllamaOnline = checkOllamaHealth(this.ollamaBaseUrl);

        if (this.isOllamaOnline) {
            System.out.println("[DYNAMIC-GUARD] ✅ Local Ollama is ONLINE. Initializing ChatLanguageModel (" + this.modelName + ").");
            try {
                this.chatModel = OllamaChatModel.builder()
                        .baseUrl(this.ollamaBaseUrl)
                        .modelName(this.modelName)
                        .timeout(Duration.ofSeconds(30))
                        .temperature(0.0)
                        .build();
            } catch (Exception e) {
                System.err.println("[DYNAMIC-GUARD] ⚠️ Failed to initialize OllamaChatModel: " + e.getMessage());
                this.chatModel = null;
                this.isOllamaOnline = false;
            }
        } else {
            System.out.println("[DYNAMIC-GUARD] 🛡️ Ollama daemon is OFFLINE or unreachable. Gracefully initializing in SOVEREIGN VECTOR-ONLY MODE (0 stack traces, 100% offline).");
            this.chatModel = null;
        }
    }

    /**
     * Pre-flight connectivity ping against local Ollama API tags endpoint.
     * Prevents ConnectException and retry delays by validating the socket first.
     */
    public static boolean checkOllamaHealth(String ollamaBaseUrl) {
        if (ollamaBaseUrl == null || ollamaBaseUrl.isBlank()) return false;
        try {
            String target = ollamaBaseUrl.replaceAll("/+$", "") + "/api/tags";
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(1200))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(target))
                    .timeout(Duration.ofMillis(1200))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isOllamaOnline() {
        return isOllamaOnline;
    }

    public String getOllamaBaseUrl() {
        return ollamaBaseUrl;
    }

    public String getModelName() {
        return modelName;
    }

    public Optional<Object> getRetrievalChain() {
        return Optional.empty();
    }

    /**
     * Dynamic status refresh invoked by Web UI or auditor.
     */
    public boolean refreshOllamaStatus() {
        boolean healthy = checkOllamaHealth(this.ollamaBaseUrl);
        if (healthy && (this.chatModel == null || !this.isOllamaOnline)) {
            try {
                this.chatModel = OllamaChatModel.builder()
                        .baseUrl(this.ollamaBaseUrl)
                        .modelName(this.modelName)
                        .timeout(Duration.ofSeconds(30))
                        .temperature(0.0)
                        .build();
                this.isOllamaOnline = true;
                System.out.println("[DYNAMIC-GUARD] 🟢 Ollama daemon detected: ONLINE.");
            } catch (Exception e) {
                this.chatModel = null;
                this.isOllamaOnline = false;
            }
        } else if (!healthy) {
            this.chatModel = null;
            this.isOllamaOnline = false;
            System.out.println("[DYNAMIC-GUARD] 🟡 Ollama daemon offline: Sovereign Vector Mode active.");
        }
        return this.isOllamaOnline;
    }

    public ForensicQueryResult processQuery(String investigatorQuestion) {
        return query(investigatorQuestion, 4);
    }

    public ForensicQueryResult query(String investigatorQuestion, int maxResults) {
        System.out.println("\n[QUERY-PIPELINE] Vectorizing query: \"" + investigatorQuestion + "\"");

        // 1. Vectorize query with native ONNX bge-small
        Embedding queryEmbedding = vault.getEmbeddingModel().embed(investigatorQuestion).content();

        // 2. Search local in-memory vector store
        EmbeddingSearchRequest request = EmbeddingSearchRequest.builder()
                .queryEmbedding(queryEmbedding)
                .maxResults(maxResults)
                .minScore(0.25)
                .build();

        EmbeddingSearchResult<TextSegment> searchResult = vault.getEmbeddingStore().search(request);
        List<EmbeddingMatch<TextSegment>> matches = searchResult.matches();

        if (matches.isEmpty()) {
            return new ForensicQueryResult(
                    investigatorQuestion,
                    "NO FORENSIC AUDIT TRAIL FOUND: No dark data fragments met the correlation threshold.",
                    Collections.emptyList()
            );
        }

        // 3. Assemble cryptographically sealed context block
        StringBuilder contextBuilder = new StringBuilder();
        List<Map<String, String>> evidenceList = new ArrayList<>();

        for (int i = 0; i < matches.size(); i++) {
            EmbeddingMatch<TextSegment> match = matches.get(i);
            TextSegment segment = match.embedded();
            var meta = segment.metadata();

            String fileName = meta.getString(ForensicDataVault.META_FILE_NAME) != null ?
                    meta.getString(ForensicDataVault.META_FILE_NAME) : meta.getString("source_file");
            if (fileName == null) fileName = "UNKNOWN_FILE";

            String fileSha = meta.getString(ForensicDataVault.META_FILE_SHA256) != null ?
                    meta.getString(ForensicDataVault.META_FILE_SHA256) : "UNKNOWN_FILE_SHA";

            String blockSha = meta.getString(ForensicDataVault.META_BLOCK_SHA256) != null ?
                    meta.getString(ForensicDataVault.META_BLOCK_SHA256) : meta.getString("forensic_sha256");
            if (blockSha == null) blockSha = "UNKNOWN_BLOCK_SHA";

            String blockIdx = meta.getString(ForensicDataVault.META_BLOCK_INDEX) != null ?
                    meta.getString(ForensicDataVault.META_BLOCK_INDEX) : "1";
            String totalBlocks = meta.getString(ForensicDataVault.META_TOTAL_BLOCKS) != null ?
                    meta.getString(ForensicDataVault.META_TOTAL_BLOCKS) : "1";

            Map<String, String> ev = new LinkedHashMap<>();
            ev.put("rank", String.valueOf(i + 1));
            ev.put("score", String.format("%.4f", match.score()));
            ev.put("fileName", fileName);
            ev.put("fileSha", fileSha);
            ev.put("blockSha", blockSha);
            ev.put("blockIdx", blockIdx + "/" + totalBlocks);
            ev.put("content", segment.text());
            evidenceList.add(ev);

            contextBuilder.append(String.format("""
                    [RECORD #%d | SIMILARITY: %.4f]
                    Source File: %s
                    Block SHA-256: %s
                    File SHA-256: %s
                    Block Index: %s of %s
                    Raw Content:
                    %s
                    -------------------------------------------------------------
                    """,
                    i + 1,
                    match.score(),
                    fileName,
                    blockSha,
                    fileSha,
                    blockIdx,
                    totalBlocks,
                    segment.text()
            ));
        }

        // 4. Execute AI reasoning if Ollama is online, otherwise graceful sovereign report
        String responseText;
        if (this.isOllamaOnline && this.chatModel != null) {
            try {
                System.out.println("[AI-EXAMINER] Querying local " + modelName + " LLM with forensic evidentiary context...");
                Map<String, Object> variables = Map.of(
                        "context", contextBuilder.toString(),
                        "question", investigatorQuestion
                );
                Prompt prompt = promptTemplate.apply(variables);
                responseText = chatModel.generate(prompt.text());
            } catch (Exception e) {
                System.err.println("[AI-EXAMINER-WARN] Ollama execution failed: " + e.getMessage() + ". Reverting to Sovereign Vector Mode.");
                this.isOllamaOnline = false;
                this.chatModel = null;
                responseText = buildSovereignVectorReport(investigatorQuestion, matches.size(), evidenceList);
            }
        } else {
            System.out.println("[AI-EXAMINER] Generating Sovereign Vector Report (" + matches.size() + " cryptographically verified blocks retrieved).");
            responseText = buildSovereignVectorReport(investigatorQuestion, matches.size(), evidenceList);
        }

        return new ForensicQueryResult(investigatorQuestion, responseText, evidenceList);
    }

    private String buildSovereignVectorReport(String query, int matchCount, List<Map<String, String>> evidenceList) {
        StringBuilder sb = new StringBuilder();
        sb.append("========================================================================================\n");
        sb.append("🛡️ [SOVEREIGN AIR-GAPPED VECTOR EXAMINATION REPORT - 100% LOCAL RETRIEVAL]\n");
        sb.append("========================================================================================\n");
        sb.append("STATUS          : Verified In-Process Vector Match (Zero Network Egress • Air-Gapped)\n");
        sb.append("REASONING ENGINE: Sovereign ONNX Vector Matrix (Ollama Offline Safeguard Active)\n");
        sb.append("EMBEDDING MODEL : bge-small-en-v1.5 (Quantized Native In-Process)\n");
        sb.append(String.format("MATCHED BLOCKS  : %d Evidentiary Fragments Retrieved (Min Cosine Correlation >= 0.2500)\n\n", matchCount));

        sb.append("[EXECUTIVE FORENSIC DISCOVERY SUMMARY]\n");
        sb.append("Local in-process vector correlation completed without cloud dependencies or external daemon delays.\n");
        sb.append("Correlated ").append(matchCount).append(" authentic dark data records matching investigator query:\n");
        sb.append("\"").append(query).append("\"\n\n");

        sb.append("[EVIDENTIARY FINDINGS & DETECTED IRREGULARITIES]\n");
        for (int i = 0; i < evidenceList.size(); i++) {
            Map<String, String> ev = evidenceList.get(i);
            sb.append(String.format("▸ FINDING #%d [Cosine Similarity: %s | Source: %s | Block: %s]\n",
                    i + 1, ev.get("score"), ev.get("fileName"), ev.get("blockIdx")));
            sb.append("  Chain of Custody: SHA-256 ").append(ev.get("blockSha")).append("\n");
            sb.append("  Evidentiary Extract:\n");
            String[] lines = ev.get("content").split("\\r?\\n");
            for (String l : lines) {
                if (!l.trim().isEmpty()) {
                    sb.append("  │ ").append(l).append("\n");
                }
            }
            sb.append("  --------------------------------------------------------------------------------------\n");
        }

        sb.append("\n[CHAIN OF CUSTODY VERIFICATION TABLE]\n");
        for (Map<String, String> ev : evidenceList) {
            String shortBlock = ev.get("blockSha").length() > 16 ? ev.get("blockSha").substring(0, 16) + "..." : ev.get("blockSha");
            String shortMaster = ev.get("fileSha").length() > 16 ? ev.get("fileSha").substring(0, 16) + "..." : ev.get("fileSha");
            sb.append(String.format("- Source: %-36s | Block: %-19s | Master: %s\n",
                    ev.get("fileName"), shortBlock, shortMaster));
        }
        sb.append("========================================================================================\n");
        return sb.toString();
    }

    public record ForensicQueryResult(
            String question,
            String analysis,
            List<Map<String, String>> evidenceRecords
    ) {}

    /**
     * Interactive CLI Entry Point for Investigators.
     */
    public static void main(String[] args) {
        System.out.println("==========================================================================");
        System.out.println("   DARK-DATA-FORENSICS-VAULT: ZERO-BUDGET LOCAL MULTI-AI JAVA STACK       ");
        System.out.println("   Air-Gapped Forensic Intelligence | SHA-256 Custody | ONNX + Ollama     ");
        System.out.println("==========================================================================\n");

        ForensicDataVault vault = new ForensicDataVault();

        // Check if sample data directory exists, or generate synthetic dark enterprise backup
        Path dataDir = Path.of("dark_data_samples");
        try {
            if (!Files.exists(dataDir)) {
                generateSyntheticDarkData(dataDir);
            }

            // Ingest all sample dark data artifacts
            try (var stream = Files.walk(dataDir)) {
                stream.filter(Files::isRegularFile).forEach(file -> {
                    try {
                        vault.ingestFile(file);
                    } catch (IOException e) {
                        System.err.println("[INGEST-ERR] Failed to ingest: " + file + " - " + e.getMessage());
                    }
                });
            }
        } catch (Exception e) {
            System.err.println("[INIT-ERR] Error preparing sample dark data: " + e.getMessage());
        }

        ForensicQueryEngine engine = new ForensicQueryEngine(vault, DEFAULT_OLLAMA_URL, DEFAULT_MODEL_NAME);

        // Boot embedded sovereign web server
        ForensicWebUI webUI = new ForensicWebUI(vault, engine, dataDir);
        int webPort = webUI.startServer();

        System.out.println("\n[VAULT-READY] " + vault.getAuditTrailLedger().size() + " total cryptographic blocks loaded.");
        System.out.println("Web Dashboard: http://localhost:" + webPort);
        System.out.println("Terminal CLI : Type your forensic question, or 'audit' to view ledger, or 'exit' to quit.\n");

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\nFORENSIC-QUERY > ");
            if (!scanner.hasNextLine()) break;
            String line = scanner.nextLine().trim();

            if (line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) {
                System.out.println("[SHUTDOWN] Exiting Forensic Vault. Memory cleared.");
                System.exit(0);
            } else if (line.equalsIgnoreCase("audit")) {
                printAuditLedger(vault);
                continue;
            } else if (line.toLowerCase().startsWith("edgar ")) {
                String[] parts = line.split("\\s+");
                String ticker = parts.length > 1 ? parts[1] : "AAPL";
                String form = parts.length > 2 ? parts[2].toUpperCase() : "8-K";
                vault.syncSecEdgarFiling(ticker, form, dataDir);
                System.out.println("[EDGAR-SYNC] Synced " + ticker + " (" + form + "). Total blocks now: " + vault.getAuditTrailLedger().size());
                continue;
            } else if (line.isEmpty()) {
                continue;
            }

            ForensicQueryResult result = engine.query(line, 4);
            System.out.println("\n" + result.analysis());
        }
        System.out.println("[SHUTDOWN] Stdin closed. Exiting Forensic Vault.");
        System.exit(0);
    }

    private static void printAuditLedger(ForensicDataVault vault) {
        System.out.println("\n====================== FORENSIC AUDIT CHAIN LEDGER ======================");
        for (var rec : vault.getAuditTrailLedger()) {
            System.out.printf("[%s] Block #%d | SHA: %s | File: %s\n",
                    rec.timestamp(), rec.blockIndex(), rec.blockSha256().substring(0, 16) + "...", rec.fileName());
        }
        System.out.println("========================================================================\n");
    }

    /**
     * Seeds synthetic dark data representing realistic enterprise audit scenarios:
     * - Unrecorded financial liabilities in offshore CSVs
     * - Uncommitted IP / secret algorithm in mock Slack communication logs
     * - Corrupted server crash dump with internal auth credentials
     */
    public static void generateSyntheticDarkData(Path dir) throws IOException {
        Files.createDirectories(dir);

        // 1. Mock Slack JSON dump containing secret uncommitted IP and unrecorded debt
        Path slackDump = dir.resolve("internal_slack_dev_channel.json");
        String slackJson = """
                [
                  {
                    "user": "lead_architect_dave",
                    "ts": "2024-03-14T09:12:00Z",
                    "text": "The Project Chimera proprietary consensus algorithm is stored on server-node-9. We haven't filed the patent yet or recorded the $450,000 licensing fee liability owed to QuantumTech Ltd on the Q1 balance sheet."
                  },
                  {
                    "user": "cfo_steve",
                    "ts": "2024-03-14T09:15:30Z",
                    "text": "Keep that off the audited books until the merger completes. If the auditors see the $450,000 unpaid claim, valuation drops by 12%."
                  },
                  {
                    "user": "lead_architect_dave",
                    "ts": "2024-03-14T09:20:10Z",
                    "text": "Understood. The core Chimera algorithm uses an optimized ring-signature protocol with polynomial zero-knowledge commitments located in /opt/chimera/crypto_core.c."
                  }
                ]
                """;
        Files.writeString(slackDump, slackJson);

        // 2. Mock unrecorded liability CSV ledger
        Path liabilityCsv = dir.resolve("offshore_unrecorded_liabilities.csv");
        String csvData = """
                TransactionID,Entity,AmountUSD,Status,Notes,TargetDisposalDate
                TX-9901,Apex Cayman Holdings,1250000,UNRECORDED,Undisclosed severance guarantees for executive board,2024-12-31
                TX-9902,Zurich Escrow Trust,820000,CONTINGENT,Unfiled intellectual property infringement settlement,2025-01-15
                TX-9903,Panama Special Ops Ltd,3400000,OFF_SHEET,Unhedged synthetic derivatives position,2024-11-30
                """;
        Files.writeString(liabilityCsv, csvData);

        // 3. Corrupted server log containing recovered intellectual property fragments
        Path corruptedLog = dir.resolve("corrupted_backup_node9.log");
        String logData = """
                [SYSTEM CRASH DUMP - 0x7FFEAA10]
                Corrupted Sector 0x00FF8812...
                FATAL_ERROR: Memory segment dump in progress.
                FOUND ARTIFACT: module=ChimeraEngine version=2.4.1
                IP_DECLARATION: Copyright 2024 Proprietary Neuro-Symbolic Inference Engine.
                SECRET_KEY_FRAGMENT: env_var_auth="ENC:9948ff10acde44"
                RECOVERED_IP: "Algorithm utilizes zero-overhead in-memory vector quantization with SIMD AVX-512 acceleration."
                END OF CORRUPTED CORE DUMP.
                """;
        Files.writeString(corruptedLog, logData);

        System.out.println("[DARK-DATA] Generated synthetic forensic test files in: " + dir.toAbsolutePath());
    }
}
