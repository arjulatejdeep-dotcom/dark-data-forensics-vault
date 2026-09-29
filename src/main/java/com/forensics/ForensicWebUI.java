package com.forensics;

import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ForensicWebUI: Embedded Sovereign Web Controller.
 *
 * Responsibilities:
 * 1. Hosts an embedded, zero-dependency Javalin web server natively inside the JVM.
 * 2. Serves the air-gapped forensic dashboard directly from the classpath at http://localhost:8080.
 * 3. Exposes secure JSON REST endpoints to query local vector space, inspect the SHA-256 audit ledger,
 *    and trigger live SEC EDGAR synchronizations.
 */
public class ForensicWebUI {

    private final ForensicDataVault vault;
    private final ForensicQueryEngine queryEngine;
    private final OnlineDataMapper onlineDataMapper;
    private Javalin app;
    private final Path stagingDir;

    public ForensicWebUI(ForensicDataVault vault, ForensicQueryEngine queryEngine) {
        this(vault, queryEngine, Path.of("dark_data_samples"), new OnlineDataMapper(vault));
    }

    public ForensicWebUI(ForensicDataVault vault, ForensicQueryEngine queryEngine, Path stagingDir) {
        this(vault, queryEngine, stagingDir, new OnlineDataMapper(vault));
    }

    public ForensicWebUI(ForensicDataVault vault, ForensicQueryEngine queryEngine, Path stagingDir, OnlineDataMapper onlineDataMapper) {
        this.vault = vault;
        this.queryEngine = queryEngine;
        this.stagingDir = stagingDir;
        this.onlineDataMapper = onlineDataMapper != null ? onlineDataMapper : new OnlineDataMapper(vault);
    }

    public OnlineDataMapper getOnlineDataMapper() {
        return onlineDataMapper;
    }

    private int activePort;

    public int getPort() {
        return activePort;
    }

    public int startServer() {
        int[] candidatePorts = {8080, 8085, 8090, 8888, 9090};
        for (int p : candidatePorts) {
            try {
                startServer(p);
                return p;
            } catch (Exception e) {
                System.err.println("[PORT-FALLBACK] Port " + p + " is occupied by another process. Trying next candidate port...");
            }
        }
        startServer(0);
        return activePort;
    }

    public void startServer(int port) {
        System.out.println("🖥️ Booting local sovereign web server on port " + (port == 0 ? "dynamic" : port) + "...");

        this.app = Javalin.create(config -> {
            config.staticFiles.add("/public", Location.CLASSPATH);
        }).start(port);

        this.activePort = app.port();

        System.out.println("==========================================================================");
        System.out.println("🖥️ FORENSIC VAULT INTERACTIVE DASHBOARD RUNNING AT: http://localhost:" + activePort);
        System.out.println("==========================================================================\n");

        // API Endpoint: Query local vector space and Ollama reasoning engine
        app.post("/api/query", ctx -> {
            try {
                @SuppressWarnings("unchecked")
                Map<String, String> requestBody = ctx.bodyAsClass(Map.class);
                String userQuery = requestBody.get("query");

                if (userQuery == null || userQuery.trim().isEmpty()) {
                    ctx.status(400).json(Map.of("status", "ERROR", "message", "Query text cannot be empty"));
                    return;
                }

                ForensicQueryEngine.ForensicQueryResult result = queryEngine.processQuery(userQuery.trim());

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("status", "SUCCESS");
                response.put("response", result.analysis());
                response.put("evidence", result.evidenceRecords());
                response.put("mode", queryEngine.isOllamaOnline() ? "LOCAL_OLLAMA_RAG" : "SOVEREIGN_AIR_GAPPED_VECTOR");
                response.put("ollamaOnline", queryEngine.isOllamaOnline());
                ctx.json(response);

            } catch (Exception e) {
                System.err.println("[API-ERR] Failed to process query: " + e.getMessage());
                ctx.status(500).json(Map.of(
                        "status", "ERROR",
                        "message", "Local backplane error: " + e.getMessage()
                ));
            }
        });

        // API Endpoint: Retrieve real-time cryptographic audit chain ledger
        app.get("/api/audit", ctx -> {
            ctx.json(vault.getAuditTrailLedger());
        });

        // API Endpoint: Automated Forensic Risk Assessment & Irregularity Ledger
        app.get("/api/risk-ledger", ctx -> {
            ctx.json(vault.generateRiskAssessment());
        });

        // API Endpoint: Dynamic probe and refresh of local Ollama daemon
        app.post("/api/ollama/refresh", ctx -> {
            boolean online = queryEngine.refreshOllamaStatus();
            ctx.json(Map.of(
                    "status", "SUCCESS",
                    "ollamaOnline", online,
                    "mode", online ? "LOCAL_OLLAMA_RAG" : "SOVEREIGN_AIR_GAPPED_VECTOR",
                    "model", queryEngine.getModelName()
            ));
        });

        // API Endpoint: Retrieve vault inventory statistics & engine status
        app.get("/api/stats", ctx -> {
            var ledger = vault.getAuditTrailLedger();
            long uniqueFiles = ledger.stream()
                    .map(ForensicDataVault.ForensicBlockRecord::fileName)
                    .distinct()
                    .count();

            var risks = vault.generateRiskAssessment();
            long criticalCount = risks.stream().filter(r -> "CRITICAL".equalsIgnoreCase(r.riskLevel())).count();
            long highCount = risks.stream().filter(r -> "HIGH".equalsIgnoreCase(r.riskLevel())).count();

            Map<String, Object> stats = new LinkedHashMap<>();
            stats.put("totalBlocks", ledger.size());
            stats.put("totalFiles", uniqueFiles);
            stats.put("embeddingModel", "bge-small-en-v1.5 (ONNX)");
            stats.put("vectorDimensions", 384);
            stats.put("ollamaOnline", queryEngine.isOllamaOnline());
            stats.put("executionMode", queryEngine.isOllamaOnline() ? "LOCAL_OLLAMA_RAG" : "SOVEREIGN_AIR_GAPPED_VECTOR");
            stats.put("modelName", queryEngine.getModelName());
            stats.put("criticalRisks", criticalCount);
            stats.put("highRisks", highCount);
            stats.put("totalRisks", risks.size());
            stats.put("diskBypassed", true);
            stats.put("streamingService", "OnlineDataMapper (RAM-Only)");

            ctx.json(stats);
        });

        // API Endpoint: Live SEC EDGAR Corporate Data Ingest (Disk Staging)
        app.post("/api/edgar/sync", ctx -> {
            try {
                @SuppressWarnings("unchecked")
                Map<String, String> body = ctx.bodyAsClass(Map.class);
                String ticker = body.getOrDefault("ticker", "AAPL").trim();
                String form = body.getOrDefault("form", "8-K").trim().toUpperCase();

                Optional<Path> savedPath = vault.syncSecEdgarFiling(ticker, form, stagingDir);
                if (savedPath.isPresent()) {
                    ctx.json(Map.of(
                            "status", "SUCCESS",
                            "file", savedPath.get().getFileName().toString(),
                            "totalBlocks", vault.getAuditTrailLedger().size()
                    ));
                } else {
                    ctx.status(404).json(Map.of(
                            "status", "ERROR",
                            "message", "Failed to retrieve filing from SEC EDGAR for ticker: " + ticker
                    ));
                }
            } catch (Exception e) {
                ctx.status(500).json(Map.of(
                        "status", "ERROR",
                        "message", "SEC EDGAR sync exception: " + e.getMessage()
                ));
            }
        });

        // API Endpoint: In-Memory Streaming Corporate Data Mapper (Zero-Disk Utility)
        app.post("/api/map-online", ctx -> {
            try {
                @SuppressWarnings("unchecked")
                Map<String, String> body = ctx.bodyAsClass(Map.class);
                String cik = body.get("cik");
                String accessionNumber = body.get("accessionNumber");
                String documentName = body.get("documentName");

                if (cik == null || cik.isBlank()) {
                    ctx.status(400).json(Map.of("status", "ERROR", "message", "Parameter 'cik' is required"));
                    return;
                }

                OnlineDataMapper.StreamedMappingResult result = onlineDataMapper.streamAndMap(cik, accessionNumber, documentName);

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("status", result.status());
                response.put("message", result.message());
                response.put("cik", result.cik());
                response.put("accessionNumber", result.accessionNumber());
                response.put("documentName", result.documentName());
                response.put("virtualFileName", result.virtualFileName());
                response.put("masterSha256", result.masterSha256());
                response.put("blocksSealed", result.blocksSealed());
                response.put("payloadBytes", result.payloadBytes());
                response.put("diskBypassed", result.diskBypassed());
                response.put("totalBlocks", vault.getAuditTrailLedger().size());
                response.put("timestamp", result.timestamp());

                if ("ERROR".equals(result.status())) {
                    ctx.status(502).json(response);
                } else {
                    ctx.json(response);
                }
            } catch (Exception e) {
                System.err.println("[MAP-ONLINE-ERR] In-memory streaming error: " + e.getMessage());
                ctx.status(500).json(Map.of(
                        "status", "ERROR",
                        "message", "In-memory streaming error: " + e.getMessage()
                ));
            }
        });

        // API Endpoint: Load/Trigger Corporate Fraud Simulation Case (Project BlackBriar)
        app.post("/api/demo/fraud", ctx -> {
            try {
                Path emailsFile = stagingDir.resolve("fraud_case_executive_emails.json");
                Path ledgerFile = stagingDir.resolve("fraud_case_offshore_spe_ledger.csv");

                if (Files.exists(emailsFile)) {
                    vault.ingestFile(emailsFile);
                }
                if (Files.exists(ledgerFile)) {
                    vault.ingestFile(ledgerFile);
                }

                Map<String, Object> caseData = Map.of(
                        "status", "SUCCESS",
                        "caseName", "Operation BlackBriar: Unrecorded $18.5M SPE Deficit",
                        "targetEntity", "Apex Global Capital Corp.",
                        "allegation", "CFO Marcus Bennett instructed concealment of $18.5M debt into Cayman SPE with secret Zurich buyback side-letter before merger.",
                        "totalBlocks", vault.getAuditTrailLedger().size(),
                        "suggestedQueries", List.of(
                                "What unrecorded liabilities are tied to Project BlackBriar?",
                                "Did CFO Marcus Bennett order debt hidden from KPMG auditors?",
                                "What secret buyback side-letter agreements exist and where are they stored?"
                        )
                );
                ctx.json(caseData);
            } catch (Exception e) {
                ctx.status(500).json(Map.of("status", "ERROR", "message", e.getMessage()));
            }
        });
    }

    public void stopServer() {
        if (app != null) {
            app.stop();
            System.out.println("[SERVER] Forensic Web Server stopped.");
        }
    }
}
