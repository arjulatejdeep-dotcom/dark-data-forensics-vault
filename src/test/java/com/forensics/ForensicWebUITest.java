package com.forensics;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;

public class ForensicWebUITest {

    @TempDir
    Path tempDir;

    @Test
    public void testServerLifecycleAndStatsEndpoint() throws Exception {
        ForensicDataVault vault = new ForensicDataVault();
        ForensicQueryEngine engine = new ForensicQueryEngine(vault, "http://localhost:11434", "mistral");
        ForensicWebUI webUI = new ForensicWebUI(vault, engine, tempDir);

        int testPort = 8089;
        webUI.startServer(testPort);

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + testPort + "/api/stats"))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Assertions.assertEquals(200, response.statusCode());
            Assertions.assertTrue(response.body().contains("totalBlocks"));
            Assertions.assertTrue(response.body().contains("vectorDimensions"));
            System.out.println("[TEST SUCCESS] Web UI /api/stats responded 200 OK: " + response.body());
        } finally {
            webUI.stopServer();
        }
    }

    @Test
    public void testRiskLedgerAndOfflineQueryFallback() throws Exception {
        ForensicDataVault vault = new ForensicDataVault();

        // Ingest sample unrecorded liability
        Path mockFile = tempDir.resolve("fraud_case_spe_ledger.csv");
        java.nio.file.Files.writeString(mockFile, "TransactionID,Entity,AmountUSD,Status,Notes\nTX-01,Cayman SPE,18500000,UNRECORDED,Concealed debt\n");
        vault.ingestFile(mockFile);

        ForensicQueryEngine engine = new ForensicQueryEngine(vault, "http://localhost:11434", "mistral");
        ForensicWebUI webUI = new ForensicWebUI(vault, engine, tempDir);

        int testPort = 8091;
        webUI.startServer(testPort);

        try {
            HttpClient client = HttpClient.newHttpClient();

            // 1. Test /api/risk-ledger
            HttpRequest riskReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + testPort + "/api/risk-ledger"))
                    .GET()
                    .build();
            HttpResponse<String> riskResp = client.send(riskReq, HttpResponse.BodyHandlers.ofString());
            Assertions.assertEquals(200, riskResp.statusCode());
            Assertions.assertTrue(riskResp.body().contains("RISK-"), "Risk ledger must detect irregularities");
            System.out.println("[TEST SUCCESS] /api/risk-ledger returned: " + riskResp.body());

            // 2. Test /api/query fallback
            HttpRequest queryReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + testPort + "/api/query"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"query\":\"What unrecorded liabilities exist?\"}"))
                    .build();
            HttpResponse<String> queryResp = client.send(queryReq, HttpResponse.BodyHandlers.ofString());
            Assertions.assertEquals(200, queryResp.statusCode());
            Assertions.assertTrue(queryResp.body().contains("SOVEREIGN_AIR_GAPPED_VECTOR") || queryResp.body().contains("LOCAL_OLLAMA_RAG"));
            Assertions.assertTrue(queryResp.body().contains("SHA-256"));
            System.out.println("[TEST SUCCESS] /api/query executed smoothly without ConnectException: " + queryResp.body());

            // 3. Test /api/ollama/refresh
            HttpRequest refreshReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + testPort + "/api/ollama/refresh"))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> refreshResp = client.send(refreshReq, HttpResponse.BodyHandlers.ofString());
            Assertions.assertEquals(200, refreshResp.statusCode());
            Assertions.assertTrue(refreshResp.body().contains("ollamaOnline"));

        } finally {
            webUI.stopServer();
        }
    }
}
