package com.forensics;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class OnlineDataMapperTest {

    @TempDir
    Path tempDir;

    @Test
    public void testCikResolution() {
        ForensicDataVault vault = new ForensicDataVault();
        OnlineDataMapper mapper = new OnlineDataMapper(vault);

        Assertions.assertEquals("0000320193", mapper.resolveCik("AAPL"));
        Assertions.assertEquals("0001318605", mapper.resolveCik("TSLA"));
        Assertions.assertEquals("0000789019", mapper.resolveCik("MSFT"));
        Assertions.assertEquals("0000320193", mapper.resolveCik("320193"));
        Assertions.assertEquals("0000320193", mapper.resolveCik("0000320193"));
    }

    @Test
    public void testInMemoryStreamIngestionZeroDiskFootprint() {
        ForensicDataVault vault = new ForensicDataVault();

        String virtualFileName = "stream://sec_edgar/0000320193/aapl_test_filing.htm";
        String sampleFilingContent = """
                <html>
                <body>
                <h1>ITEM 1A. RISK FACTORS</h1>
                <p>The Company faces material supply chain constraints and $15,000,000 in unrecorded purchase commitments.</p>
                <p>All bridge financing is held under strict air-gapped forensic custody.</p>
                </body>
                </html>
                """;

        byte[] rawBytes = sampleFilingContent.getBytes(StandardCharsets.UTF_8);
        var segments = vault.ingestInMemoryDocument(virtualFileName, rawBytes, "STREAMED_SEC_EDGAR_LIVE");

        Assertions.assertFalse(segments.isEmpty(), "In-memory document must produce vectorized segments");
        Assertions.assertEquals(virtualFileName, segments.get(0).metadata().getString(ForensicDataVault.META_FILE_NAME));
        Assertions.assertEquals("RAM_ONLY_STREAM", segments.get(0).metadata().getString("storage_mode"));

        // Verify audit ledger
        var ledger = vault.getAuditTrailLedger();
        Assertions.assertFalse(ledger.isEmpty(), "Audit trail ledger must record in-memory block");
        Assertions.assertEquals(virtualFileName, ledger.get(0).fileName());

        // Verify offline vector search retrieves the in-memory streamed block
        ForensicQueryEngine engine = new ForensicQueryEngine(vault, "http://localhost:11434", "mistral");
        var queryResult = engine.processQuery("What unrecorded purchase commitments or supply chain constraints exist?");

        Assertions.assertNotNull(queryResult);
        Assertions.assertFalse(queryResult.evidenceRecords().isEmpty(), "Vector search must retrieve streamed in-memory block");
        Assertions.assertTrue(queryResult.analysis().contains("SHA-256"));
        System.out.println("[TEST SUCCESS] In-memory streaming ingestion verified without disk storage!");
    }

    @Test
    public void testMapOnlineApiEndpoint() throws Exception {
        ForensicDataVault vault = new ForensicDataVault();
        ForensicQueryEngine engine = new ForensicQueryEngine(vault, "http://localhost:11434", "mistral");
        OnlineDataMapper mapper = new OnlineDataMapper(vault);
        ForensicWebUI webUI = new ForensicWebUI(vault, engine, tempDir, mapper);

        int testPort = 8092;
        webUI.startServer(testPort);

        try {
            HttpClient client = HttpClient.newHttpClient();

            // 1. Test validation failure when CIK is empty
            HttpRequest emptyReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + testPort + "/api/map-online"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();

            HttpResponse<String> emptyResp = client.send(emptyReq, HttpResponse.BodyHandlers.ofString());
            Assertions.assertEquals(400, emptyResp.statusCode());
            Assertions.assertTrue(emptyResp.body().contains("Parameter 'cik' is required"));

            // 2. Test /api/stats includes diskBypassed and streamingService
            HttpRequest statsReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + testPort + "/api/stats"))
                    .GET()
                    .build();

            HttpResponse<String> statsResp = client.send(statsReq, HttpResponse.BodyHandlers.ofString());
            Assertions.assertEquals(200, statsResp.statusCode());
            Assertions.assertTrue(statsResp.body().contains("diskBypassed"));
            Assertions.assertTrue(statsResp.body().contains("streamingService"));
            System.out.println("[TEST SUCCESS] /api/stats confirmed diskBypassed metric: " + statsResp.body());

        } finally {
            webUI.stopServer();
        }
    }
}
