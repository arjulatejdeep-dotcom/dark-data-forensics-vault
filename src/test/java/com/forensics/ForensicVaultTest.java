package com.forensics;

import dev.langchain4j.data.segment.TextSegment;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class ForensicVaultTest {

    @TempDir
    Path tempDir;

    @Test
    public void testSha256Computation() {
        String testInput = "Chimera proprietary consensus algorithm";
        String sha = ForensicDataVault.computeSha256(testInput.getBytes());
        Assertions.assertNotNull(sha);
        Assertions.assertEquals(64, sha.length(), "SHA-256 hex string must be 64 characters");
    }

    @Test
    public void testIngestionAndRetrievalPipeline() throws IOException {
        ForensicDataVault vault = new ForensicDataVault();

        Path mockArtifact = tempDir.resolve("unrecorded_liabilities.csv");
        String sampleCsv = """
                TransactionID,Entity,AmountUSD,Status,Notes
                TX-1001,Shell Corp Cayman,5000000,UNRECORDED,Undisclosed executive debt
                TX-1002,Alpine Escrow,250000,CONTINGENT,Unfiled litigation settlement
                """;
        Files.writeString(mockArtifact, sampleCsv);

        List<TextSegment> segments = vault.ingestFile(mockArtifact);
        Assertions.assertFalse(segments.isEmpty(), "Segments should have been created");

        TextSegment firstSegment = segments.get(0);
        Assertions.assertEquals("unrecorded_liabilities.csv", firstSegment.metadata().getString(ForensicDataVault.META_FILE_NAME));
        Assertions.assertNotNull(firstSegment.metadata().getString(ForensicDataVault.META_FILE_SHA256));
        Assertions.assertNotNull(firstSegment.metadata().getString(ForensicDataVault.META_BLOCK_SHA256));

        // Test querying
        ForensicQueryEngine engine = new ForensicQueryEngine(vault, "http://localhost:11434", "mistral");
        var result = engine.query("What undisclosed executive debt or unrecorded liabilities exist?", 2);

        Assertions.assertNotNull(result);
        Assertions.assertFalse(result.evidenceRecords().isEmpty(), "Local vector search must retrieve matched blocks");
        System.out.println("[TEST SUCCESS] Retrieved " + result.evidenceRecords().size() + " evidentiary blocks offline!");
    }
}
