package com.forensics;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

public class SecEdgarClientTest {

    @TempDir
    Path tempDir;

    @Test
    public void testCikResolution() {
        SecEdgarClient client = new SecEdgarClient(tempDir.toString());
        Assertions.assertEquals("0000320193", client.resolveCik("AAPL"));
        Assertions.assertEquals("0001318605", client.resolveCik("TSLA"));
        Assertions.assertEquals("0000789019", client.resolveCik("MSFT"));
        Assertions.assertEquals("0000320193", client.resolveCik("320193"));
    }

    @Test
    public void testHtmlSanitizer() {
        String mockHtml = "<html><body><h1>Item 1A. Risk Factors</h1><p>The company faces intense competition.</p></body></html>";
        String sanitized = SecEdgarClient.sanitizeFilingText(mockHtml, "filing.htm");

        Assertions.assertTrue(sanitized.contains("Item 1A. Risk Factors"));
        Assertions.assertTrue(sanitized.contains("The company faces intense competition."));
        Assertions.assertFalse(sanitized.contains("<html>"));
        Assertions.assertFalse(sanitized.contains("<h1>"));
    }
}
