package com.forensics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * SecEdgarClient: Offline-First Zero-Cost SEC EDGAR Corporate Data Engine.
 *
 * Responsibilities:
 * 1. Query SEC EDGAR public submissions endpoint (https://data.sec.gov/submissions/CIK{paddedCik}.json).
 * 2. Resolve corporate tickers (AAPL, TSLA, MSFT) to 10-digit padded CIKs.
 * 3. Retrieve latest 10-K (Annual Report) and 8-K (Material Event) primary document records.
 * 4. Download raw filings using SEC-compliant User-Agent identity headers and save to local staging.
 * 5. Sanitize HTML/XBRL payloads into clean forensic text ready for recursive chunking & vectorization.
 */
public class SecEdgarClient {

    private static final String SUBMISSIONS_BASE_URL = "https://data.sec.gov/submissions/CIK%s.json";
    private static final String ARCHIVES_BASE_URL = "https://www.sec.gov/Archives/edgar/data/%d/%s/%s";
    private static final String DEFAULT_USER_AGENT = "ForensicVaultAuditor/1.0 (local.forensics@vault.internal)";

    private static final Map<String, String> COMMON_TICKER_CIK_MAP = Map.of(
            "AAPL", "0000320193",
            "TSLA", "0001318605",
            "MSFT", "0000789019",
            "GOOGL", "0001652044",
            "AMZN", "0001018724"
    );

    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]*>");
    private static final Pattern MULTI_NEWLINE_PATTERN = Pattern.compile("(\\r?\\n\\s*){3,}");

    private final HttpClient httpClient;
    private final String saveDirectory;
    private final String userAgentIdentity;
    private final ObjectMapper objectMapper;

    public SecEdgarClient(String saveDirectory) {
        this(saveDirectory, DEFAULT_USER_AGENT);
    }

    public SecEdgarClient(String saveDirectory, String userAgentIdentity) {
        this.saveDirectory = saveDirectory;
        this.userAgentIdentity = userAgentIdentity;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Resolves a ticker symbol or raw CIK into a 10-digit zero-padded CIK string.
     */
    public String resolveCik(String tickerOrCik) {
        String clean = tickerOrCik.trim().toUpperCase();
        if (COMMON_TICKER_CIK_MAP.containsKey(clean)) {
            return COMMON_TICKER_CIK_MAP.get(clean);
        }
        // If numeric CIK was passed, pad to 10 digits
        if (clean.matches("\\d+")) {
            return String.format("%010d", Long.parseLong(clean));
        }
        throw new IllegalArgumentException("Unknown corporate ticker symbol: " + tickerOrCik +
                ". Supported direct tickers: " + COMMON_TICKER_CIK_MAP.keySet() +
                " or provide 10-digit CIK directly.");
    }

    /**
     * Fetches metadata for recent company submissions from the SEC EDGAR API.
     */
    public JsonNode getRecentSubmissions(String paddedCik) throws IOException, InterruptedException {
        String endpoint = String.format(SUBMISSIONS_BASE_URL, paddedCik);
        System.out.println("🌐 Querying SEC EDGAR Submissions API: " + endpoint);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("User-Agent", userAgentIdentity)
                .header("Accept", "application/json")
                .header("Accept-Encoding", "gzip, deflate")
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("SEC EDGAR rejected submissions query for CIK " + paddedCik +
                    " with HTTP Status: " + response.statusCode());
        }

        byte[] rawBytes = decompressIfNeeded(response);
        return objectMapper.readTree(rawBytes);
    }

    /**
     * Finds and downloads the latest filing of a specific form type (e.g. "10-K" or "8-K").
     */
    public Optional<Path> fetchLatestFiling(String tickerOrCik, String formType) {
        try {
            String paddedCik = resolveCik(tickerOrCik);
            JsonNode root = getRecentSubmissions(paddedCik);
            JsonNode recent = root.path("filings").path("recent");
            if (recent.isMissingNode() || !recent.has("form")) {
                System.err.println("❌ No recent filing records returned by SEC EDGAR for CIK: " + paddedCik);
                return Optional.empty();
            }

            JsonNode forms = recent.path("form");
            JsonNode accessions = recent.path("accessionNumber");
            JsonNode primaryDocs = recent.path("primaryDocument");
            JsonNode filingDates = recent.path("filingDate");

            int targetIndex = -1;
            for (int i = 0; i < forms.size(); i++) {
                if (forms.get(i).asText().equalsIgnoreCase(formType)) {
                    targetIndex = i;
                    break;
                }
            }

            if (targetIndex == -1) {
                System.err.println("❌ No filing with form type '" + formType + "' found in recent SEC submissions.");
                return Optional.empty();
            }

            String accessionNumber = accessions.get(targetIndex).asText();
            String primaryDoc = primaryDocs.get(targetIndex).asText();
            String filingDate = filingDates.get(targetIndex).asText();

            System.out.printf("📄 Located latest %s for CIK %s: Accession=%s | Doc=%s | Date=%s\n",
                    formType, paddedCik, accessionNumber, primaryDoc, filingDate);

            Path savedPath = downloadFilingData(paddedCik, accessionNumber, primaryDoc, formType);
            return Optional.ofNullable(savedPath);

        } catch (Exception e) {
            System.err.println("❌ SEC EDGAR fetch failed: " + e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Downloads raw text/html data directly via SEC EDGAR archival storage using strict header criteria.
     */
    public Path downloadFilingData(String cik, String accessionNumber, String documentName) {
        return downloadFilingData(cik, accessionNumber, documentName, "FILING");
    }

    public Path downloadFilingData(String cik, String accessionNumber, String documentName, String formTag) {
        String formattedCik = String.format("%010d", Long.parseLong(cik.trim()));
        long numericCik = Long.parseLong(formattedCik);
        String cleanedAccession = accessionNumber.replace("-", "");
        String targetUrl = String.format(ARCHIVES_BASE_URL, numericCik, cleanedAccession, documentName);

        System.out.println("🌐 Executing secure download out to target: " + targetUrl);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("User-Agent", userAgentIdentity)
                .header("Accept", "text/html,application/xhtml+xml,text/plain,*/*")
                .header("Accept-Encoding", "gzip, deflate")
                .GET()
                .build();

        try {
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());

            if (response.statusCode() == 200) {
                byte[] payloadBytes = decompressIfNeeded(response);
                String rawContent = new String(payloadBytes, StandardCharsets.UTF_8);

                // Sanitize HTML/XBRL formatting to clean readable text for local vector ingestion
                String sanitizedText = sanitizeFilingText(rawContent, documentName);

                Path outputDir = Paths.get(saveDirectory);
                Files.createDirectories(outputDir);

                String safeBaseName = documentName.replaceAll("[^a-zA-Z0-9._-]", "_");
                if (safeBaseName.toLowerCase().endsWith(".htm") || safeBaseName.toLowerCase().endsWith(".html")) {
                    safeBaseName = safeBaseName.substring(0, safeBaseName.lastIndexOf('.')) + ".txt";
                }

                Path outputPath = outputDir.resolve("sec_" + formTag.toLowerCase() + "_" + formattedCik + "_" + safeBaseName);
                Files.writeString(outputPath, sanitizedText, StandardCharsets.UTF_8);
                System.out.println("💾 Raw data locked locally to disk payload: " + outputPath.toAbsolutePath());
                return outputPath;
            } else {
                System.err.println("❌ SEC Server denied request. Status Code: " + response.statusCode());
                return null;
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("❌ Network compilation error: " + e.getMessage());
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Strips HTML markup while preserving narrative structure, headers, and bullet points.
     */
    public static String sanitizeFilingText(String rawContent, String docName) {
        if (!docName.toLowerCase().endsWith(".htm") && !docName.toLowerCase().endsWith(".html")) {
            return rawContent;
        }

        // Replace block-level tags with newlines
        String text = rawContent
                .replaceAll("(?i)<(p|div|tr|h[1-6]|br|li)[^>]*>", "\n")
                .replaceAll("(?i)</(p|div|tr|h[1-6]|li)>", "\n")
                .replaceAll("&nbsp;", " ")
                .replaceAll("&amp;", "&")
                .replaceAll("&lt;", "<")
                .replaceAll("&gt;", ">")
                .replaceAll("&quot;", "\"")
                .replaceAll("&#160;", " ");

        // Remove all remaining XML/HTML tags
        text = HTML_TAG_PATTERN.matcher(text).replaceAll("");

        // Collapse excessive whitespace
        text = MULTI_NEWLINE_PATTERN.matcher(text).replaceAll("\n\n");
        return text.trim();
    }

    private byte[] decompressIfNeeded(HttpResponse<byte[]> response) throws IOException {
        byte[] bytes = response.body();
        Optional<String> encoding = response.headers().firstValue("Content-Encoding");
        if (encoding.isPresent() && encoding.get().equalsIgnoreCase("gzip")) {
            try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(bytes))) {
                return gis.readAllBytes();
            }
        }
        return bytes;
    }
}
