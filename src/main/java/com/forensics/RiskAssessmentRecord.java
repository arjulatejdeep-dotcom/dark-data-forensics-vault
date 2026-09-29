package com.forensics;

import java.time.Instant;

/**
 * RiskAssessmentRecord: Structured data contract for automated forensic risk assessment and irregularity ledger.
 *
 * Captures detected corporate anomalies, unrecorded liabilities, executive concealment directives,
 * and regulatory contingencies with cryptographic chain of custody fingerprints.
 */
public record RiskAssessmentRecord(
        String riskId,
        String riskLevel,           // "CRITICAL", "HIGH", "MEDIUM"
        String category,            // "EXECUTIVE_CONCEALMENT", "UNRECORDED_LIABILITY", "OFF_SHEET_SPE", "REGULATORY_SUBPOENA", "CREDENTIAL_LEAK", etc.
        String targetEntity,        // e.g. "Apex Global Capital Corp.", "Tesla, Inc.", "Apple Inc."
        String sourceFile,          // Original artifact source
        String blockSha256,         // SHA-256 fingerprint of the supporting evidence block
        String detectedIrregularity,// Plaintext narrative description of the anomaly found
        String exposureAmount,      // Extracted dollar figure or financial exposure liability
        String recommendedAction,   // Forensic auditor recommendation
        String timestamp
) {
    public RiskAssessmentRecord(
            String riskId,
            String riskLevel,
            String category,
            String targetEntity,
            String sourceFile,
            String blockSha256,
            String detectedIrregularity,
            String exposureAmount,
            String recommendedAction
    ) {
        this(riskId, riskLevel, category, targetEntity, sourceFile, blockSha256, detectedIrregularity, exposureAmount, recommendedAction, Instant.now().toString());
    }
}
