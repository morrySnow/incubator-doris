// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.analysis;

import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.Pair;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * TLS certificate requirement options for CREATE/ALTER USER.
 * Supports REQUIRE NONE, REQUIRE SAN 'xxx', and future options (ISSUER, CIPHER, SUBJECT).
 *
 * <p>Current phase implementation:
 * <ul>
 *   <li>Only REQUIRE NONE and REQUIRE SAN 'xxx' are fully supported</li>
 *   <li>Multi-option combinations (SAN AND CIPHER AND ...) are parsed but rejected in analyze()</li>
 *   <li>SAN matching uses entry-level containment (all required entries must exist in certificate SAN)</li>
 * </ul>
 *
 * <p>Semantics:
 * <ul>
 *   <li>REQUIRE NONE clears all TLS requirements</li>
 *   <li>No REQUIRE clause means keep existing settings unchanged</li>
 *   <li>Unset fields use null (not empty string)</li>
 * </ul>
 */
public class TlsOptions {
    private static final Set<String> SUPPORTED_SAN_TYPES = new HashSet<>(Arrays.asList(
            "EMAIL", "DNS", "URI", "IP ADDRESS", "IP"
    ));

    private boolean hasRequireClause;
    private boolean requireNone;
    private String san;
    private String issuer;
    private String subject;
    private String cipher;

    private TlsOptions(boolean hasRequireClause, boolean requireNone,
                       String san, String issuer, String subject, String cipher) {
        this.hasRequireClause = hasRequireClause;
        this.requireNone = requireNone;
        this.san = san;
        this.issuer = issuer;
        this.subject = subject;
        this.cipher = cipher;
    }

    /**
     * Creates TlsOptions indicating no REQUIRE clause was specified.
     * This means existing TLS settings should remain unchanged.
     */
    public static TlsOptions notSpecified() {
        return new TlsOptions(false, false, null, null, null, null);
    }

    /**
     * Creates TlsOptions for REQUIRE NONE.
     * This clears all TLS requirements for the user.
     */
    public static TlsOptions requireNone() {
        return new TlsOptions(true, true, null, null, null, null);
    }

    /**
     * Creates TlsOptions from parsed list of option pairs.
     * This factory method converts the parser output (List of Pairs) into explicit fields.
     *
     * @param options List of (option_name, value) pairs from parser, e.g. [("SAN", "IP:1.2.3.4")]
     * @return TlsOptions with explicit fields populated
     */
    public static TlsOptions of(List<Pair<String, String>> options) {
        if (options == null || options.isEmpty()) {
            return requireNone();
        }

        String san = null;
        String issuer = null;
        String subject = null;
        String cipher = null;

        for (Pair<String, String> opt : options) {
            if (opt == null || opt.first == null) {
                continue;
            }
            String key = opt.first.toUpperCase();
            String value = opt.second;
            switch (key) {
                case "SAN":
                    san = value;
                    break;
                case "ISSUER":
                    issuer = value;
                    break;
                case "SUBJECT":
                    subject = value;
                    break;
                case "CIPHER":
                    cipher = value;
                    break;
                default:
                    // Unknown option - will be caught in analyze()
                    break;
            }
        }

        return new TlsOptions(true, false, san, issuer, subject, cipher);
    }

    /**
     * Validates the TLS options.
     * Current phase: only SAN is supported; multi-option combinations are rejected.
     *
     * @throws AnalysisException if validation fails
     */
    public void analyze() throws AnalysisException {
        if (!hasRequireClause || requireNone) {
            // No validation needed for not specified or REQUIRE NONE
            return;
        }

        // Count how many options are set
        int optionCount = 0;
        if (san != null) {
            optionCount++;
        }
        if (issuer != null) {
            optionCount++;
        }
        if (subject != null) {
            optionCount++;
        }
        if (cipher != null) {
            optionCount++;
        }

        if (optionCount == 0) {
            throw new AnalysisException("REQUIRE clause must specify at least one TLS option or NONE");
        }

        // Current phase: only SAN is supported
        if (issuer != null || subject != null || cipher != null) {
            throw new AnalysisException("Only REQUIRE SAN is supported in current version. "
                    + "ISSUER, SUBJECT, and CIPHER are not yet implemented.");
        }

        // Multi-option combinations are not supported in current phase
        if (optionCount > 1) {
            throw new AnalysisException("Multiple TLS options (e.g., SAN AND CIPHER) "
                    + "are not supported in current version");
        }

        // Validate SAN value is not empty or invalid
        if (san != null) {
            String trimmedSan = san.trim();
            if (trimmedSan.isEmpty()) {
                throw new AnalysisException("SAN value cannot be empty");
            }
            String strippedSan = trimmedSan.replace(",", "").trim();
            if (strippedSan.isEmpty()) {
                throw new AnalysisException("SAN value cannot be empty");
            }
            if (isSanKeywordOnly(trimmedSan)) {
                throw new AnalysisException("SAN value cannot be keyword only");
            }
            if (!trimmedSan.contains(":")) {
                throw new AnalysisException("SAN value must contain ':'");
            }
            validateSanEntries(trimmedSan);
        }
    }

    private static void validateSanEntries(String sanValue) throws AnalysisException {
        String[] entries = sanValue.split(",", -1);
        boolean hasValidEntry = false;
        for (String rawEntry : entries) {
            String entry = rawEntry == null ? "" : rawEntry.trim();
            if (entry.isEmpty()) {
                throw new AnalysisException("SAN value contains empty entry");
            }

            int colonIdx = entry.indexOf(':');
            if (colonIdx <= 0 || colonIdx == entry.length() - 1) {
                throw new AnalysisException(String.format(
                        "Invalid SAN entry format '%s', expected '<type>:<value>'",
                        entry));
            }

            String type = entry.substring(0, colonIdx).trim();
            String value = entry.substring(colonIdx + 1).trim();
            if (type.isEmpty() || value.isEmpty()) {
                throw new AnalysisException(String.format(
                        "Invalid SAN entry format '%s', expected '<type>:<value>'",
                        entry));
            }

            if (!SUPPORTED_SAN_TYPES.contains(type.toUpperCase())) {
                throw new AnalysisException(String.format(
                        "Unsupported SAN entry type '%s' in '%s'. Supported types are: email, DNS, URI, IP Address",
                        type, entry));
            }
            hasValidEntry = true;
        }

        if (!hasValidEntry) {
            throw new AnalysisException("SAN value cannot be empty");
        }
    }

    private static boolean isSanKeywordOnly(String value) {
        if (value == null) {
            return false;
        }
        switch (value.trim().toUpperCase()) {
            case "IP":
            case "DNS":
            case "URI":
            case "NONE":
            case "SAN":
                return true;
            default:
                return false;
        }
    }

    public boolean hasRequireClause() {
        return hasRequireClause;
    }

    public boolean isRequireNone() {
        return requireNone;
    }

    public String getSan() {
        return san;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public String getCipher() {
        return cipher;
    }

    /**
     * Returns SQL fragment for the REQUIRE clause.
     * Empty string means no REQUIRE clause was specified.
     */
    public String toSql() {
        if (!hasRequireClause) {
            return "";
        }
        if (requireNone) {
            return "REQUIRE NONE";
        }

        StringBuilder sb = new StringBuilder("REQUIRE ");
        boolean first = true;

        if (san != null) {
            sb.append("SAN '").append(san).append("'");
            first = false;
        }
        if (issuer != null) {
            if (!first) {
                sb.append(" AND ");
            }
            sb.append("ISSUER '").append(issuer).append("'");
            first = false;
        }
        if (subject != null) {
            if (!first) {
                sb.append(" AND ");
            }
            sb.append("SUBJECT '").append(subject).append("'");
            first = false;
        }
        if (cipher != null) {
            if (!first) {
                sb.append(" AND ");
            }
            sb.append("CIPHER '").append(cipher).append("'");
        }

        // Defensive: if all fields are null but we have a require clause, output NONE
        if (first) {
            return "REQUIRE NONE";
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return toSql();
    }
}
