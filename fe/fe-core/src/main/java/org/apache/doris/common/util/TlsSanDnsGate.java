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

package org.apache.doris.common.util;

import org.apache.doris.common.Config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class TlsSanDnsGate {
    private static final Logger LOG = LogManager.getLogger(TlsSanDnsGate.class);
    public static final String PROTOCOL_THRIFT = "thrift";
    public static final String PROTOCOL_BRPC = "brpc";

    private static final class CachedConfig {
        private final String rawValue;
        private final Map<String, Set<String>> allowed;

        private CachedConfig(String rawValue, Map<String, Set<String>> allowed) {
            this.rawValue = rawValue;
            this.allowed = allowed;
        }
    }

    private static final Object CONFIG_LOCK = new Object();
    private static volatile CachedConfig cachedConfig = new CachedConfig("", Collections.emptyMap());

    private TlsSanDnsGate() {
    }

    static Map<String, Set<String>> parseConfig(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, Set<String>> result = new HashMap<>();
        String[] segments = value.split(";");
        for (String segment : segments) {
            if (segment == null) {
                continue;
            }
            String trimmed = segment.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int idx = trimmed.indexOf('=');
            if (idx <= 0 || idx == trimmed.length() - 1) {
                LOG.warn("Ignore invalid tls_peer_cert_required_san_dns segment: {}", trimmed);
                continue;
            }
            String protocol = trimmed.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            if (!isSupportedProtocol(protocol)) {
                LOG.warn("Ignore unsupported tls_peer_cert_required_san_dns protocol: {}", protocol);
                continue;
            }
            String dnsList = trimmed.substring(idx + 1);
            String[] dnsItems = dnsList.split(",");
            Set<String> dnsSet = new HashSet<>();
            for (String dns : dnsItems) {
                String normalized = normalizeDns(dns);
                if (!normalized.isEmpty()) {
                    dnsSet.add(normalized);
                }
            }
            if (dnsSet.isEmpty()) {
                LOG.warn("Ignore tls_peer_cert_required_san_dns segment with empty dns list: {}", trimmed);
                continue;
            }
            result.computeIfAbsent(protocol, key -> new HashSet<>()).addAll(dnsSet);
        }
        return result;
    }

    public static boolean isProtocolEnabled(String protocol) {
        Set<String> allowed = getAllowedDns(protocol);
        return !allowed.isEmpty();
    }

    static Set<String> getAllowedDns(String protocol) {
        CachedConfig config = getCachedConfig();
        Set<String> allowed = config.allowed.get(protocol);
        if (allowed == null) {
            return Collections.emptySet();
        }
        return allowed;
    }

    static List<String> extractDnsSans(X509Certificate certificate) {
        if (certificate == null) {
            return Collections.emptyList();
        }
        Collection<List<?>> sans;
        try {
            sans = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            LOG.warn("Failed to parse certificate SAN", e);
            return Collections.emptyList();
        }
        if (sans == null) {
            return Collections.emptyList();
        }
        List<String> dnsSans = new ArrayList<>();
        for (List<?> entry : sans) {
            if (entry == null || entry.size() < 2) {
                continue;
            }
            Object typeObj = entry.get(0);
            Object valueObj = entry.get(1);
            if (!(typeObj instanceof Integer)) {
                continue;
            }
            int type = (Integer) typeObj;
            if (type != 2) {
                continue;
            }
            if (!(valueObj instanceof String)) {
                continue;
            }
            String normalized = normalizeDns((String) valueObj);
            if (!normalized.isEmpty()) {
                dnsSans.add(normalized);
            }
        }
        return dnsSans;
    }

    static boolean matchesAllowlist(Set<String> allowlist, List<String> dnsSans) {
        if (allowlist == null || allowlist.isEmpty() || dnsSans == null || dnsSans.isEmpty()) {
            return false;
        }
        for (String dns : dnsSans) {
            if (allowlist.contains(dns)) {
                return true;
            }
        }
        return false;
    }

    static String normalizeDns(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    public static X509TlsReloadableTrustManager.SslSocketAndEnginePeerVerifier buildVerifier(
            String protocol) {
        return new X509TlsReloadableTrustManager.SslSocketAndEnginePeerVerifier() {
            @Override
            public void verifyPeerCertificate(X509Certificate[] peerCertChain, String authType,
                    java.net.Socket socket) throws java.security.cert.CertificateException {
                verify(peerCertChain, authType);
            }

            @Override
            public void verifyPeerCertificate(X509Certificate[] peerCertChain, String authType,
                    javax.net.ssl.SSLEngine engine) throws java.security.cert.CertificateException {
                verify(peerCertChain, authType);
            }

            private void verify(X509Certificate[] peerCertChain, String authType)
                    throws java.security.cert.CertificateException {
                if (peerCertChain == null || peerCertChain.length == 0) {
                    throw new java.security.cert.CertificateException("No peer certificate provided");
                }
                Set<String> allowlist = getAllowedDns(protocol);
                if (allowlist.isEmpty()) {
                    return;
                }
                List<String> peerDns = extractDnsSans(peerCertChain[0]);
                if (!matchesAllowlist(allowlist, peerDns)) {
                    throw new java.security.cert.CertificateException(
                            "TLS SAN DNS gate reject peer certificate, protocol=" + protocol
                                    + ", allowlist=" + allowlist + ", peer_dns=" + peerDns);
                }
            }
        };
    }

    private static CachedConfig getCachedConfig() {
        String current = Config.tls_peer_cert_required_san_dns == null
                ? "" : Config.tls_peer_cert_required_san_dns;
        CachedConfig local = cachedConfig;
        if (current.equals(local.rawValue)) {
            return local;
        }
        synchronized (CONFIG_LOCK) {
            local = cachedConfig;
            if (current.equals(local.rawValue)) {
                return local;
            }
            Map<String, Set<String>> parsed = parseConfig(current);
            cachedConfig = new CachedConfig(current, parsed);
            return cachedConfig;
        }
    }

    private static boolean isSupportedProtocol(String protocol) {
        return PROTOCOL_THRIFT.equals(protocol) || PROTOCOL_BRPC.equals(protocol);
    }
}
