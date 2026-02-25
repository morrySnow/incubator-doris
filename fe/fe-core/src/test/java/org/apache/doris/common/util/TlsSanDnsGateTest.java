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

import mockit.Expectations;
import mockit.Mocked;
import org.junit.Assert;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TlsSanDnsGateTest {

    @Test
    public void testParseConfigNormalizesDns() {
        Map<String, Set<String>> parsed = TlsSanDnsGate.parseConfig(
                "brpc=Internal.com,Internal2.com.;thrift=Internal.com.");

        Assert.assertTrue(parsed.containsKey("brpc"));
        Assert.assertTrue(parsed.get("brpc").contains("internal.com"));
        Assert.assertTrue(parsed.get("brpc").contains("internal2.com"));
        Assert.assertTrue(parsed.containsKey("thrift"));
        Assert.assertTrue(parsed.get("thrift").contains("internal.com"));
    }

    @Test
    public void testParseConfigIgnoresInvalidSegments() {
        Map<String, Set<String>> parsed = TlsSanDnsGate.parseConfig(
                "bad;http=internal.com;thrift=;brpc=internal.com");

        Assert.assertEquals(1, parsed.size());
        Assert.assertTrue(parsed.containsKey("brpc"));
        Assert.assertTrue(parsed.get("brpc").contains("internal.com"));
    }

    @Test
    public void testParseConfigAcceptsIpLikeDns() {
        Map<String, Set<String>> parsed = TlsSanDnsGate.parseConfig(
                "brpc=10.23.45.67.;thrift=10.23.45.67");

        Assert.assertTrue(parsed.containsKey("brpc"));
        Assert.assertTrue(parsed.get("brpc").contains("10.23.45.67"));
        Assert.assertTrue(parsed.containsKey("thrift"));
        Assert.assertTrue(parsed.get("thrift").contains("10.23.45.67"));
    }

    @Test
    public void testParseConfigReturnsEmptyOnBlankAndNullInput() {
        Assert.assertTrue(TlsSanDnsGate.parseConfig(null).isEmpty());
        Assert.assertTrue(TlsSanDnsGate.parseConfig("  ;   ; ").isEmpty());
        Assert.assertTrue(TlsSanDnsGate.parseConfig("   ").isEmpty());
    }

    @Test
    public void testExtractDnsSans(@Mocked X509Certificate mockCert) throws Exception {
        Collection<List<?>> sanCollection = new ArrayList<>();

        List<Object> dnsSan = new ArrayList<>();
        dnsSan.add(Integer.valueOf(2));
        dnsSan.add("Internal.Com.");
        sanCollection.add(dnsSan);

        List<Object> uriSan = new ArrayList<>();
        uriSan.add(Integer.valueOf(6));
        uriSan.add("spiffe://example.com/test");
        sanCollection.add(uriSan);

        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = sanCollection;
            }
        };

        List<String> dnsSans = TlsSanDnsGate.extractDnsSans(mockCert);
        Assert.assertEquals(1, dnsSans.size());
        Assert.assertEquals("internal.com", dnsSans.get(0));
    }

    @Test
    public void testExtractDnsSansWithIpLikeDns(@Mocked X509Certificate mockCert) throws Exception {
        Collection<List<?>> sanCollection = new ArrayList<>();

        List<Object> dnsSan = new ArrayList<>();
        dnsSan.add(Integer.valueOf(2));
        dnsSan.add("10.23.45.67.");
        sanCollection.add(dnsSan);

        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = sanCollection;
            }
        };

        List<String> dnsSans = TlsSanDnsGate.extractDnsSans(mockCert);
        Assert.assertEquals(1, dnsSans.size());
        Assert.assertEquals("10.23.45.67", dnsSans.get(0));
    }

    @Test
    public void testExtractDnsSansCaseInsensitive(@Mocked X509Certificate mockCert) throws Exception {
        Collection<List<?>> sanCollection = new ArrayList<>();

        List<Object> dnsSan = new ArrayList<>();
        dnsSan.add(Integer.valueOf(2));
        dnsSan.add("INTERNAL.COM");
        sanCollection.add(dnsSan);

        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = sanCollection;
            }
        };

        List<String> dnsSans = TlsSanDnsGate.extractDnsSans(mockCert);
        Assert.assertEquals(1, dnsSans.size());
        Assert.assertEquals("internal.com", dnsSans.get(0));
    }

    @Test
    public void testExtractDnsSansUriOnlyReturnsEmpty(@Mocked X509Certificate mockCert) throws Exception {
        Collection<List<?>> sanCollection = new ArrayList<>();
        sanCollection.add(java.util.Arrays.asList(Integer.valueOf(6), "spiffe://example.com/workload"));

        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = sanCollection;
            }
        };

        Assert.assertTrue(TlsSanDnsGate.extractDnsSans(mockCert).isEmpty());
    }

    @Test
    public void testExtractDnsSansIpOnlyReturnsEmpty(@Mocked X509Certificate mockCert) throws Exception {
        Collection<List<?>> sanCollection = new ArrayList<>();
        sanCollection.add(java.util.Arrays.asList(Integer.valueOf(7), "192.168.1.100"));

        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = sanCollection;
            }
        };

        Assert.assertTrue(TlsSanDnsGate.extractDnsSans(mockCert).isEmpty());
    }

    @Test
    public void testExtractDnsSansHandlesNullCertificate() {
        Assert.assertTrue(TlsSanDnsGate.extractDnsSans(null).isEmpty());
    }

    @Test
    public void testExtractDnsSansHandlesParsingException(@Mocked X509Certificate mockCert) throws Exception {
        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = new CertificateParsingException("mock parse failure");
            }
        };

        Assert.assertTrue(TlsSanDnsGate.extractDnsSans(mockCert).isEmpty());
    }

    @Test
    public void testExtractDnsSansIgnoresMalformedEntries(@Mocked X509Certificate mockCert) throws Exception {
        Collection<List<?>> sanCollection = new ArrayList<>();
        sanCollection.add(java.util.Arrays.asList(Integer.valueOf(2)));
        sanCollection.add(java.util.Arrays.asList("2", "bad-type"));
        sanCollection.add(java.util.Arrays.asList(Integer.valueOf(2), Integer.valueOf(123)));

        new Expectations() {
            {
                mockCert.getSubjectAlternativeNames();
                result = sanCollection;
            }
        };

        Assert.assertTrue(TlsSanDnsGate.extractDnsSans(mockCert).isEmpty());
    }

    @Test
    public void testMatchesAllowlist() {
        Set<String> allowlist = new java.util.HashSet<>();
        allowlist.add("internal.com");
        List<String> dnsSans = new java.util.ArrayList<>();
        dnsSans.add("internal.com");
        Assert.assertTrue(TlsSanDnsGate.matchesAllowlist(allowlist, dnsSans));

        List<String> otherSans = new java.util.ArrayList<>();
        otherSans.add("other.com");
        Assert.assertFalse(TlsSanDnsGate.matchesAllowlist(allowlist, otherSans));
    }

    @Test
    public void testMatchesAllowlistWithIpLikeDns() {
        Set<String> allowlist = new java.util.HashSet<>();
        allowlist.add("10.23.45.67");

        List<String> dnsSans = new java.util.ArrayList<>();
        dnsSans.add("10.23.45.67");
        Assert.assertTrue(TlsSanDnsGate.matchesAllowlist(allowlist, dnsSans));
    }

    @Test
    public void testMatchesAllowlistHandlesEmptyInputs() {
        Set<String> allowlist = new java.util.HashSet<>();
        allowlist.add("internal.com");

        Assert.assertFalse(TlsSanDnsGate.matchesAllowlist(allowlist, new ArrayList<>()));
        Assert.assertFalse(TlsSanDnsGate.matchesAllowlist(new java.util.HashSet<>(),
                java.util.Collections.singletonList("internal.com")));
        Assert.assertFalse(TlsSanDnsGate.matchesAllowlist(null,
                java.util.Collections.singletonList("internal.com")));
        Assert.assertFalse(TlsSanDnsGate.matchesAllowlist(allowlist, null));
    }

    @Test
    public void testNormalizeDnsHandlesBlankAndNullInput() {
        Assert.assertEquals("", TlsSanDnsGate.normalizeDns(null));
        Assert.assertEquals("", TlsSanDnsGate.normalizeDns("   "));
        Assert.assertEquals("internal.com", TlsSanDnsGate.normalizeDns(" Internal.com. "));
    }

    @Test
    public void testConfigBackedProtocolLookupRefreshesCache() {
        String oldGate = Config.tls_peer_cert_required_san_dns;
        try {
            Config.tls_peer_cert_required_san_dns = "brpc=internal.com;thrift=rpc.example.com";
            Assert.assertTrue(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_BRPC));
            Assert.assertTrue(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_THRIFT));
            Assert.assertTrue(TlsSanDnsGate.getAllowedDns(TlsSanDnsGate.PROTOCOL_THRIFT)
                    .contains("rpc.example.com"));

            Config.tls_peer_cert_required_san_dns = "brpc=internal.com";
            Assert.assertTrue(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_BRPC));
            Assert.assertFalse(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_THRIFT));
            Assert.assertTrue(TlsSanDnsGate.getAllowedDns(TlsSanDnsGate.PROTOCOL_THRIFT).isEmpty());
            Assert.assertTrue(TlsSanDnsGate.getAllowedDns("unknown").isEmpty());
        } finally {
            Config.tls_peer_cert_required_san_dns = oldGate;
        }
    }

    @Test
    public void testProtocolGranularityIsolation() {
        String oldGate = Config.tls_peer_cert_required_san_dns;
        try {
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Assert.assertTrue(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_THRIFT));
            Assert.assertFalse(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_BRPC));

            Config.tls_peer_cert_required_san_dns = "brpc=internal.com";
            Assert.assertTrue(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_BRPC));
            Assert.assertFalse(TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_THRIFT));
        } finally {
            Config.tls_peer_cert_required_san_dns = oldGate;
        }
    }

    @Test
    public void testBuildVerifierCoversGatePaths(@Mocked X509Certificate mockCert) throws Exception {
        String oldGate = Config.tls_peer_cert_required_san_dns;
        try {
            X509TlsReloadableTrustManager.SslSocketAndEnginePeerVerifier verifier =
                    TlsSanDnsGate.buildVerifier(TlsSanDnsGate.PROTOCOL_THRIFT);

            try {
                verifier.verifyPeerCertificate(new X509Certificate[0], "RSA", (java.net.Socket) null);
                Assert.fail("Expected CertificateException when peer certificate chain is empty");
            } catch (CertificateException e) {
                Assert.assertTrue(e.getMessage().contains("No peer certificate provided"));
            }

            Config.tls_peer_cert_required_san_dns = "";
            verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA", (java.net.Socket) null);

            Collection<List<?>> mismatchSan = new ArrayList<>();
            mismatchSan.add(java.util.Arrays.asList(Integer.valueOf(2), "other.example.com"));
            new Expectations() {
                {
                    mockCert.getSubjectAlternativeNames();
                    result = mismatchSan;
                }
            };
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            try {
                verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA",
                        (javax.net.ssl.SSLEngine) null);
                Assert.fail("Expected CertificateException for SAN gate mismatch");
            } catch (CertificateException e) {
                Assert.assertTrue(e.getMessage().contains("allowlist"));
            }

            Collection<List<?>> matchSan = new ArrayList<>();
            matchSan.add(java.util.Arrays.asList(Integer.valueOf(2), "internal.com"));
            new Expectations() {
                {
                    mockCert.getSubjectAlternativeNames();
                    result = matchSan;
                }
            };
            verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA",
                    (java.net.Socket) null);
        } finally {
            Config.tls_peer_cert_required_san_dns = oldGate;
        }
    }

    @Test
    public void testBuildVerifierCaseInsensitiveAndSanTypeExclusion(@Mocked X509Certificate mockCert)
            throws Exception {
        String oldGate = Config.tls_peer_cert_required_san_dns;
        try {
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            X509TlsReloadableTrustManager.SslSocketAndEnginePeerVerifier verifier =
                    TlsSanDnsGate.buildVerifier(TlsSanDnsGate.PROTOCOL_THRIFT);

            Collection<List<?>> uppercaseDnsSan = new ArrayList<>();
            uppercaseDnsSan.add(java.util.Arrays.asList(Integer.valueOf(2), "INTERNAL.COM"));

            Collection<List<?>> uriOnlySan = new ArrayList<>();
            uriOnlySan.add(java.util.Arrays.asList(Integer.valueOf(6), "spiffe://example.com/workload"));

            Collection<List<?>> ipOnlySan = new ArrayList<>();
            ipOnlySan.add(java.util.Arrays.asList(Integer.valueOf(7), "192.168.1.100"));

            new Expectations() {
                {
                    mockCert.getSubjectAlternativeNames();
                    returns(uppercaseDnsSan, uriOnlySan, ipOnlySan, null);
                }
            };

            verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA",
                    (java.net.Socket) null);

            try {
                verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA",
                        (java.net.Socket) null);
                Assert.fail("Expected CertificateException for URI-only SAN certificate");
            } catch (CertificateException e) {
                Assert.assertTrue(e.getMessage().contains("peer_dns=[]"));
            }

            try {
                verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA",
                        (javax.net.ssl.SSLEngine) null);
                Assert.fail("Expected CertificateException for IP-only SAN certificate");
            } catch (CertificateException e) {
                Assert.assertTrue(e.getMessage().contains("peer_dns=[]"));
            }

            try {
                verifier.verifyPeerCertificate(new X509Certificate[] {mockCert}, "RSA",
                        (java.net.Socket) null);
                Assert.fail("Expected CertificateException for CN-only certificate");
            } catch (CertificateException e) {
                Assert.assertTrue(e.getMessage().contains("peer_dns=[]"));
            }
        } finally {
            Config.tls_peer_cert_required_san_dns = oldGate;
        }
    }
}
