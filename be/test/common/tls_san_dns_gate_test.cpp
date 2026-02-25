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

#include "common/tls_san_dns_gate.h"

#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
#include <unordered_set>

#include "common/config.h"

namespace doris {

static const std::string kTestCertWithSan = R"(-----BEGIN CERTIFICATE-----
MIIDuTCCAqGgAwIBAgIJAOo/EwpOibq3MA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNV
BAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRAwDgYD
VQQKDAdUZXN0T3JnMREwDwYDVQQLDAhUZXN0VW5pdDEUMBIGA1UEAwwLVGVzdCBD
bGllbnQwHhcNMjYwMTA4MDYyODAzWhcNMjcwMTA4MDYyODAzWjBsMQswCQYDVQQG
EwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzEQMA4GA1UE
CgwHVGVzdE9yZzERMA8GA1UECwwIVGVzdFVuaXQxFDASBgNVBAMMC1Rlc3QgQ2xp
ZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2CRMIw7qwdy/lfap
9qfBjOok4nQlSWPzaoMf0wQk8CUlQQRj88ZBhnbVkL732n4RNW/8Sk+vDO31JHgj
jvIIbYiDCxeE878bF5upgXcoWDs36itcDSHTq+Ln9MLZfTe+3UfKjPAFZ7STrU0w
YYNWjbrQzhSKymNoChe7+sQESl7AOypPU9S7xvBwWMO1Sf4F7KMbe8r9b4HmwTPI
02V7/6MPnU0BcSw7d3mQEVlelEPDSJHXeLfD9aV+2VQ+7j3kNimkD29QGajTupc3
4B+8xf4NE/kAmSO2XQGr8X7fxrtm9Xc/HlsrJwSpbVJbotMA/SVFN7cL8uDe0pz6
ADhVfwIDAQABo14wXDBaBgNVHREEUzBRgRB0ZXN0QGV4YW1wbGUuY29tghZ0ZXN0
Y2xpZW50LmV4YW1wbGUuY29thh9zcGlmZmU6Ly9leGFtcGxlLmNvbS90ZXN0Y2xp
ZW50hwTAqAFkMA0GCSqGSIb3DQEBCwUAA4IBAQAW1UMTC82DxwHMssRiv/UfGViC
ouBG3qriLMZyYFf6oDhgpRNLPDISDYMbnyLpw1L1r5LmRGvCJdmxipF6IkT+7rkO
xOG9/8HvRvZv+CSc/FNMBCDlik3EeITmRwRoWnFxv4CzAQx96HhyLiFk/8mcCVyp
fZt2hoE7Hb8YE3BNZwdI+d8qALY5lhPhkTbNX/dG4tU/I336gyXmeub2EZ8iCD35
qK3NfWiDfpoQMGyU3yt/gYVXTVS12sCL0rht23mx7yPWUCO/ZPpYyTcT6CBg3Qa3
c9jndkTMuRQDT2XcfKIJUw9qQbGelgDEB3pOFlGPKdVW7m1h5r8kd1LZsmXo
-----END CERTIFICATE-----)";

static const std::string kTestCertDnsCase = R"(-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIUOBeUmOqftiVWZl4ju5ZxP+KufogwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHRG5zQ2FzZTAeFw0yNjAyMTQwNzAyMDRaFw0yNzAyMTQw
NzAyMDRaMBIxEDAOBgNVBAMMB0Ruc0Nhc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCwR35SFr26KzpNzz0RyGQ//JsSPSyFuCXsTo9fEk7PEGF5J+Ef
V/JqKS3xS716fuNOIIwUXjzqzD1ec4w/69BaXoQXz56Kgz2yBQj0EJRW+p/bze0f
7rDLzmr69KICLO6H5lNX7Q43JdxCjsjENZa5HEc/4AEj77/VRXFrmIwuLoewACcH
0zVRApRRz5+2DkQmDRD98vzBQ/6T3qYUk6yEAnF2Is7RGwvIHZhjoRS6OxCIZRPC
K0cE6p8cAXTRegJe7r+/OitvHdXemD+BmM8Vz/DnUWGMHutjGMbOgLZAR0XvKDIm
DkGJjSh0FdiVVmXDgjLAhgBux26umeX6JZjDAgMBAAGjbDBqMB0GA1UdDgQWBBSd
uLPXD8VAvrgDv8JNFVQvzJev/DAfBgNVHSMEGDAWgBSduLPXD8VAvrgDv8JNFVQv
zJev/DAPBgNVHRMBAf8EBTADAQH/MBcGA1UdEQQQMA6CDElOVEVSTkFMLkNPTTAN
BgkqhkiG9w0BAQsFAAOCAQEAKtFTXDezrEeR/0DTYxFcJ5Q6bmjz374I7+MJNs/+
o3iBjfAsCem6c5bQGhw1w1iLUIC4i+Hwh2qArVY5/4xa0I4qKDsZHLOegQ5Hskz5
ATsYlop7QZHbEN3DdHY8GMrOUSKpToR+4BoydxHLpinoeB8HqEZYhIsYsun22cMa
dNcRKKmWhubxxP+bkwsLcmKZzSqYXWR3ZFE4fry4rtJkCftLgNP815bKfgyf4aJ8
C+wQ0pc20aBcFrVmaQxkfz0AWdSoZOTcVG0tIbr/0CAbefV+l2H65qYrTxTso2Sj
r+98Ap8tFCCzxrV1W4g9cvAwtXTewlEdvXVRtr///6duQw==
-----END CERTIFICATE-----)";

static const std::string kTestCertUriOnly = R"(-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUUGX+As9rsnf8f+hDp6vzNfkpDUAwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVXJpT25seTAeFw0yNjAyMTQwNzAyMDRaFw0yNzAyMTQw
NzAyMDRaMBIxEDAOBgNVBAMMB1VyaU9ubHkwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDUkBOGaWCINF6kjKf5+2goLbuF8vN3o8nS3LTbjVMNT3J3VKY+
d7zJ3tNqos9Vylg89fWr1l9hLwpJGunEmQE9eRrdOjBwJl1n/0+mMdFQo+upVTi0
ZJPndpyGNhJrSTwbCST8D1jhImH9PsbMWt9VG2+9V9lyzBndoreCkcmU4HdefiKP
PEUYYLuusiE5zNOyNT6mSNfTtakxAj6OPAwC/IEDEh2OTIsoVn5OXH1lUc4CgtE+
cVsGANPTExKT7jpDxOR4KbNJp6YyYCEbrW8wMFPur0lDt3YPxF7nE9Gk7G1FITmW
mG/1mYPJRvwARkPLDRVSpPhwAASPVqFR7tcVAgMBAAGjfTB7MB0GA1UdDgQWBBR0
ld82hpO5HMtYGScJbBl08j2dfjAfBgNVHSMEGDAWgBR0ld82hpO5HMtYGScJbBl0
8j2dfjAPBgNVHRMBAf8EBTADAQH/MCgGA1UdEQQhMB+GHXNwaWZmZTovL2V4YW1w
bGUuY29tL3dvcmtsb2FkMA0GCSqGSIb3DQEBCwUAA4IBAQAk/Dq7U47CbENTDFSx
HdxmMiV0OSPCkgJti+X2VuZw9iH6zWO5rMRHB5sqoc9XHrYfmM94G734iDrZgoQy
3D6bDnTzJootS7I82Z9ivfiKD4PeL8B5MZRjM45yKXs1nMVZ1ik9fP0pQOMpYvQE
G45Rg5R/oUvfklCwhPVlXe5QHkeR2HZmB6GdJy6/2bxU6blY5UQ3aJG0CIIxLhaP
010dgZE1yUZ3GtLhB6gvRRwcgsoR2GTZax/FpzD9zVGLF61whh/VZXudaAI9fQdS
G6Rj2bx87/BVYzuJuTEpItwOTspITqpDRtDKhOuY6txVRWjmZ2188lanqekopDII
Isy2
-----END CERTIFICATE-----)";

static const std::string kTestCertIpOnly = R"(-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIUYvjeaiwvcX2XB+kCYhA2/I+CSVQwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGSXBPbmx5MB4XDTI2MDIxNDA3MDIwNFoXDTI3MDIxNDA3
MDIwNFowETEPMA0GA1UEAwwGSXBPbmx5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAvHQuhB5/29iUm0JydeoiQAMhNlnWVW9JUzKsTE9hr5pdQtaV8T9w
64SxDSkAnYNRBRBLCJNrym39e1TACD++HHzdgCtwUCWPV+s3PwBhj0YPpnfX/7by
M7JD+svuQf8PwDnAK8eVxH+9oRrsEt4zwDQzzGpOCTR7nh4XFyk3oaMUjlTwNskK
r9er0843SG0NnR0ff+4Duxtub2dIkiKr4AH9KbSNgkRnsZxUJKfpIKOWC69B6WyQ
JZ7NH0yT0e2VirUG2O8El9U/zHMVKZcqK68QnwWGokrMvop4vHy9vQFY1WUPO2Sm
l+c9IcJxeeP+Kw6+g8WRtUJsvbdc7LEj0QIDAQABo2QwYjAdBgNVHQ4EFgQU6lW2
33Mi0De2LpebhfcFObuCd5IwHwYDVR0jBBgwFoAU6lW233Mi0De2LpebhfcFObuC
d5IwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwTAqAFkMA0GCSqGSIb3DQEB
CwUAA4IBAQBXQ7PGTftii+xVVpbldKUM6wHmjPtLu+ofCzfpX2bsoc/lGCgwtLXG
+S2uKLoEcNjNaUnmYCUYN86to9Q18qAuR9lyNYHNRGhUmVuYSPLTu3orG4Oy76bk
Fbm/M7onrueJpLwHKrUVC9GMQV3VSToXOr2y83POJjhbbTgeUha1fO12wvtJuF3Y
YZshW+e3jhai8WWmgD6IRP5t4Ze4OKmOj5isL1yP35GcQESPCKl49HidWQTkBqZ+
yNNhHiu6xhxySZZRC3Z35pgtVHfL3LNsbUrrj4CvXtWhvidP/Cw50EFWIZIJvRPb
6woILlRkXV+ubIt3/XNeeZ8kXrxC4f9E
-----END CERTIFICATE-----)";

static const std::string kTestCertCnOnly = R"(-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUQAwfca6wYy4Klqm/tS6T6Ab6K70wDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGQ25Pbmx5MB4XDTI2MDIxNDA3MDIwNFoXDTI3MDIxNDA3
MDIwNFowETEPMA0GA1UEAwwGQ25Pbmx5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAyoQQtpOIyDju3XchsBIfwXDHafA7AGqfJ4PWgZDu85IZxfxRbMNo
sS/UYtOfZf2QbiMXCjrwz49GPp2fC45QVj/EvZ2dv2IvqKI5LHAfsOOMiDxBo0Eh
LriFFKwhIffewubZFOus/9PLMzM3UH05nRY1lSNje9V4tp/Vu89C/6CHkaq2HcKr
/1WtH0B9bk5+913rQoSDerA3BbWikajM0DihKWBDuusIFO2JqDHoNmk646GJHuax
3LL3nybTpgK5eUaYFhdRrfToe1FVJgJsFm3RJHn2PUNnwr38rqFKnmrmoFjId7TG
8Nvv8Aluqr/PoWHGTr/btuosEcMTDA8WtQIDAQABo1MwUTAdBgNVHQ4EFgQUAh8W
DpUjDWV2fwuIZM0SPHDE90gwHwYDVR0jBBgwFoAUAh8WDpUjDWV2fwuIZM0SPHDE
90gwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAUfQs/9wkNGUD
VjBtMAo1KhitpdwTSipwFmd3bSzw9azik9neLvcgv8gYMCMIuaEpfbN7aDN2qV2b
i4OGZEOVXUK/DNKa3SCUPiwzZzPjYfJFl69JDc7BfUBOCjhqhszOMHkWxVPMTGHF
iZzmhs+VCOJgikoYlzD3Gla4h3cwVy8qJbh/jTuriGgvv2MeFv2YSe2z8jErPncy
dfTpEIxrgchje9Gy9EJJ9vHS6Uc3FnvjRbtY1Wemh9LfuK+XQArvAMWGY0rAHPNg
MT/hnoy+TL19lO27H0y7ooRUNKO4BTYQr54z55WZn/K6I7Z5I5MJ1ZsvUNsLJ3qY
C+Uk54AhdQ==
-----END CERTIFICATE-----)";

class TlsSanDnsGateTest : public ::testing::Test {
protected:
    X509* load_cert_from_string(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.c_str(), static_cast<int>(pem.size()));
        if (!bio) {
            return nullptr;
        }
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        return cert;
    }
};

class ScopedSanDnsConfig {
public:
    explicit ScopedSanDnsConfig(std::string value)
            : old_value_(config::tls_peer_cert_required_san_dns) {
        config::tls_peer_cert_required_san_dns = std::move(value);
    }

    ~ScopedSanDnsConfig() { config::tls_peer_cert_required_san_dns = old_value_; }

private:
    std::string old_value_;
};

TEST_F(TlsSanDnsGateTest, ParseConfigNormalizesDns) {
    auto parsed =
            TlsSanDnsGate::parse_config("brpc=internal.com,Internal2.com.;thrift=Internal.com. ");

    auto brpc_it = parsed.allowed.find("brpc");
    ASSERT_NE(brpc_it, parsed.allowed.end());
    EXPECT_EQ(brpc_it->second.count("internal.com"), 1);
    EXPECT_EQ(brpc_it->second.count("internal2.com"), 1);

    auto thrift_it = parsed.allowed.find("thrift");
    ASSERT_NE(thrift_it, parsed.allowed.end());
    EXPECT_EQ(thrift_it->second.count("internal.com"), 1);
}

TEST_F(TlsSanDnsGateTest, ParseConfigIgnoresInvalidSegments) {
    auto parsed = TlsSanDnsGate::parse_config("bad;http=internal.com;thrift=;brpc=internal.com");

    EXPECT_EQ(parsed.allowed.size(), 1);
    auto brpc_it = parsed.allowed.find("brpc");
    ASSERT_NE(brpc_it, parsed.allowed.end());
    EXPECT_EQ(brpc_it->second.count("internal.com"), 1);
}

TEST_F(TlsSanDnsGateTest, ParseConfigReturnsEmptyOnBlankInput) {
    auto parsed_whitespace = TlsSanDnsGate::parse_config("   ");
    EXPECT_TRUE(parsed_whitespace.allowed.empty());

    auto parsed_empty_segments = TlsSanDnsGate::parse_config("  ;   ; ");
    EXPECT_TRUE(parsed_empty_segments.allowed.empty());
}

TEST_F(TlsSanDnsGateTest, ParseConfigAcceptsIpLikeDns) {
    auto parsed = TlsSanDnsGate::parse_config("brpc=10.23.45.67.;thrift=10.23.45.67");

    auto brpc_it = parsed.allowed.find("brpc");
    ASSERT_NE(brpc_it, parsed.allowed.end());
    EXPECT_EQ(brpc_it->second.count("10.23.45.67"), 1);

    auto thrift_it = parsed.allowed.find("thrift");
    ASSERT_NE(thrift_it, parsed.allowed.end());
    EXPECT_EQ(thrift_it->second.count("10.23.45.67"), 1);
}

TEST_F(TlsSanDnsGateTest, ExtractDnsSans) {
    std::unique_ptr<X509, decltype(&X509_free)> cert(load_cert_from_string(kTestCertWithSan),
                                                     X509_free);
    ASSERT_NE(cert, nullptr);

    auto dns_sans = TlsSanDnsGate::extract_dns_sans(cert.get());
    ASSERT_FALSE(dns_sans.empty());
    EXPECT_EQ(dns_sans[0], "testclient.example.com");
}

TEST_F(TlsSanDnsGateTest, ExtractDnsSansCaseInsensitive) {
    std::unique_ptr<X509, decltype(&X509_free)> cert(load_cert_from_string(kTestCertDnsCase),
                                                     X509_free);
    ASSERT_NE(cert, nullptr);

    auto dns_sans = TlsSanDnsGate::extract_dns_sans(cert.get());
    ASSERT_EQ(dns_sans.size(), 1);
    EXPECT_EQ(dns_sans[0], "internal.com");
}

TEST_F(TlsSanDnsGateTest, ExtractDnsSansExcludesUriIpAndCnOnlyCertificates) {
    std::unique_ptr<X509, decltype(&X509_free)> uri_only_cert(
            load_cert_from_string(kTestCertUriOnly), X509_free);
    ASSERT_NE(uri_only_cert, nullptr);
    EXPECT_TRUE(TlsSanDnsGate::extract_dns_sans(uri_only_cert.get()).empty());

    std::unique_ptr<X509, decltype(&X509_free)> ip_only_cert(load_cert_from_string(kTestCertIpOnly),
                                                             X509_free);
    ASSERT_NE(ip_only_cert, nullptr);
    EXPECT_TRUE(TlsSanDnsGate::extract_dns_sans(ip_only_cert.get()).empty());

    std::unique_ptr<X509, decltype(&X509_free)> cn_only_cert(load_cert_from_string(kTestCertCnOnly),
                                                             X509_free);
    ASSERT_NE(cn_only_cert, nullptr);
    EXPECT_TRUE(TlsSanDnsGate::extract_dns_sans(cn_only_cert.get()).empty());
}

TEST_F(TlsSanDnsGateTest, ExtractDnsSansHandlesNullCert) {
    auto dns_sans = TlsSanDnsGate::extract_dns_sans(nullptr);
    EXPECT_TRUE(dns_sans.empty());
}

TEST_F(TlsSanDnsGateTest, MatchesAllowlist) {
    std::unique_ptr<X509, decltype(&X509_free)> cert(load_cert_from_string(kTestCertWithSan),
                                                     X509_free);
    ASSERT_NE(cert, nullptr);

    auto dns_sans = TlsSanDnsGate::extract_dns_sans(cert.get());
    std::unordered_set<std::string> allowlist = {"testclient.example.com"};
    EXPECT_TRUE(TlsSanDnsGate::matches_allowlist(allowlist, dns_sans));

    std::unordered_set<std::string> denylist = {"other.example.com"};
    EXPECT_FALSE(TlsSanDnsGate::matches_allowlist(denylist, dns_sans));
}

TEST_F(TlsSanDnsGateTest, NormalizeAndMatchIpLikeDns) {
    EXPECT_EQ("10.23.45.67", TlsSanDnsGate::normalize_dns(" 10.23.45.67. "));

    std::unordered_set<std::string> allowlist = {"10.23.45.67"};
    std::vector<std::string> peer_dns_sans = {"10.23.45.67"};
    EXPECT_TRUE(TlsSanDnsGate::matches_allowlist(allowlist, peer_dns_sans));
}

TEST_F(TlsSanDnsGateTest, MatchesAllowlistHandlesEmptyInputs) {
    std::unordered_set<std::string> allowlist = {"testclient.example.com"};
    std::vector<std::string> empty_dns;
    EXPECT_FALSE(TlsSanDnsGate::matches_allowlist(allowlist, empty_dns));

    std::unordered_set<std::string> empty_allowlist;
    std::vector<std::string> dns = {"testclient.example.com"};
    EXPECT_FALSE(TlsSanDnsGate::matches_allowlist(empty_allowlist, dns));
}

TEST_F(TlsSanDnsGateTest, ConfigBackedProtocolLookupRefreshesCache) {
    {
        ScopedSanDnsConfig cfg("brpc=internal.com;thrift=rpc.example.com");
        EXPECT_TRUE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolBrpc));
        EXPECT_TRUE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolThrift));
        const auto* thrift_allowed = TlsSanDnsGate::get_allowed_dns(TlsSanDnsGate::kProtocolThrift);
        ASSERT_NE(thrift_allowed, nullptr);
        EXPECT_EQ(thrift_allowed->count("rpc.example.com"), 1);
        EXPECT_EQ(TlsSanDnsGate::get_allowed_dns("unknown"), nullptr);
    }

    {
        ScopedSanDnsConfig cfg("brpc=only-brpc.example.com");
        EXPECT_TRUE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolBrpc));
        EXPECT_FALSE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolThrift));
        EXPECT_EQ(TlsSanDnsGate::get_allowed_dns(TlsSanDnsGate::kProtocolThrift), nullptr);
    }
}

TEST_F(TlsSanDnsGateTest, ProtocolGranularityIsolation) {
    {
        ScopedSanDnsConfig cfg("thrift=internal.com");
        EXPECT_TRUE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolThrift));
        EXPECT_FALSE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolBrpc));
    }

    {
        ScopedSanDnsConfig cfg("brpc=internal.com");
        EXPECT_TRUE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolBrpc));
        EXPECT_FALSE(TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolThrift));
    }
}

TEST_F(TlsSanDnsGateTest, FormatHelpersHandleEmptyAndTruncatedOutput) {
    std::unordered_set<std::string> empty_allowlist;
    EXPECT_EQ(TlsSanDnsGate::format_allowlist(empty_allowlist), "[]");

    std::unordered_set<std::string> allowlist = {"a.example.com", "b.example.com"};
    std::string allowlist_text = TlsSanDnsGate::format_allowlist(allowlist, 1);
    EXPECT_NE(allowlist_text.find("..."), std::string::npos);

    std::vector<std::string> empty_dns;
    EXPECT_EQ(TlsSanDnsGate::format_dns_sans(empty_dns), "[]");

    std::vector<std::string> dns = {"a.example.com", "b.example.com"};
    EXPECT_EQ(TlsSanDnsGate::format_dns_sans(dns, 1), "[a.example.com, ...]");
}

TEST_F(TlsSanDnsGateTest, NormalizeDnsHandlesBlankInput) {
    EXPECT_EQ(TlsSanDnsGate::normalize_dns("   "), "");
}

} // namespace doris
