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

#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "common/config.h"
#include "common/logging.h"

namespace doris {
namespace {

struct CachedConfig {
    std::string raw_value;
    TlsSanDnsGate::ParsedConfig parsed;
};

std::mutex g_config_mutex;
CachedConfig g_cached_config;

std::string trim(std::string_view input) {
    size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
        ++start;
    }
    size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }
    return std::string(input.substr(start, end - start));
}

std::vector<std::string> split_to_vector(std::string_view input, char delimiter) {
    std::vector<std::string> result;
    size_t start = 0;
    while (start <= input.size()) {
        size_t pos = input.find(delimiter, start);
        if (pos == std::string_view::npos) {
            pos = input.size();
        }
        result.emplace_back(input.substr(start, pos - start));
        if (pos == input.size()) {
            break;
        }
        start = pos + 1;
    }
    return result;
}

bool is_supported_protocol(const std::string& protocol) {
    return protocol == TlsSanDnsGate::kProtocolBrpc || protocol == TlsSanDnsGate::kProtocolThrift;
}

const TlsSanDnsGate::ParsedConfig& get_cached_config() {
    std::lock_guard<std::mutex> lock(g_config_mutex);
    if (g_cached_config.raw_value != config::tls_peer_cert_required_san_dns) {
        g_cached_config.raw_value = config::tls_peer_cert_required_san_dns;
        g_cached_config.parsed = TlsSanDnsGate::parse_config(g_cached_config.raw_value);
    }
    return g_cached_config.parsed;
}

} // namespace

TlsSanDnsGate::ParsedConfig TlsSanDnsGate::parse_config(const std::string& value) {
    ParsedConfig result;
    std::string trimmed_value = trim(value);
    if (trimmed_value.empty()) {
        return result;
    }

    auto segments = split_to_vector(trimmed_value, ';');
    for (const auto& raw_segment : segments) {
        std::string segment = trim(raw_segment);
        if (segment.empty()) {
            continue;
        }

        size_t eq_pos = segment.find('=');
        if (eq_pos == std::string::npos) {
            LOG(WARNING) << "Ignore invalid tls_peer_cert_required_san_dns segment: " << segment;
            continue;
        }

        std::string protocol = trim(std::string_view(segment).substr(0, eq_pos));
        std::string dns_list = std::string(std::string_view(segment).substr(eq_pos + 1));
        std::transform(protocol.begin(), protocol.end(), protocol.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (!is_supported_protocol(protocol)) {
            LOG(WARNING) << "Ignore unsupported tls_peer_cert_required_san_dns protocol: "
                         << protocol;
            continue;
        }

        std::unordered_set<std::string> dns_set;
        auto dns_items = split_to_vector(dns_list, ',');
        for (const auto& raw_dns : dns_items) {
            std::string normalized = normalize_dns(raw_dns);
            if (normalized.empty()) {
                continue;
            }
            dns_set.insert(std::move(normalized));
        }

        if (dns_set.empty()) {
            LOG(WARNING) << "Ignore tls_peer_cert_required_san_dns segment with empty dns list: "
                         << segment;
            continue;
        }

        auto& existing = result.allowed[protocol];
        existing.insert(dns_set.begin(), dns_set.end());
    }

    return result;
}

bool TlsSanDnsGate::is_protocol_enabled(const std::string& protocol) {
    const auto& parsed = get_cached_config();
    auto it = parsed.allowed.find(protocol);
    return it != parsed.allowed.end() && !it->second.empty();
}

const std::unordered_set<std::string>* TlsSanDnsGate::get_allowed_dns(const std::string& protocol) {
    const auto& parsed = get_cached_config();
    auto it = parsed.allowed.find(protocol);
    if (it == parsed.allowed.end() || it->second.empty()) {
        return nullptr;
    }
    return &it->second;
}

std::vector<std::string> TlsSanDnsGate::extract_dns_sans(X509* cert) {
    std::vector<std::string> dns_sans;
    if (cert == nullptr) {
        return dns_sans;
    }

    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names == nullptr) {
        return dns_sans;
    }

    const int count = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < count; ++i) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
        if (name == nullptr || name->type != GEN_DNS) {
            continue;
        }
        const ASN1_STRING* asn1 = name->d.dNSName;
        if (asn1 == nullptr) {
            continue;
        }
        const unsigned char* data = ASN1_STRING_get0_data(asn1);
        const int length = ASN1_STRING_length(asn1);
        if (data == nullptr || length <= 0) {
            continue;
        }
        if (memchr(data, '\0', length) != nullptr) {
            continue;
        }
        std::string dns(reinterpret_cast<const char*>(data), length);
        std::string normalized = normalize_dns(dns);
        if (!normalized.empty()) {
            dns_sans.push_back(std::move(normalized));
        }
    }

    GENERAL_NAMES_free(names);
    return dns_sans;
}

bool TlsSanDnsGate::matches_allowlist(const std::unordered_set<std::string>& allowlist,
                                      const std::vector<std::string>& dns_sans) {
    if (allowlist.empty() || dns_sans.empty()) {
        return false;
    }
    return std::ranges::any_of(dns_sans,
                               [&allowlist](const auto& dns) { return allowlist.contains(dns); });
}

std::string TlsSanDnsGate::normalize_dns(std::string dns) {
    std::string value = trim(dns);
    if (value.empty()) {
        return value;
    }
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!value.empty() && value.back() == '.') {
        value.pop_back();
    }
    return value;
}

std::string TlsSanDnsGate::format_allowlist(const std::unordered_set<std::string>& allowlist,
                                            size_t max_items) {
    if (allowlist.empty()) {
        return "[]";
    }
    std::ostringstream oss;
    oss << "[";
    size_t count = 0;
    for (const auto& item : allowlist) {
        if (count++ > 0) {
            oss << ", ";
        }
        if (count > max_items) {
            oss << "...";
            break;
        }
        oss << item;
    }
    oss << "]";
    return oss.str();
}

std::string TlsSanDnsGate::format_dns_sans(const std::vector<std::string>& dns_sans,
                                           size_t max_items) {
    if (dns_sans.empty()) {
        return "[]";
    }
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < dns_sans.size(); ++i) {
        if (i > 0) {
            oss << ", ";
        }
        if (i >= max_items) {
            oss << "...";
            break;
        }
        oss << dns_sans[i];
    }
    oss << "]";
    return oss.str();
}

} // namespace doris
