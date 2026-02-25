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

#pragma once

#include <openssl/x509.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace doris::cloud {

class TlsSanDnsGate {
public:
    static constexpr const char* kProtocolBrpc = "brpc";

    struct ParsedConfig {
        std::unordered_map<std::string, std::unordered_set<std::string>> allowed;
    };

    static ParsedConfig parse_config(const std::string& value);

    static bool is_protocol_enabled(const std::string& protocol);
    static const std::unordered_set<std::string>* get_allowed_dns(const std::string& protocol);

    static std::vector<std::string> extract_dns_sans(X509* cert);
    static bool matches_allowlist(const std::unordered_set<std::string>& allowlist,
                                  const std::vector<std::string>& dns_sans);

    static std::string normalize_dns(std::string dns);
    static std::string format_allowlist(const std::unordered_set<std::string>& allowlist,
                                        size_t max_items = 10);
    static std::string format_dns_sans(const std::vector<std::string>& dns_sans,
                                       size_t max_items = 10);
};

int tls_san_dns_verify_callback(int preverify_ok, X509_STORE_CTX* store_ctx, void* userdata);

} // namespace doris::cloud
