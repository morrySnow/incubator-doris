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

#include "service/brpc_service.h"

#include <brpc/server.h>
#include <brpc/ssl_options.h>
#include <butil/endpoint.h>
#include <fmt/format.h>
// IWYU pragma: no_include <bthread/errno.h>
#include <errno.h> // IWYU pragma: keep
#include <gflags/gflags_declare.h>
#include <openssl/x509_vfy.h>
#include <string.h>

#include <memory>
#include <ostream>

#include "cloud/cloud_internal_service.h"
#include "cloud/config.h"
#include "common/certificate_manager.h"
#include "common/config.h"
#include "common/logging.h"
#include "common/tls_san_dns_gate.h"
#include "olap/storage_engine.h"
#include "runtime/exec_env.h"
#include "service/backend_options.h"
#include "service/internal_service.h"
#include "util/mem_info.h"

namespace brpc {

DECLARE_uint64(max_body_size);
DECLARE_int64(socket_max_unwritten_bytes);
DECLARE_bool(usercode_in_pthread);

} // namespace brpc

namespace doris {

namespace {

bool verify_peer_cert_chain(X509_STORE_CTX* ctx) {
    if (ctx == nullptr) {
        return false;
    }

    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    if (cert == nullptr || config::tls_ca_certificate_path.empty()) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return false;
    }

    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> ca_store(X509_STORE_new(),
                                                                     X509_STORE_free);
    if (!ca_store ||
        X509_STORE_load_locations(ca_store.get(), config::tls_ca_certificate_path.c_str(),
                                  nullptr) != 1) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return false;
    }

    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> verify_ctx(X509_STORE_CTX_new(),
                                                                               X509_STORE_CTX_free);
    if (!verify_ctx || X509_STORE_CTX_init(verify_ctx.get(), ca_store.get(), cert,
                                           X509_STORE_CTX_get0_untrusted(ctx)) != 1) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return false;
    }

    if (X509_verify_cert(verify_ctx.get()) != 1) {
        int err = X509_STORE_CTX_get_error(verify_ctx.get());
        if (err == X509_V_OK) {
            err = X509_V_ERR_APPLICATION_VERIFICATION;
        }
        X509_STORE_CTX_set_error(ctx, err);
        return false;
    }

    return true;
}

int tls_san_dns_verify_callback(int preverify_ok, X509_STORE_CTX* ctx, void* userdata) {
    if (preverify_ok == 0) {
        return 0;
    }

    if (X509_STORE_CTX_get_error_depth(ctx) != 0) {
        return 1;
    }

    const char* protocol = static_cast<const char*>(userdata);
    if (protocol == nullptr) {
        protocol = TlsSanDnsGate::kProtocolBrpc;
    }

    const auto* allowlist = TlsSanDnsGate::get_allowed_dns(protocol);
    if (allowlist == nullptr) {
        return 1;
    }

    if (!verify_peer_cert_chain(ctx)) {
        return 0;
    }

    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    auto dns_sans = TlsSanDnsGate::extract_dns_sans(cert);
    if (!TlsSanDnsGate::matches_allowlist(*allowlist, dns_sans)) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        LOG(WARNING) << "TLS SAN DNS gate reject peer certificate."
                     << " protocol=" << protocol
                     << " allowlist=" << TlsSanDnsGate::format_allowlist(*allowlist)
                     << " peer_dns=" << TlsSanDnsGate::format_dns_sans(dns_sans);
        return 0;
    }

    return 1;
}

} // namespace

BRpcService::BRpcService(ExecEnv* exec_env) : _exec_env(exec_env), _server(new brpc::Server()) {
    // Set config
    if (config::brpc_usercode_in_pthread) {
        brpc::FLAGS_usercode_in_pthread = true;
    }
    brpc::FLAGS_max_body_size = config::brpc_max_body_size;
    brpc::FLAGS_socket_max_unwritten_bytes =
            config::brpc_socket_max_unwritten_bytes != -1
                    ? config::brpc_socket_max_unwritten_bytes
                    : std::max((int64_t)1073741824, (MemInfo::mem_limit() / 1024) * 20);
}

BRpcService::~BRpcService() {
    join();
}

Status BRpcService::start(int port, int num_threads) {
    // Add service
    if (config::is_cloud_mode()) {
        _server->AddService(
                new CloudInternalServiceImpl(_exec_env->storage_engine().to_cloud(), _exec_env),
                brpc::SERVER_OWNS_SERVICE);
    } else {
        _server->AddService(
                new PInternalServiceImpl(_exec_env->storage_engine().to_local(), _exec_env),
                brpc::SERVER_OWNS_SERVICE);
    }
    // start service
    brpc::ServerOptions options;
    if (num_threads != -1) {
        options.num_threads = num_threads;
    }
    options.idle_timeout_sec = config::brpc_idle_timeout_sec;

    const bool brpc_gate_configured =
            TlsSanDnsGate::is_protocol_enabled(TlsSanDnsGate::kProtocolBrpc);
    const bool brpc_gate_enabled =
            brpc_gate_configured &&
            config::tls_verify_mode == CertificateManager::verify_fail_if_no_peer_cert;
    if (brpc_gate_configured) {
        if (!config::enable_tls ||
            !CertificateManager::is_protocol_included(CertificateManager::Protocol::brpc)) {
            std::string msg =
                    "tls_peer_cert_required_san_dns enables brpc gate, but TLS is "
                    "disabled/excluded; please set enable_tls=true and ensure "
                    "tls_excluded_protocols does not contain brpc";
            LOG(ERROR) << msg << ", enable_tls=" << config::enable_tls
                       << ", tls_excluded_protocols=" << config::tls_excluded_protocols;
            return Status::InternalError(msg);
        }
        if (config::tls_ca_certificate_path.empty()) {
            std::string msg =
                    "tls_peer_cert_required_san_dns enables brpc gate, but "
                    "tls_ca_certificate_path is empty; please set "
                    "tls_ca_certificate_path=/path/to/ca.crt";
            LOG(ERROR) << msg;
            return Status::InternalError(msg);
        }
        if (!brpc_gate_enabled) {
            std::string msg =
                    "tls_peer_cert_required_san_dns configures brpc SAN gate, but "
                    "tls_verify_mode is not verify_fail_if_no_peer_cert; please set "
                    "tls_verify_mode=verify_fail_if_no_peer_cert";
            LOG(ERROR) << msg << ", current_mode=" << config::tls_verify_mode;
            return Status::InternalError(msg);
        }
    }

    if (config::enable_tls &&
        CertificateManager::is_protocol_included(CertificateManager::Protocol::brpc)) {
        options.mutable_ssl_options()->default_cert.certificate = config::tls_certificate_path;
        options.mutable_ssl_options()->default_cert.private_key = config::tls_private_key_path;
        options.mutable_ssl_options()->default_cert.private_key_passwd =
                config::tls_private_key_password;
        options.mutable_ssl_options()->enable_certificate_reload = true;
        options.mutable_ssl_options()->certificate_reload_interval_s =
                config::tls_cert_refresh_interval_seconds;
        if (brpc_gate_enabled) {
            options.mutable_ssl_options()->verify.verify_depth = 2;
            options.mutable_ssl_options()->verify.verify_callback = tls_san_dns_verify_callback;
            options.mutable_ssl_options()->verify.verify_userdata =
                    const_cast<char*>(TlsSanDnsGate::kProtocolBrpc);
        } else if (config::tls_verify_mode == CertificateManager::verify_fail_if_no_peer_cert) {
            options.mutable_ssl_options()->verify.verify_depth = 2;
        } else if (config::tls_verify_mode == CertificateManager::verify_peer) {
            // Relax the certificate restrictions for verify_peer
            // nothing
        } else if (config::tls_verify_mode == CertificateManager::verify_none) {
            // nothing
        } else {
            std::string msg = fmt::format(
                    "unknown verify_mode: {}, only support: verify_fail_if_no_peer_cert, "
                    "verify_peer, verify_none",
                    config::tls_verify_mode);
            LOG(WARNING) << msg;
            return Status::InternalError(msg);
        }
        options.mutable_ssl_options()->verify.ca_file_path = config::tls_ca_certificate_path;
        options.mutable_ssl_options()->alpns = "h2";
        options.force_ssl = true;
    } else if (config::enable_https) {
        auto* sslOptions = options.mutable_ssl_options();
        sslOptions->default_cert.certificate = config::ssl_certificate_path;
        sslOptions->default_cert.private_key = config::ssl_private_key_path;
    }

    options.has_builtin_services = config::enable_brpc_builtin_services;

    butil::EndPoint point;
    if (butil::str2endpoint(BackendOptions::get_service_bind_address(), port, &point) < 0) {
        return Status::InternalError("convert address failed, host={}, port={}", "[::0]", port);
    }
    LOG(INFO) << "BRPC server bind to host: " << BackendOptions::get_service_bind_address()
              << ", port: " << port;
    if (_server->Start(point, &options) != 0) {
        char buf[64];
        LOG(WARNING) << "start brpc failed, errno=" << errno
                     << ", errmsg=" << strerror_r(errno, buf, 64) << ", port=" << port;
        return Status::InternalError("start brpc service failed");
    }
    return Status::OK();
}

void BRpcService::join() {
    int stop_succeed = _server->Stop(1000);

    if (stop_succeed == 0) {
        _server->Join();
    } else {
        LOG(WARNING) << "Failed to stop brpc service, "
                     << "not calling brpc server join since it will never retrun."
                     << "maybe something bad will happen, let us know if you meet something error.";
    }

    _server->ClearServices();
}

} // namespace doris
