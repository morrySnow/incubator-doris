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

package org.apache.doris.common;

import org.apache.doris.common.util.TlsSanDnsGate;

import org.apache.thrift.TException;
import org.apache.thrift.TProcessor;
import org.apache.thrift.protocol.TProtocol;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class ThriftServerTlsSanDnsGateTest {

    @Test
    public void testGateEnabledWithoutTlsFailsFast() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldType = Config.thrift_server_type;
        try {
            Config.enable_tls = false;
            Config.tls_excluded_protocols = "";
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Config.tls_ca_certificate_path = "";
            Config.thrift_server_type = ThriftServer.SIMPLE;

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            invokeCreateSimpleServer(server);
            Assert.fail("Expected RuntimeException for TLS disabled with gate enabled");
        } catch (InvocationTargetException ex) {
            Assert.assertTrue(ex.getCause() instanceof RuntimeException);
            Assert.assertTrue(ex.getCause().getMessage().contains("enable_tls=true"));
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.thrift_server_type = oldType;
        }
    }

    @Test
    public void testGateEnabledWithoutCaFailsFast() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldType = Config.thrift_server_type;
        try {
            Config.enable_tls = true;
            Config.tls_excluded_protocols = "";
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Config.tls_ca_certificate_path = "";
            Config.thrift_server_type = ThriftServer.SIMPLE;

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            invokeCreateSimpleServer(server);
            Assert.fail("Expected RuntimeException for empty CA path with gate enabled");
        } catch (InvocationTargetException ex) {
            Assert.assertTrue(ex.getCause() instanceof RuntimeException);
            Assert.assertTrue(ex.getCause().getMessage().contains("tls_ca_certificate_path=/path/to/ca.crt"));
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.thrift_server_type = oldType;
        }
    }

    @Test
    public void testGateEnabledWithProtocolExcludedFailsFast() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldVerifyMode = Config.tls_verify_mode;
        String oldType = Config.thrift_server_type;
        try {
            Config.enable_tls = true;
            Config.tls_excluded_protocols = "thrift";
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Config.tls_ca_certificate_path = "/tmp/mock-ca.crt";
            Config.tls_verify_mode = "verify_fail_if_no_peer_cert";
            Config.thrift_server_type = ThriftServer.SIMPLE;

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            invokeCreateSimpleServer(server);
            Assert.fail("Expected RuntimeException when thrift is excluded under SAN gate");
        } catch (InvocationTargetException ex) {
            Assert.assertTrue(ex.getCause() instanceof RuntimeException);
            Assert.assertTrue(ex.getCause().getMessage().contains("tls_excluded_protocols"));
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.tls_verify_mode = oldVerifyMode;
            Config.thrift_server_type = oldType;
        }
    }

    @Test
    public void testValidateGatePassesWhenConfigCompatible() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldVerifyMode = Config.tls_verify_mode;
        try {
            Config.enable_tls = true;
            Config.tls_excluded_protocols = "";
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Config.tls_ca_certificate_path = "/tmp/mock-ca.crt";
            Config.tls_verify_mode = "verify_fail_if_no_peer_cert";

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            invokeValidateTlsSanDnsGate(server, true);
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.tls_verify_mode = oldVerifyMode;
        }
    }

    @Test
    public void testGateDisabledSkipsValidation() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldVerifyMode = Config.tls_verify_mode;
        try {
            Config.enable_tls = false;
            Config.tls_excluded_protocols = "thrift";
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Config.tls_ca_certificate_path = "";
            Config.tls_verify_mode = "verify_none";

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            invokeValidateTlsSanDnsGate(server, false);
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.tls_verify_mode = oldVerifyMode;
        }
    }

    @Test
    public void testGateEnabledWithoutRequiredVerifyModeFailsFast() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldVerifyMode = Config.tls_verify_mode;
        String oldType = Config.thrift_server_type;
        try {
            Config.enable_tls = true;
            Config.tls_excluded_protocols = "";
            Config.tls_peer_cert_required_san_dns = "thrift=internal.com";
            Config.tls_ca_certificate_path = "/tmp/mock-ca.crt";
            Config.tls_verify_mode = "verify_peer";
            Config.thrift_server_type = ThriftServer.SIMPLE;

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            invokeCreateSimpleServer(server);
            Assert.fail("Expected RuntimeException when verify mode is not verify_fail_if_no_peer_cert");
        } catch (InvocationTargetException ex) {
            Assert.assertTrue(ex.getCause() instanceof RuntimeException);
            Assert.assertTrue(ex.getCause().getMessage().contains("verify_fail_if_no_peer_cert"));
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.tls_verify_mode = oldVerifyMode;
            Config.thrift_server_type = oldType;
        }
    }

    @Test
    public void testBrpcOnlyGateConfigDoesNotAffectThriftValidation() throws Exception {
        boolean oldEnableTls = Config.enable_tls;
        String oldExcluded = Config.tls_excluded_protocols;
        String oldGate = Config.tls_peer_cert_required_san_dns;
        String oldCa = Config.tls_ca_certificate_path;
        String oldVerifyMode = Config.tls_verify_mode;
        try {
            Config.enable_tls = false;
            Config.tls_excluded_protocols = "thrift";
            Config.tls_peer_cert_required_san_dns = "brpc=internal.com";
            Config.tls_ca_certificate_path = "";
            Config.tls_verify_mode = "verify_none";

            ThriftServer server = new ThriftServer(0, new NoopProcessor());
            boolean thriftGateEnabled = TlsSanDnsGate.isProtocolEnabled(TlsSanDnsGate.PROTOCOL_THRIFT);
            Assert.assertFalse(thriftGateEnabled);
            invokeValidateTlsSanDnsGate(server, thriftGateEnabled);
        } finally {
            Config.enable_tls = oldEnableTls;
            Config.tls_excluded_protocols = oldExcluded;
            Config.tls_peer_cert_required_san_dns = oldGate;
            Config.tls_ca_certificate_path = oldCa;
            Config.tls_verify_mode = oldVerifyMode;
        }
    }

    private void invokeCreateSimpleServer(ThriftServer server) throws Exception {
        Method method = ThriftServer.class.getDeclaredMethod("createSimpleServer");
        method.setAccessible(true);
        method.invoke(server);
    }

    private void invokeValidateTlsSanDnsGate(ThriftServer server, boolean gateEnabled) throws Exception {
        Method method = ThriftServer.class.getDeclaredMethod("validateTlsSanDnsGate", boolean.class);
        method.setAccessible(true);
        method.invoke(server, gateEnabled);
    }

    private static class NoopProcessor implements TProcessor {
        @Override
        public void process(TProtocol in, TProtocol out) throws TException {
        }
    }
}
