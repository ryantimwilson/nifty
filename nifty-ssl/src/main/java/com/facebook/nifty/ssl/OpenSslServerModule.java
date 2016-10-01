/*
 * Copyright (C) 2012-2016 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.nifty.ssl;

import com.google.inject.AbstractModule;
import io.airlift.configuration.Config;
import io.airlift.units.Duration;
import org.apache.tomcat.jni.SessionTicketKey;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class OpenSslServerModule extends AbstractModule {
    private boolean allowPlaintext = true;
    private long pollingFileInterval = 0;
    private File certFile = null;
    private File keyFile = null;
    private File ticketSeedFile = null;
    private File clientCAFile = null;
    private OpenSslServerConfiguration.SSLVerification sslVerification =
            OpenSslServerConfiguration.SSLVerification.VERIFY_OPTIONAL;

    @Override
    protected void configure() {
        if (bindSslServerConfiguration()) {
            OpenSslServerConfiguration.Builder builder =
                    OpenSslServerConfiguration.newBuilder()
                            .allowPlaintext(allowPlaintext)
                            .certFile(certFile)
                            .keyFile(keyFile)
                            .sslVerification(sslVerification);
            if (ticketSeedFile != null) {
                try {
                    List<SessionTicketKey> ticketKeysList =
                            new TicketSeedFileParser().parse(ticketSeedFile);
                    SessionTicketKey[] ticketKeys =
                            ticketKeysList.toArray(new SessionTicketKey[ticketKeysList.size()]);
                    builder.ticketKeys(ticketKeys);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            if (clientCAFile != null) {
                builder.clientCAFile(clientCAFile);
            }
            SslServerConfiguration sslServerConfiguration = builder.build();
            bind(SslServerConfiguration.class).toInstance(sslServerConfiguration);
        }
        if (bindTransportAttachObserver()) {
            PollingMultiFileWatcher fileWatcher = new PollingMultiFileWatcher(
                    new Duration(0, TimeUnit.MILLISECONDS),
                    new Duration(pollingFileInterval, TimeUnit.MILLISECONDS));
            TransportAttachObserver transportAttachObserver = new SslConfigFileWatcher(
                    ticketSeedFile,
                    keyFile,
                    certFile,
                    null,
                    fileWatcher);
            bind(TransportAttachObserver.class).toInstance(transportAttachObserver);
        }
    }

    private boolean bindSslServerConfiguration() {
        return certFile != null && keyFile != null;
    }

    private boolean bindTransportAttachObserver() {
        return bindSslServerConfiguration() && ticketSeedFile != null && pollingFileInterval > 0;
    }

    @Config("thrift.allow_plaintext")
    public void setAllowPlaintext(boolean allowPlaintext) {
        this.allowPlaintext = allowPlaintext;
    }

    @Config("thrift.polling_file_interval")
    public void setPollingFileInterval(long pollingFileInterval) {
        this.pollingFileInterval = pollingFileInterval;
    }

    @Config("thrift.cert")
    public void setCertFile(String certFile) {
        this.certFile = new File(certFile);
    }

    @Config("thrift.key")
    public void setKeyFile(String keyFile) {
        this.keyFile = new File(keyFile);
    }

    @Config("thrift.ticket_seed_file")
    public void setTicketSeedFile(String ticketSeedFile) {
        this.ticketSeedFile = new File(ticketSeedFile);
    }

    @Config("thrift.ca_file")
    public void setClientCAFile(String clientCAFile) {
        this.clientCAFile = new File(clientCAFile);
    }

    @Config("thrift.ssl_verification")
    public void setSslVerification(OpenSslServerConfiguration.SSLVerification sslVerification) {
        this.sslVerification = sslVerification;
    }
}