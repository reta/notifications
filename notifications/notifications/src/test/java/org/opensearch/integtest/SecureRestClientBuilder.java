/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.integtest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.ConfigConstants;

/**
 * Provides builder to create low-level and high-level REST client to make calls to OpenSearch.
 *
 * Sample usage:
 *      SecureRestClientBuilder builder = new SecureRestClientBuilder(settings).build()
 *      RestClient restClient = builder.build();
 *
 * Other usage:
 *  RestClient restClient = new SecureRestClientBuilder("localhost", 9200, false)
 *                     .setUserPassword("admin", "admin")
 *                     .build();
 *
 *
 * If https is enabled, creates RestClientBuilder using self-signed certificates or passed pem
 * as trusted.
 *
 * If https is not enabled, creates a http based client.
 */
public class SecureRestClientBuilder {

    private final boolean httpSSLEnabled;
    private final String user;
    private final String passwd;
    private final ArrayList<HttpHost> hosts = new ArrayList<>();

    private int defaultConnectTimeOutMSecs = 5000;
    private int defaultSoTimeoutMSecs = 10000;
    private int defaultConnRequestTimeoutMSecs = 3 * 60 * 1000; /* 3 minutes */

    /**
     * ONLY for integration tests.
     * @param host
     * @param port
     * @param httpSSLEnabled
     * @param user
     * @param passWord
     */
    public SecureRestClientBuilder(
        final String host,
        final int port,
        final boolean httpSSLEnabled,
        final String user,
        final String passWord
    ) {
        if (Strings.isNullOrEmpty(user) || Strings.isNullOrEmpty(passWord)) {
            throw new IllegalArgumentException("Invalid user or password");
        }

        this.httpSSLEnabled = httpSSLEnabled;
        this.user = user;
        this.passwd = passWord;
        hosts.add(new HttpHost(httpSSLEnabled ? ConfigConstants.HTTPS : ConfigConstants.HTTP, host, port));
    }

    /**
     * ONLY for integration tests.
     * @param httpHosts
     * @param httpSSLEnabled
     * @param user
     * @param passWord
     */
    public SecureRestClientBuilder(HttpHost[] httpHosts, final boolean httpSSLEnabled, final String user, final String passWord) {

        if (Strings.isNullOrEmpty(user) || Strings.isNullOrEmpty(passWord)) {
            throw new IllegalArgumentException("Invalid user or password");
        }

        this.httpSSLEnabled = httpSSLEnabled;
        this.user = user;
        this.passwd = passWord;
        hosts.addAll(Arrays.asList(httpHosts));
    }

    /**
     * Creates a low-level Rest client.
     * @return
     * @throws IOException
     */
    public RestClient build() throws IOException {
        return createRestClientBuilder().build();
    }

    public SecureRestClientBuilder setConnectTimeout(int timeout) {
        this.defaultConnectTimeOutMSecs = timeout;
        return this;
    }

    public SecureRestClientBuilder setSocketTimeout(int timeout) {
        this.defaultSoTimeoutMSecs = timeout;
        return this;
    }

    public SecureRestClientBuilder setConnectionRequestTimeout(int timeout) {
        this.defaultConnRequestTimeoutMSecs = timeout;
        return this;
    }

    private RestClientBuilder createRestClientBuilder() throws IOException {
        RestClientBuilder builder = RestClient.builder(hosts.toArray(new HttpHost[hosts.size()]));

        builder.setRequestConfigCallback(new RestClientBuilder.RequestConfigCallback() {
            @Override
            public RequestConfig.Builder customizeRequestConfig(RequestConfig.Builder requestConfigBuilder) {
                return requestConfigBuilder
                    .setConnectTimeout(Timeout.ofMilliseconds(defaultConnectTimeOutMSecs))
                    .setResponseTimeout(Timeout.ofMilliseconds(defaultSoTimeoutMSecs))
                    .setConnectionRequestTimeout(Timeout.ofMilliseconds(defaultConnRequestTimeoutMSecs));
            }
        });

        final SSLContext sslContext;
        try {
            sslContext = createSSLContext();
        } catch (GeneralSecurityException | IOException ex) {
            throw new IOException(ex);
        }
        final CredentialsProvider credentialsProvider = createCredsProvider();
        builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
            @Override
            public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                if (sslContext != null) {
                    TlsStrategy tlsStrategy = ClientTlsStrategyBuilder
                        .create()
                        .setSslContext(sslContext)
                        // See please https://issues.apache.org/jira/browse/HTTPCLIENT-2219
                        .setTlsDetailsFactory(new Factory<SSLEngine, TlsDetails>() {
                            @Override
                            public TlsDetails create(final SSLEngine sslEngine) {
                                return new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol());
                            }
                        })
                        .build();
                    PoolingAsyncClientConnectionManager connectionManager = PoolingAsyncClientConnectionManagerBuilder
                        .create()
                        .setTlsStrategy(tlsStrategy)
                        .build();
                    httpClientBuilder.setConnectionManager(connectionManager);
                }
                if (credentialsProvider != null) {
                    httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                }
                return httpClientBuilder;
            }
        });
        return builder;
    }

    private SSLContext createSSLContext() throws IOException, GeneralSecurityException {
        SSLContextBuilder builder = new SSLContextBuilder();
        if (httpSSLEnabled) {
             builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
        }
        return builder.build();
    }

    private CredentialsProvider createCredsProvider() {
        if (Strings.isNullOrEmpty(user) || Strings.isNullOrEmpty(passwd))
            return null;

        final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(user, passwd.toCharArray()));
        return credentialsProvider;
    }
}
