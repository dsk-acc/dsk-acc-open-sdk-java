package com.dsk.acc.openapi.client.util.okhttp;


import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.dsk.acc.openapi.client.exception.AccException;
import com.dsk.acc.openapi.client.util.TrueHostnameVerifier;
import com.dsk.acc.openapi.client.util.X509TrustManagerImp;

import okhttp3.Authenticator;
import okhttp3.ConnectionPool;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

public class OkHttpClientBuilder {
    private OkHttpClient.Builder builder;

    public OkHttpClientBuilder() {
        builder = new OkHttpClient().newBuilder();
    }

    public OkHttpClientBuilder connectTimeout(Map<String, Object> map) {
        Object object = map.get("connectTimeout");
        long timeout;
        try {
            timeout = Long.parseLong(String.valueOf(object));
        } catch (Exception e) {
            return this;
        }
        this.builder.connectTimeout(timeout, TimeUnit.MILLISECONDS);
        return this;
    }

    public OkHttpClientBuilder readTimeout(Map<String, Object> map) {
        Object object = map.get("readTimeout");
        long timeout;
        try {
            timeout = Long.parseLong(String.valueOf(object));
        } catch (Exception e) {
            return this;
        }
        this.builder.readTimeout(timeout, TimeUnit.MILLISECONDS);
        return this;
    }

    public OkHttpClientBuilder connectionPool(Map<String, Object> map) {
        Object maxIdleConns = map.get("maxIdleConns");
        int maxIdleConnections;
        try {
            maxIdleConnections = Integer.parseInt(String.valueOf(maxIdleConns));
        } catch (Exception e) {
            maxIdleConnections = 5;
        }
        ConnectionPool connectionPool = new ConnectionPool(maxIdleConnections, 10000L, TimeUnit.MILLISECONDS);
        this.builder.connectionPool(connectionPool);
        return this;
    }

    public OkHttpClientBuilder certificate(Map<String, Object> map) {
        try {
            if (Boolean.parseBoolean(String.valueOf(map.get("ignoreSSL")))) {
                X509TrustManager compositeX509TrustManager = new X509TrustManagerImp();
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{compositeX509TrustManager}, new java.security.SecureRandom());
                this.builder.sslSocketFactory(sslContext.getSocketFactory(), compositeX509TrustManager).
                        hostnameVerifier(new TrueHostnameVerifier());
            }
            return this;
        } catch (Exception e) {
            throw new AccException(e.getMessage(), e);
        }

    }

    public OkHttpClientBuilder proxy(Map<String, Object> map) {
        try {
            if (null != map.get("httpProxy") || null != map.get("httpsProxy")) {
                Object urlString = null == map.get("httpProxy") ? map.get("httpsProxy") : map.get("httpProxy");
                URL url = new URL(String.valueOf(urlString));
                this.builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(url.getHost(), url.getPort())));
            }
            return this;
        } catch (Exception e) {
            throw new AccException(e.getMessage(), e);
        }

    }

    public OkHttpClientBuilder proxyAuthenticator(Map<String, Object> map) {
        try {
            Object httpsProxy = map.get("httpsProxy");
            if (httpsProxy != null) {
                URL proxyUrl = new URL(String.valueOf(httpsProxy));
                String userInfo = proxyUrl.getUserInfo();
                if (null != userInfo) {
                    String[] userMessage = userInfo.split(":");
                    final String credential = Credentials.basic(userMessage[0], userMessage[1]);
                    Authenticator authenticator = new Authenticator() {
                        @Override
                        public Request authenticate(Route route, Response response) throws IOException {
                            return response.request().newBuilder()
                                    .header("Proxy-Authorization", credential)
                                    .build();
                        }
                    };
                    this.builder.proxyAuthenticator(authenticator);
                }
            }
            return this;
        } catch (Exception e) {
            throw new AccException(e.getMessage(), e);
        }
    }

    public OkHttpClient buildOkHttpClient() {
        return this.builder.build();
    }
}
