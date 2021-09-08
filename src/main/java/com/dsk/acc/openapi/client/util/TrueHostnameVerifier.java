package com.dsk.acc.openapi.client.util;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class TrueHostnameVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String s, SSLSession sslSession) {
        return true;
    }
}
