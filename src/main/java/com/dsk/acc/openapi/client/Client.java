package com.dsk.acc.openapi.client;

import java.util.Map;

import com.dsk.acc.openapi.client.bean.OpenApiRequest;
import com.dsk.acc.openapi.client.bean.Params;
import com.dsk.acc.openapi.client.bean.RuntimeOptions;
import com.dsk.acc.openapi.client.core.Acc;
import com.dsk.acc.openapi.client.core.AccConverter;
import com.dsk.acc.openapi.client.core.AccModel;
import com.dsk.acc.openapi.client.core.AccPair;
import com.dsk.acc.openapi.client.core.AccRequest;
import com.dsk.acc.openapi.client.core.AccResponse;
import com.dsk.acc.openapi.client.exception.AccException;
import com.dsk.acc.openapi.client.exception.AccUnretryableException;
import com.dsk.acc.openapi.client.util.ClientUtil;
import com.dsk.acc.openapi.client.util.CommonUtils;


public class Client {

    public String _endpoint;
    public String _regionId;
    public String _protocol;
    public String _userAgent;
    public String _endpointRule;
    public Map<String, String> _endpointMap;
    public Integer _readTimeout;
    public Integer _connectTimeout;
    public String _network;
    public Integer _maxIdleConns;
    public String _signatureAlgorithm;
    public Map<String, String> _headers;

    public String _accessKeyId;
    public String _accessKeySecret;
    public String _securityToken;
    
    public Client(Config config) throws Exception {
        if (CommonUtils.isUnset(AccModel.buildMap(config))) {
            throw new AccException(AccConverter.buildMap(
                new AccPair("code", "ParameterMissing"),
                new AccPair("message", "'config' can not be unset")
            ));
        }
        this._accessKeyId = config.accessKeyId;
        this._accessKeySecret = config.accessKeySecret;
        this._securityToken = config.securityToken;

        this._endpoint = CommonUtils.defaultString(config.endpoint, "import.jiansheku.com");
        this._protocol = config.protocol;
        this._regionId = config.regionId;
        this._userAgent = config.userAgent;
        this._readTimeout = config.readTimeout;
        this._connectTimeout = config.connectTimeout;
        this._maxIdleConns = config.maxIdleConns;
    }

    public Map<String, ?> doRPCRequest(String action, String version, String protocol, String method, String authType, String bodyType, OpenApiRequest request, RuntimeOptions runtime) throws Exception {
        AccModel.validateParams(request, "request");
        Map<String, Object> runtime_ = AccConverter.buildMap(
            new AccPair("timeouted", "retry"),
            new AccPair("readTimeout", CommonUtils.defaultNumber(runtime.readTimeout, _readTimeout)),
            new AccPair("connectTimeout", CommonUtils.defaultNumber(runtime.connectTimeout, _connectTimeout)),
            new AccPair("maxIdleConns", CommonUtils.defaultNumber(runtime.maxIdleConns, _maxIdleConns)),
            new AccPair("retry", AccConverter.buildMap(
                new AccPair("retryable", runtime.autoretry),
                new AccPair("maxAttempts", CommonUtils.defaultNumber(runtime.maxAttempts, 3))
            )),
            new AccPair("ignoreSSL", runtime.ignoreSSL)
        );

        AccRequest _lastRequest = null;
        Exception _lastException = null;
        long _now = System.currentTimeMillis();
        int _retryTimes = 0;
        while (Acc.allowRetry((Map<String, Object>) runtime_.get("retry"), _retryTimes, _now)) {
            if (_retryTimes > 0) {
                int backoffTime = Acc.getBackoffTime(runtime_.get("backoff"), _retryTimes);
                if (backoffTime > 0) {
                    Acc.sleep(backoffTime);
                }
            }
            _retryTimes = _retryTimes + 1;
            try {
                AccRequest request_ = new AccRequest();
                request_.protocol = CommonUtils.defaultString(_protocol, protocol);
                request_.method = method;
                request_.pathname = "/";
                request_.query = AccConverter.merge(String.class,
                    AccConverter.buildMap(
                        new AccPair("Action", action),
                        new AccPair("Format", "json"),
                        new AccPair("Version", version),
                        new AccPair("Timestamp", System.currentTimeMillis()),
                        new AccPair("SignatureNonce", CommonUtils.getNonce())
                    ),
                    request.query
                );
                Map<String, String> headers = this.getRpcHeaders();
                if (CommonUtils.isUnset(headers)) {
                    // endpoint is setted in product client
                    request_.headers = AccConverter.buildMap(
                        new AccPair("host", _endpoint),
                        new AccPair("x-acc-version", version),
                        new AccPair("x-acc-action", action),
                        new AccPair("user-agent", this.getUserAgent())
                    );
                } else {
                    request_.headers = AccConverter.merge(String.class,
                        AccConverter.buildMap(
                            new AccPair("host", _endpoint),
                            new AccPair("x-acc-version", version),
                            new AccPair("x-acc-action", action),
                            new AccPair("user-agent", this.getUserAgent())
                        ),
                        headers
                    );
                }

                if (!CommonUtils.isUnset(request.body)) {
                    Map<String, Object> m = CommonUtils.assertAsMap(request.body);
                    Map<String, Object> tmp = CommonUtils.anyifyMapValue(ClientUtil.query(m));
                    request_.body = Acc.toReadable(CommonUtils.toFormString(tmp));
                    request_.headers.put("content-type", "application/x-www-form-urlencoded");
                }

                if (!CommonUtils.equalString(authType, "Anonymous")) {
                    String accessKeyId = this.getAccessKeyId();
                    String accessKeySecret = this.getAccessKeySecret();
                    String securityToken = this.getSecurityToken();
                    if (!CommonUtils.empty(securityToken)) {
                        request_.query.put("SecurityToken", securityToken);
                    }

                    request_.query.put("SignatureMethod", "HMAC-SHA1");
                    request_.query.put("SignatureVersion", "1.0");
                    request_.query.put("AccessKeyId", accessKeyId);
                    Map<String, Object> t = null;
                    if (!CommonUtils.isUnset(request.body)) {
                        t = CommonUtils.assertAsMap(request.body);
                    }

                    Map<String, String> signedParam = AccConverter.merge(String.class,
                        request_.query,
                        ClientUtil.query(t)
                    );
                    request_.query.put("Signature", ClientUtil.getRPCSignature(signedParam, request_.method, accessKeySecret));
                }

                _lastRequest = request_;
                AccResponse response_ = Acc.doAction(request_, runtime_);

                if (CommonUtils.is4xx(response_.statusCode) || CommonUtils.is5xx(response_.statusCode)) {
                    Object _res = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> err = CommonUtils.assertAsMap(_res);
                    Object requestId = Client.defaultAny(err.get("RequestId"), err.get("requestId"));
                    throw new AccException(AccConverter.buildMap(
                        new AccPair("code", "" + Client.defaultAny(err.get("code"), err.get("statusCode")) + ""),
                        new AccPair("msg", "code: " + response_.statusCode + ", " + Client.defaultAny(err.get("msg"), err.get("message")) + " request id: " + requestId + ""),
                        new AccPair("data", err)
                    ));
                }

                if (CommonUtils.equalString(bodyType, "binary")) {
                    Map<String, Object> resp = AccConverter.buildMap(
                        new AccPair("body", response_.body),
                        new AccPair("headers", response_.headers)
                    );
                    return resp;
                } else if (CommonUtils.equalString(bodyType, "byte")) {
                    byte[] byt = CommonUtils.readAsBytes(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", byt),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "string")) {
                    String str = CommonUtils.readAsString(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", str),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "json")) {
                    Object obj = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> res = CommonUtils.assertAsMap(obj);
                    return AccConverter.buildMap(
                        new AccPair("body", res),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "array")) {
                    Object arr = CommonUtils.readAsJSON(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", arr),
                        new AccPair("headers", response_.headers)
                    );
                } else {
                    return AccConverter.buildMap(
                        new AccPair("headers", response_.headers)
                    );
                }

            } catch (Exception e) {
                if (Acc.isRetryable(e)) {
                    _lastException = e;
                    continue;
                }
                throw e;
            }
        }

        throw new AccUnretryableException(_lastRequest, _lastException);
    }

    public Map<String, ?> doROARequest(String action, String version, String protocol, String method, String authType, String pathname, String bodyType, OpenApiRequest request, RuntimeOptions runtime) throws Exception {
        AccModel.validateParams(request, "request");
        Map<String, Object> runtime_ = AccConverter.buildMap(
            new AccPair("timeouted", "retry"),
            new AccPair("readTimeout", CommonUtils.defaultNumber(runtime.readTimeout, _readTimeout)),
            new AccPair("connectTimeout", CommonUtils.defaultNumber(runtime.connectTimeout, _connectTimeout)),
            new AccPair("maxIdleConns", CommonUtils.defaultNumber(runtime.maxIdleConns, _maxIdleConns)),
            new AccPair("retry", AccConverter.buildMap(
                new AccPair("retryable", runtime.autoretry),
                new AccPair("maxAttempts", CommonUtils.defaultNumber(runtime.maxAttempts, 3))
            )),
            new AccPair("ignoreSSL", runtime.ignoreSSL)
        );

        AccRequest _lastRequest = null;
        Exception _lastException = null;
        long _now = System.currentTimeMillis();
        int _retryTimes = 0;
        while (Acc.allowRetry((Map<String, Object>) runtime_.get("retry"), _retryTimes, _now)) {
            if (_retryTimes > 0) {
                int backoffTime = Acc.getBackoffTime(runtime_.get("backoff"), _retryTimes);
                if (backoffTime > 0) {
                    Acc.sleep(backoffTime);
                }
            }
            _retryTimes = _retryTimes + 1;
            try {
                AccRequest request_ = new AccRequest();
                request_.protocol = CommonUtils.defaultString(_protocol, protocol);
                request_.method = method;
                request_.pathname = pathname;
                request_.headers = AccConverter.merge(String.class,
                    AccConverter.buildMap(
                        new AccPair("date", CommonUtils.getDateUTCString()),
                        new AccPair("host", _endpoint),
                        new AccPair("accept", "application/json"),
                        new AccPair("x-acc-signature-nonce", CommonUtils.getNonce()),
                        new AccPair("x-acc-signature-method", "HMAC-SHA1"),
                        new AccPair("x-acc-signature-version", "1.0"),
                        new AccPair("x-acc-version", version),
                        new AccPair("x-acc-action", action),
                        new AccPair("user-agent", CommonUtils.getUserAgent(_userAgent))
                    ),
                    request.headers
                );
                if (!CommonUtils.isUnset(request.body)) {
                    request_.body = Acc.toReadable(CommonUtils.toJSONString(request.body));
                    request_.headers.put("content-type", "application/json; charset=utf-8");
                }

                if (!CommonUtils.isUnset(request.query)) {
                    request_.query = request.query;
                }

                if (!CommonUtils.equalString(authType, "Anonymous")) {
                    String accessKeyId = this.getAccessKeyId();
                    String accessKeySecret = this.getAccessKeySecret();
                    String securityToken = this.getSecurityToken();
                    if (!CommonUtils.empty(securityToken)) {
                        request_.headers.put("x-acc-accesskey-id", accessKeyId);
                        request_.headers.put("x-acc-security-token", securityToken);
                    }

                    String stringToSign = ClientUtil.getStringToSign(request_);
                    request_.headers.put("authorization", "acs " + accessKeyId + ":" + ClientUtil.getROASignature(stringToSign, accessKeySecret) + "");
                }

                _lastRequest = request_;
                AccResponse response_ = Acc.doAction(request_, runtime_);

                if (CommonUtils.equalNumber(response_.statusCode, 204)) {
                    return AccConverter.buildMap(
                        new AccPair("headers", response_.headers)
                    );
                }

                if (CommonUtils.is4xx(response_.statusCode) || CommonUtils.is5xx(response_.statusCode)) {
                    Object _res = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> err = CommonUtils.assertAsMap(_res);
                    Object requestId = Client.defaultAny(err.get("RequestId"), err.get("requestId"));
                    requestId = Client.defaultAny(requestId, err.get("requestid"));
                    throw new AccException(AccConverter.buildMap(
                        new AccPair("code", "" + Client.defaultAny(err.get("code"), err.get("statusCode")) + ""),
                        new AccPair("msg", "code: " + response_.statusCode + ", " + Client.defaultAny(err.get("msg"), err.get("message")) + " request id: " + requestId + ""),
                        new AccPair("data", err)
                    ));
                }

                if (CommonUtils.equalString(bodyType, "binary")) {
                    Map<String, Object> resp = AccConverter.buildMap(
                        new AccPair("body", response_.body),
                        new AccPair("headers", response_.headers)
                    );
                    return resp;
                } else if (CommonUtils.equalString(bodyType, "byte")) {
                    byte[] byt = CommonUtils.readAsBytes(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", byt),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "string")) {
                    String str = CommonUtils.readAsString(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", str),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "json")) {
                    Object obj = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> res = CommonUtils.assertAsMap(obj);
                    return AccConverter.buildMap(
                        new AccPair("body", res),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "array")) {
                    Object arr = CommonUtils.readAsJSON(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", arr),
                        new AccPair("headers", response_.headers)
                    );
                } else {
                    return AccConverter.buildMap(
                        new AccPair("headers", response_.headers)
                    );
                }

            } catch (Exception e) {
                if (Acc.isRetryable(e)) {
                    _lastException = e;
                    continue;
                }
                throw e;
            }
        }

        throw new AccUnretryableException(_lastRequest, _lastException);
    }

    public Map<String, ?> doROARequestWithForm(String action, String version, String protocol, String method, String authType, String pathname, String bodyType, OpenApiRequest request, RuntimeOptions runtime) throws Exception {
        AccModel.validateParams(request, "request");
        Map<String, Object> runtime_ = AccConverter.buildMap(
            new AccPair("timeouted", "retry"),
            new AccPair("readTimeout", CommonUtils.defaultNumber(runtime.readTimeout, _readTimeout)),
            new AccPair("connectTimeout", CommonUtils.defaultNumber(runtime.connectTimeout, _connectTimeout)),
            new AccPair("maxIdleConns", CommonUtils.defaultNumber(runtime.maxIdleConns, _maxIdleConns)),
            new AccPair("retry", AccConverter.buildMap(
                new AccPair("retryable", runtime.autoretry),
                new AccPair("maxAttempts", CommonUtils.defaultNumber(runtime.maxAttempts, 3))
            )),
            new AccPair("ignoreSSL", runtime.ignoreSSL)
        );

        AccRequest _lastRequest = null;
        Exception _lastException = null;
        long _now = System.currentTimeMillis();
        int _retryTimes = 0;
        while (Acc.allowRetry((Map<String, Object>) runtime_.get("retry"), _retryTimes, _now)) {
            if (_retryTimes > 0) {
                int backoffTime = Acc.getBackoffTime(runtime_.get("backoff"), _retryTimes);
                if (backoffTime > 0) {
                    Acc.sleep(backoffTime);
                }
            }
            _retryTimes = _retryTimes + 1;
            try {
                AccRequest request_ = new AccRequest();
                request_.protocol = CommonUtils.defaultString(_protocol, protocol);
                request_.method = method;
                request_.pathname = pathname;
                request_.headers = AccConverter.merge(String.class,
                    AccConverter.buildMap(
                        new AccPair("date", CommonUtils.getDateUTCString()),
                        new AccPair("host", _endpoint),
                        new AccPair("accept", "application/json"),
                        new AccPair("x-acc-signature-nonce", CommonUtils.getNonce()),
                        new AccPair("x-acc-signature-method", "HMAC-SHA1"),
                        new AccPair("x-acc-signature-version", "1.0"),
                        new AccPair("x-acc-version", version),
                        new AccPair("x-acc-action", action),
                        new AccPair("user-agent", CommonUtils.getUserAgent(_userAgent))
                    ),
                    request.headers
                );
                if (!CommonUtils.isUnset(request.body)) {
                    Map<String, Object> m = CommonUtils.assertAsMap(request.body);
                    request_.body = Acc.toReadable(ClientUtil.toForm(m));
                    request_.headers.put("content-type", "application/x-www-form-urlencoded");
                }

                if (!CommonUtils.isUnset(request.query)) {
                    request_.query = request.query;
                }

                if (!CommonUtils.equalString(authType, "Anonymous")) {
                    String accessKeyId = this.getAccessKeyId();
                    String accessKeySecret = this.getAccessKeySecret();
                    String securityToken = this.getSecurityToken();
                    if (!CommonUtils.empty(securityToken)) {
                        request_.headers.put("x-acc-accesskey-id", accessKeyId);
                        request_.headers.put("x-acc-security-token", securityToken);
                    }

                    String stringToSign = ClientUtil.getStringToSign(request_);
                    request_.headers.put("authorization", "acs " + accessKeyId + ":" + ClientUtil.getROASignature(stringToSign, accessKeySecret) + "");
                }

                _lastRequest = request_;
                AccResponse response_ = Acc.doAction(request_, runtime_);

                if (CommonUtils.equalNumber(response_.statusCode, 204)) {
                    return AccConverter.buildMap(
                        new AccPair("headers", response_.headers)
                    );
                }

                if (CommonUtils.is4xx(response_.statusCode) || CommonUtils.is5xx(response_.statusCode)) {
                    Object _res = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> err = CommonUtils.assertAsMap(_res);
                    throw new AccException(AccConverter.buildMap(
                        new AccPair("code", "" + Client.defaultAny(err.get("code"), err.get("statusCode")) + ""),
                        new AccPair("msg", "code: " + response_.statusCode + ", " + Client.defaultAny(err.get("msg"), err.get("message")) + " request id: " + Client.defaultAny(err.get("RequestId"), err.get("requestId")) + ""),
                        new AccPair("data", err)
                    ));
                }

                if (CommonUtils.equalString(bodyType, "binary")) {
                    Map<String, Object> resp = AccConverter.buildMap(
                        new AccPair("body", response_.body),
                        new AccPair("headers", response_.headers)
                    );
                    return resp;
                } else if (CommonUtils.equalString(bodyType, "byte")) {
                    byte[] byt = CommonUtils.readAsBytes(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", byt),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "string")) {
                    String str = CommonUtils.readAsString(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", str),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "json")) {
                    Object obj = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> res = CommonUtils.assertAsMap(obj);
                    return AccConverter.buildMap(
                        new AccPair("body", res),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(bodyType, "array")) {
                    Object arr = CommonUtils.readAsJSON(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", arr),
                        new AccPair("headers", response_.headers)
                    );
                } else {
                    return AccConverter.buildMap(
                        new AccPair("headers", response_.headers)
                    );
                }

            } catch (Exception e) {
                if (Acc.isRetryable(e)) {
                    _lastException = e;
                    continue;
                }
                throw e;
            }
        }

        throw new AccUnretryableException(_lastRequest, _lastException);
    }

    public Map<String, ?> doRequest(Params params, OpenApiRequest request, RuntimeOptions runtime) throws Exception {
        AccModel.validateParams(params, "params");
        AccModel.validateParams(request, "request");
        Map<String, Object> runtime_ = AccConverter.buildMap(
            new AccPair("timeouted", "retry"),
            new AccPair("readTimeout", CommonUtils.defaultNumber(runtime.readTimeout, _readTimeout)),
            new AccPair("connectTimeout", CommonUtils.defaultNumber(runtime.connectTimeout, _connectTimeout)),
            new AccPair("maxIdleConns", CommonUtils.defaultNumber(runtime.maxIdleConns, _maxIdleConns)),
            new AccPair("retry", AccConverter.buildMap(
                new AccPair("retryable", runtime.autoretry),
                new AccPair("maxAttempts", CommonUtils.defaultNumber(runtime.maxAttempts, 3))
            )),
            new AccPair("ignoreSSL", runtime.ignoreSSL)
        );

        AccRequest _lastRequest = null;
        Exception _lastException = null;
        long _now = System.currentTimeMillis();
        int _retryTimes = 0;
        while (Acc.allowRetry((Map<String, Object>) runtime_.get("retry"), _retryTimes, _now)) {
            if (_retryTimes > 0) {
                int backoffTime = Acc.getBackoffTime(runtime_.get("backoff"), _retryTimes);
                if (backoffTime > 0) {
                    Acc.sleep(backoffTime);
                }
            }
            _retryTimes = _retryTimes + 1;
            try {
                AccRequest request_ = new AccRequest();
                request_.protocol = CommonUtils.defaultString(_protocol, params.protocol);
                request_.method = params.method;
                request_.pathname = ClientUtil.getEncodePath(params.pathname);
                request_.query = request.query;
                // endpoint is setted in product client
                request_.headers = AccConverter.merge(String.class,
                    AccConverter.buildMap(
                        new AccPair("host", _endpoint),
                        new AccPair("x-acc-version", params.version),
                        new AccPair("x-acc-action", params.action),
                        new AccPair("user-agent", this.getUserAgent()),
                        new AccPair("x-acc-date", ClientUtil.getTimestamp()),
                        new AccPair("x-acc-signature-nonce", CommonUtils.getNonce()),
                        new AccPair("accept", "application/json")
                    ),
                    request.headers
                );
                String signatureAlgorithm = CommonUtils.defaultString(_signatureAlgorithm, "ACS3-HMAC-SHA256");
                String hashedRequestPayload = null;
                if (!CommonUtils.isUnset(request.body)) {
                    if (CommonUtils.equalString(params.reqBodyType, "json")) {
                        String jsonObj = CommonUtils.toJSONString(request.body);
                        hashedRequestPayload = ClientUtil.hexEncode(ClientUtil.hash(CommonUtils.toBytes(jsonObj), signatureAlgorithm));
                        request_.body = Acc.toReadable(jsonObj);
                    } else {
                        Map<String, Object> m = CommonUtils.assertAsMap(request.body);
                        String formObj = ClientUtil.toForm(m);
                        hashedRequestPayload = ClientUtil.hexEncode(ClientUtil.hash(CommonUtils.toBytes(formObj), signatureAlgorithm));
                        request_.body = Acc.toReadable(formObj);
                        request_.headers.put("content-type", "application/x-www-form-urlencoded");
                    }

                }

                if (!CommonUtils.isUnset(request.stream)) {
                    byte[] tmp = CommonUtils.readAsBytes(request.stream);
                    hashedRequestPayload = ClientUtil.hexEncode(ClientUtil.hash(tmp, signatureAlgorithm));
                    request_.body = Acc.toReadable(tmp);
                }
                
                if( hashedRequestPayload == null) {
                	hashedRequestPayload = ClientUtil.hexEncode(ClientUtil.hash(CommonUtils.toBytes(""), signatureAlgorithm));
                }

                request_.headers.put("x-acc-content-sha256", hashedRequestPayload);
                if (!CommonUtils.equalString(params.authType, "Anonymous")) {
                    String accessKeyId = this.getAccessKeyId();
                    String accessKeySecret = this.getAccessKeySecret();
                    String securityToken = this.getSecurityToken();
                    if (!CommonUtils.empty(securityToken)) {
                        request_.headers.put("x-acc-security-token", securityToken);
                    }

                    request_.headers.put("Authorization", ClientUtil.getAuthorization(request_, signatureAlgorithm, hashedRequestPayload, accessKeyId, accessKeySecret));
                }

                _lastRequest = request_;
                AccResponse response_ = Acc.doAction(request_, runtime_);

                if (CommonUtils.is4xx(response_.statusCode) || CommonUtils.is5xx(response_.statusCode)) {
                    Object _res = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> err = CommonUtils.assertAsMap(_res);
                    throw new AccException(AccConverter.buildMap(
                        new AccPair("code", "" + Client.defaultAny(err.get("code"), err.get("statusCode")) + ""),
                        new AccPair("msg", "code: " + response_.statusCode + ", " + Client.defaultAny(err.get("msg"), err.get("message")) + " request id: " + Client.defaultAny(err.get("RequestId"), err.get("requestId")) + ""),
                        new AccPair("data", err)
                    ));
                }

                if (CommonUtils.equalString(params.bodyType, "binary")) {
                    Map<String, Object> resp = AccConverter.buildMap(
                        new AccPair("body", response_.body),
                        new AccPair("headers", response_.headers)
                    );
                    return resp;
                } else if (CommonUtils.equalString(params.bodyType, "byte")) {
                    byte[] byt = CommonUtils.readAsBytes(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", byt),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(params.bodyType, "string")) {
                    String str = CommonUtils.readAsString(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", str),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(params.bodyType, "json")) {
                    Object obj = CommonUtils.readAsJSON(response_.body);
                    Map<String, Object> res = CommonUtils.assertAsMap(obj);
                    return AccConverter.buildMap(
                        new AccPair("body", res),
                        new AccPair("headers", response_.headers)
                    );
                } else if (CommonUtils.equalString(params.bodyType, "array")) {
                    Object arr = CommonUtils.readAsJSON(response_.body);
                    return AccConverter.buildMap(
                        new AccPair("body", arr),
                        new AccPair("headers", response_.headers)
                    );
                } else {
                    return AccConverter.buildMap(
                        new AccPair("headers", response_.headers)
                    );
                }

            } catch (Exception e) {
                if (Acc.isRetryable(e)) {
                    _lastException = e;
                    continue;
                }
                throw e;
            }
        }

        throw new AccUnretryableException(_lastRequest, _lastException);
    }

    public Map<String, ?> callApi(Params params, OpenApiRequest request, RuntimeOptions runtime) throws Exception {
        if (CommonUtils.isUnset(AccModel.buildMap(params))) {
            throw new AccException(AccConverter.buildMap(
                new AccPair("code", "ParameterMissing"),
                new AccPair("msg", "'params' can not be unset")
            ));
        }

        if (CommonUtils.isUnset(_signatureAlgorithm) || !CommonUtils.equalString(_signatureAlgorithm, "v2")) {
            return this.doRequest(params, request, runtime);
        } else if (CommonUtils.equalString(params.style, "ROA") && CommonUtils.equalString(params.reqBodyType, "json")) {
            return this.doROARequest(params.action, params.version, params.protocol, params.method, params.authType, params.pathname, params.bodyType, request, runtime);
        } else if (CommonUtils.equalString(params.style, "ROA")) {
            return this.doROARequestWithForm(params.action, params.version, params.protocol, params.method, params.authType, params.pathname, params.bodyType, request, runtime);
        } else {
            return this.doRPCRequest(params.action, params.version, params.protocol, params.method, params.authType, params.bodyType, request, runtime);
        }

    }

    /**
     * Get user agent
     * @return user agent
     */
    public String getUserAgent() throws Exception {
        String userAgent = CommonUtils.getUserAgent(_userAgent);
        return userAgent;
    }

    /**
     * Get accesskey id by using credential
     * @return accesskey id
     */
    public String getAccessKeyId() throws Exception {
        return this._accessKeyId;
    }

    /**
     * Get accesskey secret by using credential
     * @return accesskey secret
     */
    public String getAccessKeySecret() throws Exception {
        return this._accessKeySecret;
    }

    /**
     * Get security token by using credential
     * @return security token
     */
    public String getSecurityToken() throws Exception {
    	return this._securityToken;
    }

    /**
     * If inputValue is not null, return it or return defaultValue
     * @param inputValue  users input value
     * @param defaultValue default value
     * @return the final result
     */
    public static Object defaultAny(Object inputValue, Object defaultValue) throws Exception {
        if (CommonUtils.isUnset(inputValue)) {
            return defaultValue;
        }

        return inputValue;
    }

    /**
     * If the endpointRule and config.endpoint are empty, throw error
     * @param config config contains the necessary information to create a client
     */
    public void checkConfig(Config config) throws Exception {
        if (CommonUtils.empty(_endpointRule) && CommonUtils.empty(config.endpoint)) {
            throw new AccException(AccConverter.buildMap(
                new AccPair("code", "ParameterMissing"),
                new AccPair("message", "'config.endpoint' can not be empty")
            ));
        }

    }

    /**
     * set RPC header for debug
     * @param headers headers for debug, this header can be used only once.
     */
    public void setRpcHeaders(Map<String, String> headers) throws Exception {
        this._headers = headers;
    }

    /**
     * get RPC header for debug
     */
    public Map<String, String> getRpcHeaders() throws Exception {
        Map<String, String> headers = _headers;
        this._headers = null;
        return headers;
    }
}
