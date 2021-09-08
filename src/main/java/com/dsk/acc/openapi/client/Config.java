package com.dsk.acc.openapi.client;

import com.dsk.acc.openapi.client.core.AccModel;

public class Config extends AccModel {
    // accesskey id
    @AccJsonField("accessKeyId")
    public String accessKeyId;

    // accesskey secret
    @AccJsonField("accessKeySecret")
    public String accessKeySecret;

    // security token
    @AccJsonField("securityToken")
    public String securityToken;

    // http protocol
    @AccJsonField("protocol")
    public String protocol;

    // region id
    @AccJsonField("regionId")
    public String regionId;

    // read timeout
    @AccJsonField("readTimeout")
    public Integer readTimeout;

    // connect timeout
    @AccJsonField("connectTimeout")
    public Integer connectTimeout;

    // endpoint
    @AccJsonField("endpoint")
    public String endpoint;

    // max idle conns
    @AccJsonField("maxIdleConns")
    public Integer maxIdleConns;

    // network for endpoint
    @AccJsonField("network")
    public String network;

    // user agent
    @AccJsonField("userAgent")
    public String userAgent;
    
    // Signature Algorithm
    @AccJsonField("signatureAlgorithm")
    public String signatureAlgorithm;

    // credential
    @AccJsonField("credential")
    public Client credential;

    public static Config build(java.util.Map<String, ?> map) throws Exception {
        Config self = new Config();
        return AccModel.build(map, self);
    }

	public Config() {
		super();
	}

	public Config(String accessKeyId, String accessKeySecret) {
		super();
		this.accessKeyId = accessKeyId;
		this.accessKeySecret = accessKeySecret;
	}

	public String getAccessKeyId() {
		return accessKeyId;
	}

	public void setAccessKeyId(String accessKeyId) {
		this.accessKeyId = accessKeyId;
	}

	public String getAccessKeySecret() {
		return accessKeySecret;
	}

	public void setAccessKeySecret(String accessKeySecret) {
		this.accessKeySecret = accessKeySecret;
	}

	public String getSecurityToken() {
		return securityToken;
	}

	public void setSecurityToken(String securityToken) {
		this.securityToken = securityToken;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getRegionId() {
		return regionId;
	}

	public void setRegionId(String regionId) {
		this.regionId = regionId;
	}

	public Integer getReadTimeout() {
		return readTimeout;
	}

	public void setReadTimeout(Integer readTimeout) {
		this.readTimeout = readTimeout;
	}

	public Integer getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(Integer connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public String getEndpoint() {
		return endpoint;
	}

	public Config setEndpoint(String endpoint) {
		this.endpoint = endpoint;
		return this;
	}

	public Integer getMaxIdleConns() {
		return maxIdleConns;
	}

	public void setMaxIdleConns(Integer maxIdleConns) {
		this.maxIdleConns = maxIdleConns;
	}

	public String getNetwork() {
		return network;
	}

	public void setNetwork(String network) {
		this.network = network;
	}

	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
    public Config setCredential(Client credential) {
        this.credential = credential;
        return this;
    }
    public Client getCredential() {
        return this.credential;
    }
}
