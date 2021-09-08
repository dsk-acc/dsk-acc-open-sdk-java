package com.dsk.acc.openapi.client.bean;

import com.dsk.acc.openapi.client.AccJsonField;
import com.dsk.acc.openapi.client.core.AccModel;

public class RuntimeOptions extends AccModel {
	@AccJsonField("autoretry")
	public Boolean autoretry = false;

	@AccJsonField("ignoreSSL")
	public Boolean ignoreSSL = true;

	@AccJsonField("max_attempts")
	public Integer maxAttempts;

	@AccJsonField("readTimeout")
	public Integer readTimeout;

	@AccJsonField("connectTimeout")
	public Integer connectTimeout;

	@AccJsonField("maxIdleConns")
	public Integer maxIdleConns;

	public static RuntimeOptions build(java.util.Map<String, ?> map) throws Exception {
		RuntimeOptions self = new RuntimeOptions();
		return AccModel.build(map, self);
	}

}
