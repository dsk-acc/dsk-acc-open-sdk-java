package com.dsk.acc.openapi.api;

import java.util.Map;

import com.dsk.acc.openapi.client.Client;
import com.dsk.acc.openapi.client.Config;
import com.dsk.acc.openapi.client.bean.OpenApiRequest;
import com.dsk.acc.openapi.client.bean.Params;
import com.dsk.acc.openapi.client.bean.RuntimeOptions;
import com.dsk.acc.openapi.client.core.AccConverter;
import com.dsk.acc.openapi.client.core.AccPair;
import com.dsk.acc.openapi.client.exception.AccValidException;

public class AccClient {

	private static Client client;
	private static String version = "1.0.0";
	private static String OPENAPI_POINT = "120.27.13.145:8766"; //测试
//	private static String OPENAPI_POINT = "120.27.13.145:8766"; //正式
	
	private AccClient() {
	}
	
	/**
	 * -单例生成
	 * @param config
	 * @return
	 */
	public static void init(Config config) {
		try {
			if(client == null) client = new Client(config.setEndpoint(OPENAPI_POINT));
		} catch (Exception e) {
			throw new AccValidException("client config init error", e);
		}
	}
	
	/**
	 * -发起请求
	 * @param config
	 * @return
	 */
	public static Map<String, ?> request(String pathname, Map<String, Object> reqBody){
		if(client == null) throw new AccValidException("client not init");
		
		OpenApiRequest req;
		Map<String, ?> callApi = null;
		try {
			req = OpenApiRequest.build(AccConverter.buildMap( new AccPair("body", reqBody) ));
			Params params = new Params()
					.setAction(pathname)
					.setPathname(pathname)
					.setAuthType("AK")
					.setBodyType("json")
					.setReqBodyType("json")
					.setMethod("POST")
					.setProtocol("HTTP")
					.setVersion(version);
			callApi = client.callApi(params, req, new RuntimeOptions());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return callApi;
	}
}
