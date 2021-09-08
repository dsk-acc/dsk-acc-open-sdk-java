package com.dsk.acc.openapi;

/**
 * 
 * @author zhaowei 2021年9月2日
 */
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.dsk.acc.openapi.api.AccClient;
import com.dsk.acc.openapi.client.Config;


//@Slf4j
//@Component
public class DemoAccClientUtil {
	
	public static String accessKeyId;
	public static String accessSecret;
	
	/**
	 * -开放平台统一请求
	 * @param path
	 * @param bodyMap
	 * @return
	 */
	public static JSONObject request(String path, Map<String, Object> bodyMap){
		JSONObject resObj = null;
		try {
			AccClient.init(new Config(accessKeyId, accessSecret));
			Map<String, ?> res = AccClient.request(path, bodyMap);
			if(res.get("body") == null || res.get("headers") == null) {
				return null;
			}
			resObj = JSON.parseObject(JSON.toJSONString(res.get("body")));
		} catch (Exception e) {
//			log.error("请求开放平台失败,reqPath={},reqBody={},e={}", path, JSON.toJSONString(bodyMap), e.getMessage());
		}
		return resObj;
	}

	public String getAccessKeyId() {
		return accessKeyId;
	}
//	@Value("${dsk-acc.open.accessKeyId}")
	public void setAccessKeyId(String accessKeyId) {
		this.accessKeyId = accessKeyId;
	}

	public String getAccessSecret() {
		return accessSecret;
	}
//	@Value("${dsk-acc.open.accessSecret}")
	public void setAccessSecret(String accessSecret) {
		this.accessSecret = accessSecret;
	}
	
}