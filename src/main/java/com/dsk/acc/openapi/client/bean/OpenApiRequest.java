package com.dsk.acc.openapi.client.bean;

import com.dsk.acc.openapi.client.AccJsonField;
import com.dsk.acc.openapi.client.core.AccModel;

public class OpenApiRequest extends AccModel {
	@AccJsonField("headers")
	public java.util.Map<String, String> headers;

	@AccJsonField("query")
	public java.util.Map<String, String> query;

	@AccJsonField("body")
	public Object body;

	@AccJsonField("stream")
	public java.io.InputStream stream;

	public static OpenApiRequest build(java.util.Map<String, ?> map) throws Exception {
		OpenApiRequest self = new OpenApiRequest();
		return AccModel.build(map, self);
	}

	public OpenApiRequest setHeaders(java.util.Map<String, String> headers) {
		this.headers = headers;
		return this;
	}

	public java.util.Map<String, String> getHeaders() {
		return this.headers;
	}

	public OpenApiRequest setQuery(java.util.Map<String, String> query) {
		this.query = query;
		return this;
	}

	public java.util.Map<String, String> getQuery() {
		return this.query;
	}

	public OpenApiRequest setBody(Object body) {
		this.body = body;
		return this;
	}

	public Object getBody() {
		return this.body;
	}

	public OpenApiRequest setStream(java.io.InputStream stream) {
		this.stream = stream;
		return this;
	}

	public java.io.InputStream getStream() {
		return this.stream;
	}

}
