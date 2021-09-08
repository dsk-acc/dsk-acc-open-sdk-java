package com.dsk.acc.openapi.client.bean;

import com.dsk.acc.openapi.client.AccJsonField;
import com.dsk.acc.openapi.client.AccValid;
import com.dsk.acc.openapi.client.core.AccModel;

public class Params extends AccModel {
	@AccJsonField("action")
    @AccValid(required = true)
    public String action;

    @AccJsonField("version")
    @AccValid(required = true)
    public String version;

    @AccJsonField("protocol")
    @AccValid(required = true)
    public String protocol;

    @AccJsonField("pathname")
    @AccValid(required = true)
    public String pathname;

    @AccJsonField("method")
    @AccValid(required = true)
    public String method;

    @AccJsonField("authType")
    @AccValid(required = true)
    public String authType;

    @AccJsonField("bodyType")
    @AccValid(required = true)
    public String bodyType;

    @AccJsonField("reqBodyType")
    @AccValid(required = true)
    public String reqBodyType;

    @AccJsonField("style")
    public String style;

    public static Params build(java.util.Map<String, ?> map) throws Exception {
        Params self = new Params();
        return AccModel.build(map, self);
    }

    public Params setAction(String action) {
        this.action = action;
        return this;
    }
    public String getAction() {
        return this.action;
    }

    public Params setVersion(String version) {
        this.version = version;
        return this;
    }
    public String getVersion() {
        return this.version;
    }

    public Params setProtocol(String protocol) {
        this.protocol = protocol;
        return this;
    }
    public String getProtocol() {
        return this.protocol;
    }

    public Params setPathname(String pathname) {
        this.pathname = pathname;
        return this;
    }
    public String getPathname() {
        return this.pathname;
    }

    public Params setMethod(String method) {
        this.method = method;
        return this;
    }
    public String getMethod() {
        return this.method;
    }

    public Params setAuthType(String authType) {
        this.authType = authType;
        return this;
    }
    public String getAuthType() {
        return this.authType;
    }

    public Params setBodyType(String bodyType) {
        this.bodyType = bodyType;
        return this;
    }
    public String getBodyType() {
        return this.bodyType;
    }

    public Params setReqBodyType(String reqBodyType) {
        this.reqBodyType = reqBodyType;
        return this;
    }
    public String getReqBodyType() {
        return this.reqBodyType;
    }

    public Params setStyle(String style) {
        this.style = style;
        return this;
    }
    public String getStyle() {
        return this.style;
    }


}
