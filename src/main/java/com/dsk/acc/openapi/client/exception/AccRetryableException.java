package com.dsk.acc.openapi.client.exception;

import java.util.Map;

public class AccRetryableException extends AccException {

    private static final long serialVersionUID = 3883312421128465122L;

    public AccRetryableException(Throwable cause) {
        super("", cause);
        message = cause.getMessage();
    }

    public AccRetryableException(Map<String, ?> map) {
        super(map);
    }

    public AccRetryableException() {
    }
}