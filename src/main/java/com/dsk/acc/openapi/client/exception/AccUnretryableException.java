package com.dsk.acc.openapi.client.exception;

import com.dsk.acc.openapi.client.core.AccRequest;

public class AccUnretryableException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = -7006694712718176751L;

    private AccRequest lastRequest = null;

    public AccRequest getLastRequest() {
        return lastRequest;
    }

    public AccUnretryableException(AccRequest lastRequest, Throwable lastException) {
        super(lastException.getMessage(), lastException);
        this.lastRequest = lastRequest;
    }

    public AccUnretryableException(AccRequest lastRequest) {
        this.lastRequest = lastRequest;
    }

    public AccUnretryableException(Throwable lastException) {
        super(lastException);
    }

    public AccUnretryableException() {
        super();
    }
}
