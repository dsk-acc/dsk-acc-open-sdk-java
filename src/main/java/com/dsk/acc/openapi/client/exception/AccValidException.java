package com.dsk.acc.openapi.client.exception;

public class AccValidException extends RuntimeException {
    public AccValidException(String message) {
        super(message);
    }

    public AccValidException(String message, Exception e) {
        super(message, e);
    }
}
