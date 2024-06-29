package com.jwe.exception;

import lombok.Getter;

public class ApplicationException extends Exception{

    @Getter
    private ExceptionCode exceptionCode;
    private String abdmErrorCode;
    private String abdmErrorObject;

    private static final long serialVersionUID = 1L;

    public ApplicationException(String message) {
        super(message);
        this.exceptionCode = ExceptionCode.UNKNOWN;
    }

    public ApplicationException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public ApplicationException(ExceptionCode exceptionCode, String message) {
        super(message);
        this.exceptionCode = exceptionCode;
    }

    public ApplicationException(ExceptionCode exceptionCode, String message, Throwable throwable) {
        super(message, throwable);
        this.exceptionCode = exceptionCode;
    }

}
