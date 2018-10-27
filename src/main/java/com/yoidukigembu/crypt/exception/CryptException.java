package com.yoidukigembu.crypt.exception;

public class CryptException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = -4360985691850820045L;

    public CryptException(Throwable cause) {
        super(cause);
    }

    public CryptException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
