package com.sopt.wokat.global.error.exception;

import com.sopt.wokat.global.error.ErrorCode;

public class CantConvertFileException extends BusinessException {
    public CantConvertFileException() {
        super(ErrorCode.FILE_CANT_CONVERT);
    }
}
