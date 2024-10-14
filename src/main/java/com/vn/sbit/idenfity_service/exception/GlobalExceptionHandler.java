package com.vn.sbit.idenfity_service.exception;

import com.vn.sbit.idenfity_service.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    //ResponseEntity:một lớp trong Spring Framework được sử dụng để biểu diễn toàn bộ phản hồi HTTP
    //Exception chung
    @ExceptionHandler(value = Exception.class)
    ResponseEntity<ApiResponse> handlingRuntimeException(RuntimeException exception) {
        log.error("Exception: ", exception);
        ApiResponse apiResponse = new ApiResponse();

        apiResponse.setCode(ErrorCode.UNCATEGORIZED_EXCEPTION.getCode());
        apiResponse.setMessage(ErrorCode.UNCATEGORIZED_EXCEPTION.getMessage());

        return ResponseEntity.badRequest().body(apiResponse);
    }



    //xử lý ngoại lệ bằng class (AppException)
    @ExceptionHandler(value = AppException.class)
    ResponseEntity<ApiResponse> handlingAppException(AppException exception){
        ApiResponse apiResponse = new ApiResponse();
        //AppException co construct ErrorCode
        ErrorCode errorCode = exception.getErrorCode();
        //code cua user_existed
        apiResponse.setCode(errorCode.getCode());
        //loi nhan error
        apiResponse.setMessage((errorCode.getMessage()));

        return ResponseEntity
                .status(errorCode.getHttpStatusCode())
                .body(apiResponse);
    }


//    @ExceptionHandler(value = DefaultHandlerExceptionResolver.class)
//    ResponseEntity<ApiResponse> DefaultHandlerExceptionResolve() {
//        return DefaultHandlerExceptionResolve(null);
//    }



//   class CustomAccessDeniedHandler - bắt lỗi không có quyền truy cập như User log -> Admin endpoint

//    @ExceptionHandler(value = AccessDeniedException.class)
//    ResponseEntity<ApiResponse> handlingAccessDeniedException(AccessDeniedException exception) {
//        ErrorCode errorCode = ErrorCode.UNAUTHORIZED;
//
//        return ResponseEntity.status(errorCode.getHttpStatusCode())
//                .body(ApiResponse.builder()
//                        .code(errorCode.getCode())
//                        .message(errorCode.getMessage())
//                        .build());
//    }

    //user tạo không đúng quy định - user validation
    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    ResponseEntity<ApiResponse> handlingMethodArgumentNotValidException(MethodArgumentNotValidException exception){
        String enumKey = exception.getFieldError().getDefaultMessage();//trả về message ở size UserCreationRequest

        ErrorCode errorCode =ErrorCode.INVALID_KEY; // defaul sẽ luôn là lỗi này, đề phòng trường hợp sai không có code phù hợp

        try {
            errorCode = ErrorCode.valueOf(enumKey);//ép chuỗi string thành ErrorCode type
        }catch (IllegalArgumentException e){
            System.out.println(e.getMessage());
        }

        ApiResponse apiResponse= new ApiResponse();

        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage());

        return ResponseEntity.badRequest().body(apiResponse);
    }
}
