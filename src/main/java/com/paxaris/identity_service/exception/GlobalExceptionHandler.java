package com.paxaris.identity_service.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static com.paxaris.identity_service.config.CorrelationIdFilter.CORRELATION_ID_HEADER;
import static com.paxaris.identity_service.config.CorrelationIdFilter.CORRELATION_ID_KEY;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleMethodNotSupported(
        HttpRequestMethodNotSupportedException ex,
        HttpServletRequest request) {

    String correlationId = resolveCorrelationId(request);
    log.warn("MethodNotSupported correlationId={} path={} message={}",
        correlationId, request.getRequestURI(), ex.getMessage());

    return buildErrorResponse(
        HttpStatus.METHOD_NOT_ALLOWED,
        "Method Not Allowed",
        ex.getMessage(),
        request,
        correlationId
    );
    }

    @ExceptionHandler({
        MethodArgumentNotValidException.class,
        MethodArgumentTypeMismatchException.class,
        HttpMessageNotReadableException.class,
        IllegalArgumentException.class
    })
    public ResponseEntity<Map<String, Object>> handleBadRequest(
        Exception ex,
        HttpServletRequest request) {

    String correlationId = resolveCorrelationId(request);
    log.warn("BadRequest correlationId={} path={} message={}",
        correlationId, request.getRequestURI(), ex.getMessage());

    String message;
    if (ex instanceof MethodArgumentNotValidException validationEx) {
        message = validationEx.getBindingResult().getFieldErrors().stream()
            .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
            .collect(Collectors.joining("; "));
    } else {
        message = ex.getMessage();
    }

    return buildErrorResponse(
        HttpStatus.BAD_REQUEST,
        "Bad Request",
        message,
        request,
        correlationId
    );
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(
        ResponseStatusException ex,
        HttpServletRequest request) {

    String correlationId = resolveCorrelationId(request);
    HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
    log.warn("ResponseStatusException correlationId={} path={} status={} message={}",
        correlationId, request.getRequestURI(), status.value(), ex.getMessage());

    return buildErrorResponse(
        status,
        status.getReasonPhrase(),
        ex.getReason() != null ? ex.getReason() : ex.getMessage(),
        request,
        correlationId
    );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request) {

        String correlationId = resolveCorrelationId(request);
        log.warn("AccessDeniedException correlationId={} path={} message={}",
                correlationId, request.getRequestURI(), ex.getMessage());

        return buildErrorResponse(
                HttpStatus.FORBIDDEN,
                "Access Denied",
                ex.getMessage(),
                request,
                correlationId
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(
            Exception ex,
            HttpServletRequest request) {

        String correlationId = resolveCorrelationId(request);
        log.error("UnhandledException correlationId={} path={} message={}",
                correlationId, request.getRequestURI(), ex.getMessage(), ex);

        return buildErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                ex.getMessage(),
                request,
                correlationId
        );
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(HttpStatus status,
                                                                    String error,
                                                                    String message,
                                                                    HttpServletRequest request,
                                                                    String correlationId) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", LocalDateTime.now());
        payload.put("status", status.value());
        payload.put("error", error);
        payload.put("message", message);
        payload.put("path", request.getRequestURI());
        payload.put("correlationId", correlationId);
        return ResponseEntity.status(status).body(payload);
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String correlationId = request.getHeader(CORRELATION_ID_HEADER);
        if (StringUtils.hasText(correlationId)) {
            return correlationId;
        }

        Object correlationAttr = request.getAttribute(CORRELATION_ID_KEY);
        if (correlationAttr != null && StringUtils.hasText(correlationAttr.toString())) {
            return correlationAttr.toString();
        }

        return "N/A";
    }
}
