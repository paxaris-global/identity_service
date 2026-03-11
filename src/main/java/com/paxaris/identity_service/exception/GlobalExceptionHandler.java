package com.paxaris.identity_service.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.paxaris.identity_service.config.CorrelationIdFilter.CORRELATION_ID_HEADER;
import static com.paxaris.identity_service.config.CorrelationIdFilter.CORRELATION_ID_KEY;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

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
