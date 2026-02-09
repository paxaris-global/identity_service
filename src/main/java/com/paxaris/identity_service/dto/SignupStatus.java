package com.paxaris.identity_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupStatus {
    private String status; // "IN_PROGRESS", "SUCCESS", "FAILED"
    private String message;
    private List<StepStatus> steps;
    private Map<String, Object> token;
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class StepStatus {
        private String stepName;
        private String status; // "PENDING", "IN_PROGRESS", "SUCCESS", "FAILED"
        private String message;
        private String error;
    }
    
    public void addStep(String stepName, String status, String message) {
        if (this.steps == null) {
            this.steps = new ArrayList<>();
        }
        StepStatus step = StepStatus.builder()
                .stepName(stepName)
                .status(status)
                .message(message)
                .build();
        this.steps.add(step);
    }
    
    public void addStep(String stepName, String status, String message, String error) {
        if (this.steps == null) {
            this.steps = new ArrayList<>();
        }
        StepStatus step = StepStatus.builder()
                .stepName(stepName)
                .status(status)
                .message(message)
                .error(error)
                .build();
        this.steps.add(step);
    }
}
