package com.cashflow.cashflow.dto;

import lombok.Data;

@Data
public class ProfileUpdateRequest {
    private String name;
    private Double budget;
    private String currency;
}