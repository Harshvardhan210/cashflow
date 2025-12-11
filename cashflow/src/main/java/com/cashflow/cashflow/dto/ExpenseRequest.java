package com.cashflow.cashflow.dto;

import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
public class ExpenseRequest {
    private String title;
    private Double amount;
    private String date;   // safer for JSON frontends
}

