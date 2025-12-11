package com.cashflow.cashflow.dto;

import jakarta.persistence.Entity;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;
import java.time.LocalDateTime;

public record SignupRequest(
        @NotBlank String name,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 4) String username,
        @NotBlank @Size(min = 6) String password,
        String dob
) {}
