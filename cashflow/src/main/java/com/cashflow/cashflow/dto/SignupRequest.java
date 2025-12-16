package com.cashflow.cashflow.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record SignupRequest(

        @NotBlank String name,

        @NotBlank
        @Email String email,

        @NotBlank
        @Size(min = 4)
        String username,

        @NotBlank
        @Size(min = 6)
        String password,

        @JsonFormat(pattern = "yyyy-MM-dd")
        LocalDate dob        // ✅ FIXED
) {}
