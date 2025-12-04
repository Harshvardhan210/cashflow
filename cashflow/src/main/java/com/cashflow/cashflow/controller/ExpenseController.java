package com.cashflow.cashflow.controller;

import com.cashflow.cashflow.dto.ExpenseRequest;
import com.cashflow.cashflow.entity.Expense;
import com.cashflow.cashflow.service.ExpenseService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/expenses")
@RequiredArgsConstructor
public class ExpenseController {

    private final ExpenseService expenseService;

    // Create expense
    @PostMapping
    public Expense createExpense(@RequestBody ExpenseRequest request) {
        return expenseService.addExpense(request);
    }

    // Get all logged-in user's expenses
    @GetMapping
    public List<Expense> getUserExpenses() {
        return expenseService.getUserExpenses();
    }

    // Delete expense by ID
    @DeleteMapping("/{id}")
    public String deleteExpense(@PathVariable Long id) {
        expenseService.deleteExpense(id);
        return "Expense deleted successfully";
    }
}
