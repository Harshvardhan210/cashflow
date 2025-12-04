package com.cashflow.cashflow.service;

import com.cashflow.cashflow.dto.ExpenseRequest;
import com.cashflow.cashflow.entity.Expense;
import com.cashflow.cashflow.entity.User;
import com.cashflow.cashflow.repository.ExpenseRepository;
import com.cashflow.cashflow.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ExpenseService {

    private final ExpenseRepository expenseRepository;
    private final UserRepository userRepository;

    /**
     * Get logged-in user using Spring Security context
     */
    private User getLoggedInUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    /**
     * Add new expense mapped from DTO
     */
    public Expense addExpense(ExpenseRequest request) {
        User user = getLoggedInUser();

        Expense expense = new Expense();
        expense.setTitle(request.getTitle());
        expense.setAmount(request.getAmount());

        // Ensure valid date
        expense.setDate(request.getDate());


        expense.setUser(user);

        return expenseRepository.save(expense);
    }

    /**
     * Fetch all expenses for logged-in user
     */
    public List<Expense> getUserExpenses() {
        User user = getLoggedInUser();
        return expenseRepository.findByUserId(user.getId());
    }

    /**
     * Delete expense only if it belongs to the logged-in user
     */
    public void deleteExpense(Long expenseId) {
        User user = getLoggedInUser();
        Expense expense = expenseRepository.findById(expenseId)
                .orElseThrow(() -> new RuntimeException("Expense not found"));

        if (!expense.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Not authorized to delete this expense");
        }

        expenseRepository.delete(expense);
    }
}
