package com.stroe.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthValidationResponse {

    private boolean valid;
    private String username;
    private List<String> roles;
}
