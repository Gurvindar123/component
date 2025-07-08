package com.apis.auth_service.controllers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@RestController
@RequestMapping("/api/invoice-check")
public class InvoiceCheckController {

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${invoice.service.base-url:http://192.168.1.7:8081}")
    private String invoiceServiceBaseUrl;

    @GetMapping("/{invoiceId}")
    public ResponseEntity<?> checkInvoiceStatus(@PathVariable("invoiceId") Long invoiceId) {
        String invoiceApiUrl = invoiceServiceBaseUrl + "/invoices/" + invoiceId;

        try {
            ResponseEntity<Map> response = restTemplate.getForEntity(invoiceApiUrl, Map.class);
            Map<String, Object> body = response.getBody();

            if (body == null || !body.containsKey("status")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("message", "Invalid invoice data received."));
            }

            String status = body.get("status").toString();
            boolean isOutstanding = "OUTSTANDING".equalsIgnoreCase(status);

            return ResponseEntity.ok(Map.of(
                    "invoiceId", invoiceId,
                    "reference", body.get("reference"),
                    "studentId", body.get("studentId"),
                    "amount", body.get("amount"),
                    "status", status,
                    "isOutstanding", isOutstanding
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error fetching invoice", "error", e.getMessage()));
        }
    }
}
