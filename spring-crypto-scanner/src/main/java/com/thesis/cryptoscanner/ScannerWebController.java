package com.thesis.cryptoscanner;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ScannerWebController {

    @PostMapping("/scan")
    public ResponseEntity<Map<String,Object>> scan(
            @RequestBody Map<String,String> body) throws Exception {

        String path = body.get("path");
        if (path == null || path.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error","Project path is required"));
        }

        File dir = new File(path);
        if (!dir.exists() || !dir.isDirectory()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error","Path does not exist: " + path));
        }

        // Run the scanner
        SpringCryptoScanner scanner = new SpringCryptoScanner(path);
        scanner.scan();

        // Read the generated CBOM JSON
        File cbomFile = new File(path + "/cbom-springscanner.json");
        String cbomJson = cbomFile.exists()
                ? new String(Files.readAllBytes(cbomFile.toPath()))
                : "{}";

        // Build summary response
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("projectName", new File(path).getName());
        result.put("totalFindings", scanner.getFindings().size());
        result.put("critical", scanner.getFindings().stream()
                .filter(f -> "CRITICAL".equals(f.severity)).count());
        result.put("high", scanner.getFindings().stream()
                .filter(f -> "HIGH".equals(f.severity)).count());
        result.put("medium", scanner.getFindings().stream()
                .filter(f -> "MEDIUM".equals(f.severity)).count());
        result.put("quantumVulnerable", scanner.getFindings().stream()
                .filter(f -> "notQuantumSafe".equals(f.quantumStatus)).count());
        result.put("classicallyBroken", scanner.getFindings().stream()
                .filter(f -> "classicallyBroken".equals(f.quantumStatus)).count());
        result.put("cbomkitWouldMiss", scanner.getFindings().stream()
                .filter(f -> !f.layer.equals("L4-RawJCA")).count());
        result.put("layer1", scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L1")).count());
        result.put("layer2", scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L2")).count());
        result.put("layer3", scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L3")).count());
        result.put("layer4", scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L4")).count());

        // Full findings list
        List<Map<String,String>> findingsList = new ArrayList<>();
        for (SpringCryptoScanner.Finding f : scanner.getFindings()) {
            Map<String,String> fm = new LinkedHashMap<>();
            fm.put("rule",          f.rule);
            fm.put("file",          f.file);
            fm.put("line",          String.valueOf(f.line));
            fm.put("severity",      f.severity);
            fm.put("layer",         f.layer);
            fm.put("algorithm",     f.algorithm);
            fm.put("quantumStatus", f.quantumStatus);
            fm.put("detail",        f.detail);
            fm.put("replacement",   f.replacement);
            fm.put("cbomkitDetects", f.layer.equals("L4-RawJCA") ? "true" : "false");
            findingsList.add(fm);
        }
        result.put("findings", findingsList);
        result.put("cbomJson", cbomJson);

        return ResponseEntity.ok(result);
    }
}