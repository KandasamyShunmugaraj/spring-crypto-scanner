package com.thesis.cryptoscanner;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.File;
import java.nio.file.Files;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ScannerWebController {

    // ── Scan endpoint — accepts local path OR GitHub URL ─────────────────────
    @PostMapping("/scan")
    public ResponseEntity<Map<String, Object>> scan(
            @RequestBody Map<String, String> body) throws Exception {

        String input = body.get("path");
        if (input == null || input.isEmpty()) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Project path or GitHub URL is required"));
        }

        String projectPath = input.trim();
        File tempDir = null;

        // ── If GitHub URL — clone to temp folder ──────────────────────────────
        boolean isGitHub = projectPath.startsWith("https://github.com/")
                        || projectPath.startsWith("http://github.com/");

        if (isGitHub) {
            // Normalise URL — add .git if missing
            String repoUrl = projectPath.endsWith(".git")
                ? projectPath : projectPath + ".git";

            // Create temp directory
            tempDir = Files.createTempDirectory("spring-crypto-scanner-").toFile();
            System.out.println("Cloning: " + repoUrl + " → " + tempDir.getAbsolutePath());

            // Run git clone --depth=1 (shallow clone — fast)
            ProcessBuilder pb = new ProcessBuilder(
                "git", "clone", "--depth=1", repoUrl, tempDir.getAbsolutePath()
            );
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            String cloneOutput = new String(proc.getInputStream().readAllBytes());
            int exitCode = proc.waitFor();

            if (exitCode != 0) {
                deleteDirectory(tempDir);
                return ResponseEntity.badRequest()
                    .body(Map.of("error",
                        "Git clone failed. Check the URL is a valid public GitHub repo.\n"
                        + cloneOutput));
            }

            projectPath = tempDir.getAbsolutePath();
            System.out.println("Clone successful → " + projectPath);
        }

        // ── Validate local path ───────────────────────────────────────────────
        File dir = new File(projectPath);
        if (!dir.exists() || !dir.isDirectory()) {
            if (tempDir != null) deleteDirectory(tempDir);
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Path does not exist: " + projectPath));
        }

        try {
            // ── Run scanner ───────────────────────────────────────────────────
            SpringCryptoScanner scanner = new SpringCryptoScanner(projectPath);
            scanner.scan();

            // Read the generated CBOM JSON
            File cbomFile = new File(projectPath + "/cbom-springscanner.json");
            String cbomJson = cbomFile.exists()
                ? new String(Files.readAllBytes(cbomFile.toPath()))
                : "{}";

            // ── Build project name ────────────────────────────────────────────
            // For GitHub URLs use the repo name from the URL
            String projectName;
            if (isGitHub) {
                String url = input.trim().replaceAll("\\.git$", "");
                String[] parts = url.split("/");
                projectName = parts[parts.length - 1]; // last segment = repo name
            } else {
                projectName = new File(projectPath).getName();
            }

            // ── Build summary response ────────────────────────────────────────
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("projectName",      projectName);
            result.put("inputUrl",         input.trim());
            result.put("isGitHub",         isGitHub);
            result.put("totalFindings",    scanner.getFindings().size());
            result.put("critical",         scanner.getFindings().stream()
                .filter(f -> "CRITICAL".equals(f.severity)).count());
            result.put("high",             scanner.getFindings().stream()
                .filter(f -> "HIGH".equals(f.severity)).count());
            result.put("medium",           scanner.getFindings().stream()
                .filter(f -> "MEDIUM".equals(f.severity)).count());
            result.put("quantumVulnerable",scanner.getFindings().stream()
                .filter(f -> "notQuantumSafe".equals(f.quantumStatus)).count());
            result.put("classicallyBroken",scanner.getFindings().stream()
                .filter(f -> "classicallyBroken".equals(f.quantumStatus)).count());
            result.put("cbomkitWouldMiss", scanner.getFindings().stream()
                .filter(f -> !f.layer.equals("L4-RawJCA")).count());
            result.put("layer1",           scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L1")).count());
            result.put("layer2",           scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L2")).count());
            result.put("layer3",           scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L3")).count());
            result.put("layer4",           scanner.getFindings().stream()
                .filter(f -> f.layer.startsWith("L4")).count());

            // Full findings list
            List<Map<String, String>> findingsList = new ArrayList<>();
            for (SpringCryptoScanner.Finding f : scanner.getFindings()) {
                Map<String, String> fm = new LinkedHashMap<>();
                fm.put("rule",           f.rule);
                fm.put("file",           f.file);
                fm.put("line",           String.valueOf(f.line));
                fm.put("severity",       f.severity);
                fm.put("layer",          f.layer);
                fm.put("algorithm",      f.algorithm);
                fm.put("quantumStatus",  f.quantumStatus);
                fm.put("detail",         f.detail);
                fm.put("replacement",    f.replacement);
                fm.put("cbomkitDetects", f.layer.equals("L4-RawJCA") ? "true" : "false");
                findingsList.add(fm);
            }
            result.put("findings", findingsList);
            result.put("cbomJson", cbomJson);

            return ResponseEntity.ok(result);

        } finally {
            // Always clean up temp dir if we cloned from GitHub
            if (tempDir != null) {
                deleteDirectory(tempDir);
                System.out.println("Temp dir cleaned up.");
            }
        }
    }

    // ── Download CBOM JSON endpoint ───────────────────────────────────────────
    // Called by the browser's Download JSON button
    // GET /api/download-cbom?project=spring-security-samples
    @GetMapping("/download-cbom")
    public ResponseEntity<byte[]> downloadCbom(
            @RequestParam(defaultValue = "project") String project,
            @RequestParam(required = false)          String cbomJson) {

        // If cbomJson passed as param use it, otherwise return placeholder
        String json = (cbomJson != null && !cbomJson.isEmpty())
            ? cbomJson
            : "{ \"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\", \"components\": [] }";

        String filename = "cbom-springscanner-" + project
            .replaceAll("[^a-zA-Z0-9_-]", "-") + ".json";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.CONTENT_DISPOSITION,
            "attachment; filename=\"" + filename + "\"");

        return ResponseEntity.ok()
            .headers(headers)
            .body(json.getBytes());
    }

    // ── Health check ──────────────────────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
            "status",  "UP",
            "tool",    "SpringCryptoScanner v2.0",
            "output",  "CycloneDX 1.6 CBOM JSON",
            "thesis",  "Kandasamy | IIT Jodhpur | M25AID042"
        ));
    }

    // ── Helper — delete directory recursively ─────────────────────────────────
    private void deleteDirectory(File dir) {
        if (dir != null && dir.exists()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) deleteDirectory(f);
            }
            dir.delete();
        }
    }
}
