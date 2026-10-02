package com.thesis.cryptoscanner;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.File;
import java.nio.file.Files;
import java.util.*;
import java.util.Arrays;

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
            String repoUrl = projectPath.endsWith(".git")
                ? projectPath : projectPath + ".git";

            tempDir = Files.createTempDirectory("spring-crypto-scanner-").toFile();
            System.out.println("Cloning: " + repoUrl + " → " + tempDir.getAbsolutePath());

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

            // Pass GitHub metadata if cloned
            if (isGitHub) {
                String commit = getGitCommit(projectPath);
                String branch = getGitBranch(projectPath);
                scanner.setSourceInfo(input.trim(), commit, branch);
            }

            scanner.scan();

            // Read CBOM JSON
            File cbomFile = new File(projectPath + "/cbom-springscanner.json");
            String cbomJson = cbomFile.exists()
                ? new String(Files.readAllBytes(cbomFile.toPath()))
                : "{}";

            // Build project name
            String projectName;
            if (isGitHub) {
                String url = input.trim().replaceAll("\\.git$", "");
                String[] parts = url.split("/");
                projectName = parts[parts.length - 1];
            } else {
                projectName = new File(projectPath).getName();
            }

            List<SpringCryptoScanner.Finding> all = scanner.getFindings();

            // ── Key distinction: actionable vs inventory ───────────────────────
            // issuesFound    = CRITICAL + HIGH + MEDIUM (actionable, comparable to CBOMkit)
            // infoInventory  = INFO only (quantum-safe assets for CBOM inventory)
            // totalFindings  = all findings

            long issuesFound = all.stream()
                .filter(f -> !f.severity.equals("INFO")).count();

            long infoInventory = all.stream()
                .filter(f -> f.severity.equals("INFO")).count();

            // Findings produced by JCA calls that CBOMkit's rules cover are flagged cbomkitExpected.
            // Everything else is outside CBOMkit's rules. Whether CBOMkit actually reports the
            // expected ones depends on its module detection and must be checked against its output.
            long outsideCbomkitRules = all.stream().filter(f -> !f.cbomkitExpected).count();

            // ── Build response ────────────────────────────────────────────────
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("projectName",       projectName);
            result.put("inputUrl",          input.trim());
            result.put("isGitHub",          isGitHub);

            // Total counts
            result.put("totalFindings",     all.size());
            result.put("issuesFound",       issuesFound);   // actionable only
            result.put("infoInventory",     infoInventory); // safe assets for CBOM

            // Severity breakdown (actionable)
            result.put("critical",          all.stream().filter(f -> "CRITICAL".equals(f.severity)).count());
            result.put("high",              all.stream().filter(f -> "HIGH".equals(f.severity)).count());
            result.put("medium",            all.stream().filter(f -> "MEDIUM".equals(f.severity)).count());
            result.put("info",              infoInventory);

            // Quantum classification (all findings)
            result.put("quantumVulnerable", all.stream().filter(f -> "notQuantumSafe".equals(f.quantumStatus)).count());
            result.put("classicallyBroken", all.stream().filter(f -> "classicallyBroken".equals(f.quantumStatus)).count());
            result.put("quantumSafe",       all.stream().filter(f -> "quantumSafe".equals(f.quantumStatus)).count());

            // CBOMkit gap — CORRECTED VALUE
            result.put("cbomkitWouldMiss",  outsideCbomkitRules);   // kept for the UI; = outside CBOMkit's JCA rules
            result.put("cbomkitExpected",   all.size() - outsideCbomkitRules);
            result.put("javaFilesScanned",  scanner.getJavaFilesScanned());
            result.put("parseFailures",     scanner.getParseFailures());
            result.put("byContext",         Map.of(
                "main",   all.stream().filter(f -> "main".equals(f.context)).count(),
                "sample", all.stream().filter(f -> "sample".equals(f.context)).count(),
                "docs",   all.stream().filter(f -> "docs".equals(f.context)).count()));

            // Layer breakdown
            result.put("layer1",            all.stream().filter(f -> f.layer.startsWith("L1")).count());
            result.put("layer2",            all.stream().filter(f -> f.layer.startsWith("L2")).count());
            result.put("layer3",            all.stream().filter(f -> f.layer.startsWith("L3")).count());
            result.put("layer4",            all.stream().filter(f -> f.layer.startsWith("L4")).count());

            // Layer 4 breakdown — how many your scanner finds vs what CBOMkit can detect
            result.put("layer4ActionableVsCbomkit",
                "Your scanner finds " + all.stream().filter(f -> f.layer.startsWith("L4") && !f.severity.equals("INFO")).count() +
                " actionable L4 issues + " + all.stream().filter(f -> f.layer.startsWith("L4") && f.severity.equals("INFO")).count() +
                " INFO inventory entries at L4");

            // Full findings list
            List<Map<String, String>> findingsList = new ArrayList<>();
            for (SpringCryptoScanner.Finding f : all) {
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
                fm.put("context",        f.context);
                fm.put("cbomkitDetects", String.valueOf(f.cbomkitExpected)); // expected from JCA rule coverage
                findingsList.add(fm);
            }
            result.put("findings", findingsList);
            result.put("cbomJson", cbomJson);

            return ResponseEntity.ok(result);

        } finally {
            if (tempDir != null) {
                deleteDirectory(tempDir);
                System.out.println("Temp dir cleaned up.");
            }
        }
    }

    // ── Git helpers — extract commit and branch after clone ───────────────────
    private String getGitCommit(String repoPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "git", "-C", repoPath, "rev-parse", "--short", "HEAD");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return out;
        } catch (Exception e) { return ""; }
    }

    private String getGitBranch(String repoPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "git", "-C", repoPath, "rev-parse", "--abbrev-ref", "HEAD");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return out.isEmpty() ? "main" : out;
        } catch (Exception e) { return "main"; }
    }

    // ── Download CBOM JSON endpoint ───────────────────────────────────────────
    @GetMapping("/download-cbom")
    public ResponseEntity<byte[]> downloadCbom(
            @RequestParam(defaultValue = "project") String project,
            @RequestParam(required = false)          String cbomJson) {

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
