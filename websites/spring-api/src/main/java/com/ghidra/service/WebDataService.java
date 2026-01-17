package com.ghidra.service;

import com.ghidra.model.VersionData;
import com.ghidra.model.BinaryData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class WebDataService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Cacheable(value = "versions", key = "'count'")
    public int getExecutableCount() {
        return jdbcTemplate.queryForObject("SELECT COUNT(*) FROM exetable", Integer.class);
    }

    @Cacheable(value = "versions", key = "'all'")
    public List<VersionData> getVersions() {
        // Use a SQL query that groups executables by parsed version info
        String sql = """
            SELECT
                CASE
                    WHEN name_exec LIKE 'LoD_%' THEN 'LoD'
                    WHEN name_exec LIKE 'Classic_%' THEN 'Classic'
                    WHEN name_exec ~ '^1\\.[0-9]+[a-z]?_' THEN 'Classic'
                    ELSE 'Unknown'
                END AS game_type,
                CASE
                    WHEN name_exec ~ '^(Classic|LoD)_([0-9]+\\.[0-9]+[a-z]?)_' THEN
                        substring(name_exec, '_(\\d+\\.\\d+[a-z]?)_')
                    WHEN name_exec ~ '^(1\\.[0-9]+[a-z]?)_' THEN
                        substring(name_exec, '^(\\d+\\.\\d+[a-z]?)_')
                    ELSE 'Unknown'
                END AS version,
                COUNT(*) as file_count
            FROM exetable
            WHERE name_exec IS NOT NULL
            GROUP BY game_type, version
            ORDER BY game_type, version
        """;

        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
        List<VersionData> versions = new ArrayList<>();

        for (Map<String, Object> row : results) {
            String gameType = (String) row.get("game_type");
            String version = (String) row.get("version");
            Long fileCountLong = (Long) row.get("file_count");
            int fileCount = fileCountLong.intValue();

            // Determine if it's LoD
            boolean isLod = "LoD".equals(gameType) ||
                           (version != null && version.matches("1\\.(0[7-9]|1[0-9]).*"));

            // Generate raw PE version
            String rawPeVersion = convertVersionToPeFormat(version);

            // Create folder name
            String folderName = gameType + "/" + version;

            VersionData versionData = VersionData.builder()
                .folderName(folderName)
                .gameType(gameType)
                .version(version)
                .fileCount(fileCount)
                .changeCount(fileCount)
                .isLod(isLod)
                .rawPeVersion(rawPeVersion)
                .totalSizeReadable(null)
                .nocdStatus(null)
                .build();

            versions.add(versionData);
        }

        return versions;
    }

    @Cacheable(value = "binaries", key = "#gameType + '_' + #version")
    public List<BinaryData> getBinariesForVersion(String gameType, String version) {
        String sql = """
            SELECT
                name_exec,
                md5,
                architecture,
                ingest_date
            FROM exetable
            WHERE name_exec LIKE ?
            ORDER BY name_exec
        """;

        // Match actual naming convention: "Classic_1.00_D2Game.dll" or "LoD_1.07_D2Game.dll"
        String pattern = gameType + "_" + version + "_%";
        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, pattern);
        List<BinaryData> binaries = new ArrayList<>();

        for (Map<String, Object> row : results) {
            String nameExec = (String) row.get("name_exec");
            String md5 = (String) row.get("md5");
            Object archObj = row.get("architecture");
            Integer architecture = null;
            if (archObj instanceof String) {
                architecture = "x86".equals(archObj) ? 32 : 64;
            } else if (archObj instanceof Integer) {
                architecture = (Integer) archObj;
            }

            // Convert Timestamp to ZonedDateTime
            ZonedDateTime ingestDate = null;
            Object ingestDateObj = row.get("ingest_date");
            if (ingestDateObj instanceof java.sql.Timestamp) {
                ingestDate = ((java.sql.Timestamp) ingestDateObj).toInstant()
                    .atZone(java.time.ZoneId.systemDefault());
            }

            // Extract file name from name_exec (e.g., "Classic_1.00_D2Game.dll" -> "D2Game.dll")
            String fileName = extractFileName(nameExec);
            String fileType = extractFileExtension(fileName);
            String category = categorizeFile(fileName);

            BinaryData binary = BinaryData.builder()
                .fileName(fileName)
                .fullName(nameExec)
                .md5(md5)
                .architecture(architecture)
                .ingestDate(ingestDate)
                .gameType(gameType)
                .version(version)
                .fileType(fileType)
                .category(category)
                .build();

            binaries.add(binary);
        }

        return binaries;
    }

    private String extractFileName(String nameExec) {
        // Extract file name from "GameType_Version_FileName.ext" format
        String[] parts = nameExec.split("_", 3);
        if (parts.length >= 3) {
            return parts[2];
        }
        return nameExec;
    }

    private String extractFileExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot > 0) {
            return fileName.substring(lastDot + 1);
        }
        return "";
    }

    private String categorizeFile(String fileName) {
        String lowerName = fileName.toLowerCase();

        if (lowerName.contains("d2game") || lowerName.contains("d2common") || lowerName.contains("d2server")) {
            return "Game Logic";
        } else if (lowerName.contains("d2gdi") || lowerName.contains("d2glide") || lowerName.contains("d2ddraw") || lowerName.contains("d2direct3d")) {
            return "Graphics";
        } else if (lowerName.contains("d2sound") || lowerName.contains("audio")) {
            return "Audio";
        } else if (lowerName.contains("d2mcpclient") || lowerName.contains("d2net") || lowerName.contains("network")) {
            return "Network";
        } else if (lowerName.contains("d2launch") || lowerName.contains("diablo") || lowerName.contains("game.exe")) {
            return "Launcher";
        } else if (lowerName.contains("bnclient") || lowerName.contains("storm")) {
            return "MPQ";
        } else if (lowerName.contains("d2win") || lowerName.contains("d2lang") || lowerName.contains("d2char")) {
            return "Utility";
        } else {
            return "Other";
        }
    }

    @Cacheable(value = "categories", key = "'all'")
    public Map<String, Object> getCategories() {
        // Return basic file categories structure
        Map<String, Object> categories = new HashMap<>();
        categories.put("Game Logic", Map.of("color", "#00FF00", "short", "GL"));
        categories.put("Graphics", Map.of("color", "#6969FF", "short", "GR"));
        categories.put("Audio", Map.of("color", "#A59263", "short", "AU"));
        categories.put("Network", Map.of("color", "#FF6600", "short", "NW"));
        categories.put("Launcher", Map.of("color", "#FFFF00", "short", "LA"));
        categories.put("MPQ", Map.of("color", "#C7B377", "short", "MPQ"));
        categories.put("Utility", Map.of("color", "#808080", "short", "UT"));
        categories.put("Other", Map.of("color", "#FFFFFF", "short", "OT"));
        return categories;
    }

    @Cacheable(value = "fileHistory", key = "'all'")
    public Map<String, Object> getFileHistory() {
        // Placeholder - would need to implement based on file tracking
        return new HashMap<>();
    }

    @Cacheable(value = "diffs", key = "'all'")
    public Map<String, Object> getDiffs() {
        // Placeholder - would need version comparison logic
        return new HashMap<>();
    }

    @Cacheable(value = "exports", key = "'all'")
    public Map<String, Object> getExports() {
        // Placeholder - would need PE export analysis
        return new HashMap<>();
    }

    @Cacheable(value = "textContent", key = "'all'")
    public Map<String, Object> getTextContent() {
        // Placeholder - would need text file content storage
        return new HashMap<>();
    }

    @Cacheable(value = "functionIndex", key = "'all'")
    public Map<String, Object> getFunctionIndex() {
        // Get list of available executables for function data
        String sql = "SELECT DISTINCT name_exec FROM exetable ORDER BY name_exec";
        List<String> executables = jdbcTemplate.queryForList(sql, String.class);

        Map<String, Object> index = new HashMap<>();
        Map<String, String> files = new HashMap<>();

        for (String exe : executables) {
            files.put(exe, exe.replace(".dll", "").replace(".exe", ""));
        }

        index.put("files", files);
        index.put("generated", new Date().toString());

        return index;
    }

    /**
     * Get cross-version function data for a specific binary file.
     * Returns functions with addresses across all versions, handling Classic/LoD deduplication.
     * DLLs are shared between Classic and LoD (except for .exe files), so we use unique version numbers.
     */
    @Cacheable(value = "crossVersionFunctions", key = "#filename")
    public Map<String, Object> getCrossVersionFunctions(String filename) {
        // Get all executables matching this filename pattern (e.g., *_D2Client.dll)
        String executablesSql = """
            SELECT
                e.id,
                e.name_exec,
                e.md5
            FROM exetable e
            WHERE e.name_exec LIKE ?
            ORDER BY e.name_exec
        """;

        String filenamePattern = "%_" + filename;
        List<Map<String, Object>> executables = jdbcTemplate.queryForList(executablesSql, filenamePattern);

        if (executables.isEmpty()) {
            Map<String, Object> emptyResponse = new HashMap<>();
            emptyResponse.put("filename", filename);
            emptyResponse.put("versions", new ArrayList<>());
            emptyResponse.put("functions", new HashMap<>());
            emptyResponse.put("error", "No executables found matching " + filename);
            return emptyResponse;
        }

        // Build version list - deduplicate by using unique version numbers
        // Classic and LoD share DLLs (same binary), so we only need one column per version number
        Map<String, Long> versionToExeId = new LinkedHashMap<>(); // Preserve insertion order
        Map<String, String> versionToMd5 = new HashMap<>();
        List<String> allVersions = new ArrayList<>();
        boolean isExe = filename.toLowerCase().endsWith(".exe");

        for (Map<String, Object> exe : executables) {
            String nameExec = (String) exe.get("name_exec");
            Long exeId = (Long) exe.get("id");
            String md5 = (String) exe.get("md5");

            // Parse version from name: Classic_1.00_D2Client.dll -> 1.00
            String[] parts = nameExec.split("_");
            if (parts.length >= 3) {
                String gameType = parts[0]; // Classic or LoD
                String version = parts[1];  // 1.00, 1.07, etc.

                // For .exe files, include gameType in the key (they differ between Classic/LoD)
                // For .dll files, just use version number (same binary shared)
                String versionKey = isExe ? (gameType + "/" + version) : version;

                // Only add if we haven't seen this version (or if it's an exe, which can differ)
                if (!versionToExeId.containsKey(versionKey)) {
                    versionToExeId.put(versionKey, exeId);
                    versionToMd5.put(versionKey, md5);
                    allVersions.add(versionKey);
                }
            }
        }

        // Sort versions naturally (1.00, 1.01, 1.02, ..., 1.10, 1.11, etc.)
        allVersions.sort((a, b) -> {
            // Extract numeric version for comparison
            String verA = a.contains("/") ? a.split("/")[1] : a;
            String verB = b.contains("/") ? b.split("/")[1] : b;
            return compareVersions(verA, verB);
        });

        // Get all function data for these executables
        String functionsSql = """
            SELECT
                d.name_func,
                d.addr,
                d.flags,
                e.id as exe_id,
                e.name_exec
            FROM desctable d
            JOIN exetable e ON d.id_exe = e.id
            WHERE e.name_exec LIKE ?
            ORDER BY d.name_func, e.name_exec
        """;

        List<Map<String, Object>> functionResults = jdbcTemplate.queryForList(functionsSql, filenamePattern);

        // Build function map: function_name -> { name, addresses: { version: address }, category }
        Map<String, Map<String, Object>> functionsMap = new LinkedHashMap<>();

        for (Map<String, Object> row : functionResults) {
            String funcName = (String) row.get("name_func");
            Long addr = (Long) row.get("addr");
            String nameExec = (String) row.get("name_exec");

            // Parse version from executable name
            String[] parts = nameExec.split("_");
            if (parts.length < 3) continue;

            String gameType = parts[0];
            String version = parts[1];
            String versionKey = isExe ? (gameType + "/" + version) : version;

            // Initialize function entry if not exists
            functionsMap.computeIfAbsent(funcName, k -> {
                Map<String, Object> funcData = new LinkedHashMap<>();
                funcData.put("name", funcName);
                funcData.put("category", categorizeFunctionName(funcName));
                funcData.put("addresses", new LinkedHashMap<String, String>());
                return funcData;
            });

            // Add address for this version
            @SuppressWarnings("unchecked")
            Map<String, String> addresses = (Map<String, String>) functionsMap.get(funcName).get("addresses");
            addresses.put(versionKey, "0x" + String.format("%08x", addr).toUpperCase());
        }

        // Build response
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("filename", filename);
        response.put("versions", allVersions);
        response.put("versionMd5s", versionToMd5);
        response.put("functions", functionsMap);
        response.put("functionCount", functionsMap.size());
        response.put("versionCount", allVersions.size());
        response.put("isExe", isExe);
        response.put("generated", new Date().toString());

        return response;
    }

    /**
     * Compare version strings like "1.00", "1.07", "1.13d" naturally
     */
    private int compareVersions(String v1, String v2) {
        // Extract numeric parts
        String num1 = v1.replaceAll("[^0-9.]", "");
        String num2 = v2.replaceAll("[^0-9.]", "");

        String[] parts1 = num1.split("\\.");
        String[] parts2 = num2.split("\\.");

        for (int i = 0; i < Math.max(parts1.length, parts2.length); i++) {
            int p1 = (i < parts1.length && !parts1[i].isEmpty()) ? Integer.parseInt(parts1[i]) : 0;
            int p2 = (i < parts2.length && !parts2[i].isEmpty()) ? Integer.parseInt(parts2[i]) : 0;
            if (p1 != p2) return p1 - p2;
        }

        // If numeric parts are equal, compare the suffix (e.g., "a", "b", "c")
        String suffix1 = v1.replaceAll("[0-9.]", "");
        String suffix2 = v2.replaceAll("[0-9.]", "");
        return suffix1.compareTo(suffix2);
    }

    @Cacheable(value = "functions", key = "#filename")
    public Map<String, Object> getFunctions(String filename) {
        // Get function data for specific executable
        String sql = """
            SELECT
                d.name_func,
                d.addr,
                d.flags,
                e.name_exec,
                e.architecture
            FROM desctable d
            JOIN exetable e ON d.id_exe = e.id
            WHERE e.name_exec = ? OR e.name_exec = ?
            ORDER BY d.addr
        """;

        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql,
            filename, filename + ".dll");

        Map<String, Object> functions = new HashMap<>();

        for (Map<String, Object> row : results) {
            String funcName = (String) row.get("name_func");
            Long addr = (Long) row.get("addr");

            Map<String, Object> funcData = new HashMap<>();
            funcData.put("name", funcName);
            funcData.put("address", "0x" + Long.toHexString(addr));
            funcData.put("rva", addr);
            funcData.put("architecture", row.get("architecture"));

            functions.put(funcName + "_" + Long.toHexString(addr), funcData);
        }

        return functions;
    }

    // Helper class for version parsing
    private static class VersionInfo {
        String folderName;
        String gameType;
        String version;
        boolean isLod;
        String rawPeVersion;

        VersionInfo(String folderName, String gameType, String version, boolean isLod, String rawPeVersion) {
            this.folderName = folderName;
            this.gameType = gameType;
            this.version = version;
            this.isLod = isLod;
            this.rawPeVersion = rawPeVersion;
        }
    }

    private VersionInfo parseVersionFromExecutableName(String exeName) {
        // Parse the format: {GameType}_{Version}_{FileName}.{ext}
        // Examples: Classic_1.06b_D2Win.dll, LoD_1.13d_D2Glide.dll

        // Default values
        String gameType = "Classic";
        String version = "Unknown";
        boolean isLod = false;
        String rawPeVersion = "1, 0, 0, 0";

        // Debug logging
        System.out.println("Parsing executable: " + exeName);

        // Split the executable name by underscores
        String[] parts = exeName.split("_");

        if (parts.length >= 2) {
            // Extract game type from first part
            String firstPart = parts[0].trim();
            if (!firstPart.isEmpty()) {
                gameType = firstPart;
            }

            // Extract version from second part
            String secondPart = parts[1].trim();
            if (!secondPart.isEmpty()) {
                version = secondPart;
            }

            // Determine if it's LoD based on game type or version patterns
            if ("LoD".equalsIgnoreCase(gameType)) {
                isLod = true;
            } else if (version.matches("1\\.(0[7-9]|1[0-9]).*")) {
                // Version 1.07 and above are LoD (1.07, 1.08, 1.09, 1.10, 1.11, 1.12, 1.13, 1.14, etc.)
                isLod = true;
            }

            // Generate raw PE version based on version string
            if (!version.equals("Unknown")) {
                rawPeVersion = convertVersionToPeFormat(version);
            }
        } else {
            // If we can't parse the name, try to extract some info from the filename itself
            if (exeName.toLowerCase().contains("lod")) {
                gameType = "LoD";
                isLod = true;
            }
            // Try to find version patterns in the filename
            java.util.regex.Pattern versionPattern = java.util.regex.Pattern.compile("1\\.(\\d{2}[a-z]?)");
            java.util.regex.Matcher matcher = versionPattern.matcher(exeName);
            if (matcher.find()) {
                version = matcher.group();
                if (version.matches("1\\.(0[7-9]|1[0-9]).*")) {
                    isLod = true;
                }
                rawPeVersion = convertVersionToPeFormat(version);
            }
        }

        String folderName = gameType + "/" + version;

        // Debug logging
        System.out.println("Parsed result - gameType: " + gameType + ", version: " + version + ", isLod: " + isLod + ", folderName: " + folderName);

        return new VersionInfo(folderName, gameType, version, isLod, rawPeVersion);
    }

    private String convertVersionToPeFormat(String version) {
        // Convert version like "1.07" or "1.13d" to PE format "1, 0, 7, 0" or "1, 0, 13, 0"
        try {
            if (version.matches("1\\.(\\d{2})[a-z]?")) {
                String[] parts = version.replace("1.", "").replaceAll("[a-z]", "").split("\\.");
                if (parts.length > 0) {
                    int minorVersion = Integer.parseInt(parts[0]);
                    return "1, 0, " + minorVersion + ", 0";
                }
            }
        } catch (NumberFormatException e) {
            // Fall back to default
        }
        return "1, 0, 0, 0";
    }

    private int compareVersionStrings(String v1, String v2) {
        // Simple version comparison - you might want to make this more sophisticated
        return v1.compareTo(v2);
    }

    public Map<String, Object> getFileDetails(String gameType, String version, String filename) {
        // Get basic file information
        String sql = """
            SELECT
                e.name_exec,
                e.md5,
                e.architecture,
                e.ingest_date,
                COUNT(d.id) as function_count
            FROM exetable e
            LEFT JOIN desctable d ON e.id = d.id_exe
            WHERE e.name_exec LIKE ?
            GROUP BY e.id, e.name_exec, e.md5, e.architecture, e.ingest_date
        """;

        String pattern = gameType + "_" + version + "_" + filename;
        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, pattern);

        if (results.isEmpty()) {
            throw new RuntimeException("File not found");
        }

        Map<String, Object> result = results.get(0);

        // Get function details for this file
        String funcSql = """
            SELECT
                d.name_func,
                d.addr,
                d.flags
            FROM desctable d
            JOIN exetable e ON d.id_exe = e.id
            WHERE e.name_exec = ?
            ORDER BY d.addr
        """;

        List<Map<String, Object>> functions = jdbcTemplate.queryForList(funcSql, pattern);

        // Build response
        Map<String, Object> fileDetails = new HashMap<>();
        fileDetails.put("filename", filename);
        fileDetails.put("fullName", result.get("name_exec"));
        fileDetails.put("gameType", gameType);
        fileDetails.put("version", version);
        fileDetails.put("md5", result.get("md5"));
        fileDetails.put("architecture", result.get("architecture"));
        fileDetails.put("ingestDate", result.get("ingest_date"));
        fileDetails.put("functionCount", result.get("function_count"));
        fileDetails.put("category", categorizeFile(filename));
        fileDetails.put("functions", functions);

        return fileDetails;
    }

    @Cacheable(value = "crossVersionAnalysis", key = "#filename")
    public Map<String, Object> getCrossVersionFunctionAnalysis(String filename) {
        // Get available versions for this filename pattern
        String versionsSql = """
            SELECT DISTINCT
                name_exec,
                game_type,
                version,
                md5
            FROM cross_version_functions
            WHERE name_exec LIKE ?
            ORDER BY game_type, version
        """;

        String filenamePattern = "%_" + filename;
        List<Map<String, Object>> versions = jdbcTemplate.queryForList(versionsSql, filenamePattern);

        // Get function evolution data using our optimized view
        String functionsSql = """
            SELECT
                fe.name_func,
                fe.version_count,
                fe.versions,
                cvf.function_id,
                cvf.addr,
                cvf.name_exec,
                cvf.game_type,
                cvf.version,
                cvf.id_signature
            FROM function_evolution fe
            JOIN cross_version_functions cvf ON cvf.name_func = fe.name_func
            WHERE cvf.name_exec LIKE ?
            ORDER BY fe.version_count DESC, fe.name_func, cvf.game_type, cvf.version
        """;

        List<Map<String, Object>> functionResults = jdbcTemplate.queryForList(functionsSql, filenamePattern);

        // Build cross-version function map
        Map<String, Map<String, Object>> functionsMap = new HashMap<>();

        for (Map<String, Object> row : functionResults) {
            String funcName = (String) row.get("name_func");
            String gameType = (String) row.get("game_type");
            String version = (String) row.get("version");
            String versionKey = gameType + "/" + version;
            Long addr = (Long) row.get("addr");

            functionsMap.computeIfAbsent(funcName, k -> new HashMap<>());

            Map<String, Object> funcData = functionsMap.get(funcName);
            if (!funcData.containsKey("versions")) {
                funcData.put("versions", new HashMap<>());
                funcData.put("name", funcName);
                funcData.put("category", categorizeFunctionName(funcName));
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> versionMap = (Map<String, Object>) funcData.get("versions");

            Map<String, Object> versionData = new HashMap<>();
            versionData.put("address", "0x" + Long.toHexString(addr));
            versionData.put("rva", addr);
            versionData.put("flags", row.get("flags"));

            versionMap.put(versionKey, versionData);
        }

        // Build response
        Map<String, Object> response = new HashMap<>();
        response.put("filename", filename);
        response.put("versions", versions);
        response.put("functions", functionsMap);
        response.put("generated", new Date().toString());

        return response;
    }

    private String categorizeFunctionName(String funcName) {
        String lowerName = funcName.toLowerCase();

        // Exception handling
        if (lowerName.contains("exception") || lowerName.contains("__except") ||
            lowerName.contains("_eh") || lowerName.startsWith("_c_specific_handler")) {
            return "EH";
        }

        // Import functions (typically start with __imp_)
        if (lowerName.startsWith("__imp_") || lowerName.startsWith("imp_")) {
            return "IMP";
        }

        // CRT/Library functions
        if (lowerName.startsWith("_") && (lowerName.contains("crt") || lowerName.contains("main") ||
            lowerName.contains("malloc") || lowerName.contains("free") || lowerName.contains("printf") ||
            lowerName.contains("scanf") || lowerName.contains("str") || lowerName.contains("mem"))) {
            return "CRT";
        }

        // Game logic functions (D2 specific patterns)
        if (lowerName.startsWith("d2") || lowerName.contains("game") || lowerName.contains("player") ||
            lowerName.contains("item") || lowerName.contains("skill") || lowerName.contains("monster")) {
            return "Game";
        }

        return "Game"; // Default to game functions
    }

    public Map<String, Object> getFunctionSimilarityAnalysis(String filename, double similarityThreshold, double confidenceThreshold, int limit) {
        // Query actual function_similarity_matrix data populated by Step4
        String sql = """
            SELECT
                sf.name_func as source_function,
                tf.name_func as target_function,
                se.name_exec as source_executable,
                te.name_exec as target_executable,
                fsm.similarity_score,
                fsm.confidence_score,
                fsm.match_type
            FROM function_similarity_matrix fsm
            JOIN desctable sf ON fsm.source_function_id = sf.id
            JOIN exetable se ON sf.id_exe = se.id
            JOIN desctable tf ON fsm.target_function_id = tf.id
            JOIN exetable te ON tf.id_exe = te.id
            WHERE se.name_exec = ?
                AND fsm.similarity_score >= ?
                AND fsm.confidence_score >= ?
            ORDER BY fsm.similarity_score DESC, fsm.confidence_score DESC
            LIMIT ?
        """;

        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, filename, similarityThreshold, confidenceThreshold, limit);

        // Build response with real similarity analysis
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> similarityData = new HashMap<>();

        for (Map<String, Object> row : results) {
            String sourceFunction = (String) row.get("source_function");
            String targetFunction = (String) row.get("target_function");
            String targetExecutable = (String) row.get("target_executable");
            Double similarity = (Double) row.get("similarity_score");
            Double confidence = (Double) row.get("confidence_score");
            String matchType = (String) row.get("match_type");

            String matchKey = sourceFunction + " -> " + targetFunction;
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("source_function", sourceFunction);
            functionInfo.put("target_function", targetFunction);
            functionInfo.put("target_executable", targetExecutable);
            functionInfo.put("similarity_score", Math.round(similarity * 1000.0) / 1000.0);
            functionInfo.put("confidence_score", Math.round(confidence * 10.0) / 10.0);
            functionInfo.put("match_type", matchType);

            similarityData.put(matchKey, functionInfo);
        }

        response.put("filename", filename);
        response.put("similarity_threshold", similarityThreshold);
        response.put("confidence_threshold", confidenceThreshold);
        response.put("matches", similarityData);
        response.put("total_matches", results.size());
        response.put("generated", new Date().toString());
        response.put("cache_enabled", true);

        return response;
    }
}