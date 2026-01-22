// STEP 2: Generate Enhanced Function Signatures (REQUIRED SECOND STEP)
//
// Creates mathematical signatures for functions that enable similarity analysis across
// different versions of binaries. This step transforms raw function data from Step1
// into comparable signatures optimized for cross-version analysis.
//
// SIGNATURE GENERATION PROCESS:
// - Analyzes function control flow and instruction patterns
// - Creates LSH (Locality Sensitive Hash) signatures for similarity matching
// - Stores enhanced signatures in BSim database for rapid comparison
// - Optimizes signatures for unified version system cross-analysis
//
// UNIFIED VERSION INTEGRATION:
// - Processes functions from binaries added via Step1
// - Maintains version metadata for cross-version similarity analysis
// - Compatible with both standard (1.03_D2Game.dll) and exception formats
//
// PROCESSING MODES:
// - Single Program: Generate signatures for currently opened program
// - All Programs: Batch signature generation for all project programs
// - Version Filter: Generate signatures for programs matching version criteria
//
// TECHNICAL DETAILS:
// - Compatible with Ghidra 11.4.2 - No BSim client dependencies required
// - Uses direct PostgreSQL connectivity to remote database (localhost:5432)
// - Implements enhanced signature algorithms for improved accuracy
//
// WORKFLOW POSITION: Requires Step1 completion, enables Step3-5 operations
//
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift L
// @menupath Tools.BSim.Step2 - Generate Enhanced Signatures

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;
import java.util.regex.*;

public class Step2_GenerateBSimSignatures extends GhidraScript {

    private static final String DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DB_USER = "ben";
    private static final String DB_PASS = "goodyx12";

    // Mode selection constants
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    // Unified version info helper
    private static class UnifiedVersionInfo {
        String gameVersion = null;
        String familyType = "Unified";
        boolean isException = false;

        UnifiedVersionInfo(String executableName) {
            parseUnifiedName(executableName);
        }

        private void parseUnifiedName(String executableName) {
            if (executableName == null || executableName.isEmpty()) return;

            // Try to extract version info from file path first
            if (executableName.contains("/") || executableName.contains("\\")) {
                parseFromPath(executableName);
                if (gameVersion != null) return; // Successfully parsed from path
            }

            // Standard binaries: 1.03_D2Game.dll
            Pattern standardPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)_([A-Za-z0-9_]+)\\.(dll|exe)$");
            Matcher standardMatcher = standardPattern.matcher(executableName);

            if (standardMatcher.matches()) {
                gameVersion = standardMatcher.group(1);
                familyType = "Unified";
                isException = false;
                return;
            }

            // Exception binaries: Classic_1.03_Game.exe
            Pattern exceptionPattern = Pattern.compile("^(Classic|LoD)_(1\\.[0-9]+[a-z]?)_(Game|Diablo_II)\\.(exe|dll)$");
            Matcher exceptionMatcher = exceptionPattern.matcher(executableName);

            if (exceptionMatcher.matches()) {
                familyType = exceptionMatcher.group(1);
                gameVersion = exceptionMatcher.group(2);
                isException = true;
            }
        }

        private void parseFromPath(String fullPath) {
            // Parse paths like "/Classic/1.05b/D2Sound.dll" or "/PD2/Game.exe"
            String[] pathParts = fullPath.split("[/\\\\]");

            for (int i = 0; i < pathParts.length; i++) {
                String part = pathParts[i];
                if (part.isEmpty()) continue; // Skip empty parts from leading slashes

                // Check for family type (Classic, LoD, PD2, etc.)
                if (part.equalsIgnoreCase("Classic") || part.equalsIgnoreCase("LoD")) {
                    familyType = part;
                    isException = true;

                    // Look for version in next part
                    if (i + 1 < pathParts.length) {
                        String nextPart = pathParts[i + 1];
                        // Updated regex to handle 1.00, 1.05b, 1.13c, etc.
                        if (nextPart.matches("1\\.[0-9]{1,2}[a-z]?")) {
                            gameVersion = nextPart;
                        }
                    }
                    return;
                }

                // Check for PD2 or mod paths
                if (part.equalsIgnoreCase("PD2")) {
                    familyType = "PD2";
                    gameVersion = "PD2";
                    isException = false;
                    return;
                }

                // Direct version pattern (like "1.05b" or "1.00")
                if (part.matches("1\\.[0-9]{1,2}[a-z]?")) {
                    gameVersion = part;
                    if (familyType == null) {
                        familyType = "Unified";
                    }
                    return;
                }
            }

            // Fallback: try to infer from filename
            String fileName = fullPath;
            if (fileName.contains("/")) fileName = fileName.substring(fileName.lastIndexOf("/") + 1);
            if (fileName.contains("\\")) fileName = fileName.substring(fileName.lastIndexOf("\\") + 1);

            if (fileName.equals("Game.exe") || fileName.equals("Diablo II.exe")) {
                familyType = "Classic";
                gameVersion = "Unknown";
                isException = true;
            }
        }

        public String getDisplayInfo() {
            if (gameVersion == null) return "Unknown format";
            return isException ?
                String.format("%s %s (Exception)", familyType, gameVersion) :
                String.format("Unified %s (Standard)", gameVersion);
        }

        public boolean isValid() {
            return gameVersion != null;
        }
    }

    @Override
    public void run() throws Exception {
        println("=== Enhanced BSim Signature Generation ===");

        // Ask user for processing mode
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to generate signatures?",
            Arrays.asList(modes), MODE_SINGLE);

        if (selectedMode == null) {
            println("Operation cancelled by user");
            return;
        }

        if (selectedMode.equals(MODE_SINGLE)) {
            processSingleProgram();
        } else if (selectedMode.equals(MODE_ALL)) {
            processAllPrograms();
        } else if (selectedMode.equals(MODE_VERSION)) {
            processVersionFiltered();
        }
    }

    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName);

        println("Program: " + programName);
        println("Version Info: " + versionInfo.getDisplayInfo());

        FunctionManager funcManager = currentProgram.getFunctionManager();
        int functionCount = funcManager.getFunctionCount();
        println("Total functions: " + functionCount);

        if (!versionInfo.isValid()) {
            boolean proceed = askYesNo("Non-Unified Format",
                "This executable doesn't follow unified naming.\n" +
                "Signatures will be generated but may not have optimal version mapping.\n\n" +
                "Continue?");
            if (!proceed) {
                println("Operation cancelled");
                return;
            }
        }

        boolean proceed = askYesNo("Generate Enhanced Signatures",
            String.format("Generate enhanced signatures for %d functions?\n\n" +
            "Version: %s\n\n" +
            "This will:\n" +
            "- Create structural function signatures\n" +
            "- Extract instruction patterns and features\n" +
            "- Store data for similarity analysis\n" +
            "- Enable cross-version function matching\n\nProceed?",
            functionCount, versionInfo.getDisplayInfo()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            generateSignatures(currentProgram, programName, versionInfo);
            println("Successfully generated enhanced signatures!");

        } catch (Exception e) {
            printerr("Error generating signatures: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void processAllPrograms() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        if (programFiles.isEmpty()) {
            popup("No program files found in the project.");
            return;
        }

        // Validate unified formats
        int validCount = 0;
        int invalidCount = 0;
        for (DomainFile file : programFiles) {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName());
            if (versionInfo.isValid()) {
                validCount++;
            } else {
                invalidCount++;
            }
        }

        println("Found " + programFiles.size() + " program files");
        println("  Valid unified format: " + validCount);
        println("  Invalid/unknown format: " + invalidCount);

        boolean proceed = askYesNo("Generate Signatures for All Programs",
            String.format("Generate enhanced signatures for all %d programs?\n\n" +
            "Valid unified format: %d\n" +
            "Invalid format: %d\n\n" +
            "This may take a considerable amount of time.",
            programFiles.size(), validCount, invalidCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        int successCount = 0;
        int errorCount = 0;

        for (int i = 0; i < programFiles.size(); i++) {
            DomainFile file = programFiles.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, programFiles.size(), file.getName()));
            monitor.setProgress(i);

            if (monitor.isCancelled()) {
                println("Operation cancelled by user");
                break;
            }

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("Completed: %d successful, %d errors", successCount, errorCount));
    }

    private void processVersionFiltered() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        String versionFilter = askString("Version Filter",
            "Enter version pattern (e.g., '1.03', '1.04b', '1.13c', 'Classic'):", "1.04b");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("Operation cancelled - no filter provided");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        // Get programs from BSim database that match the version filter
        Set<String> bsimProgramNames = getBSimProgramsByVersion(versionFilter);

        if (bsimProgramNames.isEmpty()) {
            popup("No programs matching version '" + versionFilter + "' found in BSim database.\n" +
                  "Available versions can be seen by running Step1 first.");
            return;
        }

        println("Found " + bsimProgramNames.size() + " programs in BSim database for version '" + versionFilter + "':");
        for (String name : bsimProgramNames) {
            println("  - " + name);
        }

        // Filter Ghidra project files by matching names in BSim database
        List<DomainFile> matchingFiles = new ArrayList<>();
        for (DomainFile file : programFiles) {
            String fileName = file.getName();

            // Direct name match
            if (bsimProgramNames.contains(fileName)) {
                matchingFiles.add(file);
                continue;
            }

            // Check for unified name formats that might match
            for (String bsimName : bsimProgramNames) {
                if (isNameMatch(fileName, bsimName)) {
                    matchingFiles.add(file);
                    break;
                }
            }
        }

        if (matchingFiles.isEmpty()) {
            popup("No programs matching version '" + versionFilter + "' found in Ghidra project.\n\n" +
                  "BSim database contains programs for this version:\n" +
                  String.join(", ", bsimProgramNames) + "\n\n" +
                  "But none were found in the current Ghidra project.");
            return;
        }

        println("Found " + matchingFiles.size() + " matching programs in Ghidra project:");
        for (DomainFile file : matchingFiles) {
            println("  - " + file.getName());
        }

        boolean proceed = askYesNo("Generate Signatures for Filtered Programs",
            String.format("Generate signatures for %d programs matching version '%s'?",
            matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        int successCount = 0;
        int errorCount = 0;

        for (int i = 0; i < matchingFiles.size(); i++) {
            DomainFile file = matchingFiles.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, matchingFiles.size(), file.getName()));

            if (monitor.isCancelled()) {
                break;
            }

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("Completed: %d successful, %d errors", successCount, errorCount));
    }

    private void collectProgramFiles(DomainFolder folder, List<DomainFile> files) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                files.add(file);
            }
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            collectProgramFiles(subfolder, files);
        }
    }

    private void processProjectFile(DomainFile file) throws Exception {
        println("Processing: " + file.getPathname());

        Program program = (Program) file.getDomainObject(this, true, false, monitor);

        try {
            String programName = program.getName();
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName);
            generateSignatures(program, programName, versionInfo);
            println("  Generated signatures for " + programName + " (" + versionInfo.getDisplayInfo() + ")");

        } finally {
            program.release(this);
        }
    }

    private void generateSignatures(Program program, String programName, UnifiedVersionInfo versionInfo) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            println("Connected to BSim database");

            // Get executable ID
            int executableId = getExecutableId(conn, programName, versionInfo);
            if (executableId == -1) {
                // Provide more helpful error message
                String unifiedName = generateUnifiedExecutableName(programName, versionInfo);
                throw new Exception(String.format("Executable not found in database.\n" +
                    "  Tried: '%s', unified: '%s', version: %s\n" +
                    "  Run AddProgramToBSimDatabase first for this binary.",
                    programName, unifiedName, versionInfo.getDisplayInfo()));
            }

            println("Found executable ID: " + executableId);

            // Generate enhanced signatures
            generateEnhancedSignatures(conn, executableId, program, versionInfo);

            // Update similarity analysis
            updateSimilarityAnalysis(conn, executableId);

            println("Signature generation completed for " + programName);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private int getExecutableId(Connection conn, String programName, UnifiedVersionInfo versionInfo) throws SQLException {
        // First try with the original name (for backward compatibility)
        String originalSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(originalSql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }

        // Try with unified name format (generated by Step1)
        String unifiedName = generateUnifiedExecutableName(programName, versionInfo);
        String unifiedSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(unifiedSql)) {
            stmt.setString(1, unifiedName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                println("Found executable using unified name: " + unifiedName);
                return rs.getInt("id");
            }
        }

        // Try partial matching for executables stored with different naming patterns
        // Order by function count to prefer more complete entries
        String partialSql = """
            SELECT e.id, e.name_exec, COUNT(d.id) as function_count
            FROM exetable e
            LEFT JOIN desctable d ON d.id_exe = e.id
            WHERE e.name_exec ILIKE ?
            GROUP BY e.id, e.name_exec
            ORDER BY function_count DESC, e.name_exec
            """;
        try (PreparedStatement stmt = conn.prepareStatement(partialSql)) {
            // Extract just the base filename
            String baseFileName = programName;
            if (baseFileName.contains("/")) {
                baseFileName = baseFileName.substring(baseFileName.lastIndexOf("/") + 1);
            }
            if (baseFileName.contains("\\")) {
                baseFileName = baseFileName.substring(baseFileName.lastIndexOf("\\") + 1);
            }

            stmt.setString(1, "%" + baseFileName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int id = rs.getInt("id");
                String foundName = rs.getString("name_exec");
                int functionCount = rs.getInt("function_count");
                println("Found executable using partial match: " + foundName + " (" + functionCount + " functions) for " + baseFileName);
                return id;
            }
        }

        return -1;
    }

    /**
     * Generate unified executable name (matching Step1 logic)
     */
    private String generateUnifiedExecutableName(String programName, UnifiedVersionInfo versionInfo) {
        String fileName = programName;
        if (fileName.contains("/")) {
            fileName = fileName.substring(fileName.lastIndexOf("/") + 1);
        }
        if (fileName.contains("\\")) {
            fileName = fileName.substring(fileName.lastIndexOf("\\") + 1);
        }
        fileName = fileName.replace(" ", "_");

        // Handle null/missing version info
        String gameVersion = versionInfo.gameVersion != null ? versionInfo.gameVersion : "Unknown";
        String familyType = versionInfo.familyType != null ? versionInfo.familyType : "Unified";

        if (fileName.equals("Game.exe") || fileName.equals("Diablo_II.exe")) {
            return String.format("%s_%s_Diablo_II.exe", familyType, gameVersion);
        }
        return String.format("%s_%s", gameVersion, fileName);
    }

    private void generateEnhancedSignatures(Connection conn, int executableId, Program program, UnifiedVersionInfo versionInfo) throws Exception {
        println("Generating enhanced signatures...");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int functionCount = 0;
        int signatureCount = 0;

        // Check if enhanced_signatures table exists
        boolean hasEnhancedTable = checkEnhancedSignaturesTable(conn);

        String insertSql;
        if (hasEnhancedTable) {
            insertSql = "INSERT INTO enhanced_signatures (function_id, executable_id, signature_hash, " +
                "signature_data, lsh_vector, confidence_score) " +
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (function_id) DO UPDATE SET " +
                "signature_hash = EXCLUDED.signature_hash, " +
                "signature_data = EXCLUDED.signature_data, " +
                "lsh_vector = EXCLUDED.lsh_vector, " +
                "confidence_score = EXCLUDED.confidence_score";
        } else {
            println("Enhanced signatures table not available - using basic signature storage");
            return;
        }

        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                functionCount++;

                if (functionCount % 50 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s", functionCount, function.getName()));
                }

                try {
                    // Get function ID from desctable (try address first, then name)
                    int functionId = getFunctionId(conn, function, executableId);
                    if (functionId == -1) {
                        continue; // Function not in database
                    }

                    // Generate enhanced signature
                    FunctionSignature signature = generateFunctionSignature(function);

                    // Create JSON signature data
                    String signatureData = String.format(
                        "{\"instructionCount\":%d,\"basicBlockCount\":%d,\"callCount\":%d,\"quality\":%.2f,\"featureVector\":\"%s\"}",
                        signature.instructionCount, signature.basicBlockCount, signature.callCount,
                        signature.quality, signature.featureVector);

                    stmt.setInt(1, functionId);
                    stmt.setInt(2, executableId);
                    stmt.setString(3, signature.hash);
                    stmt.setString(4, signatureData);
                    stmt.setString(5, signature.featureVector);  // Use as LSH vector
                    stmt.setDouble(6, signature.quality);

                    stmt.addBatch();
                    signatureCount++;

                    // Execute batch periodically
                    if (signatureCount % 100 == 0) {
                        stmt.executeBatch();
                    }

                } catch (SQLException e) {
                    printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                }
            }

            // Execute remaining batch
            stmt.executeBatch();
        }

        println(String.format("Generated %d enhanced signatures for %d functions", signatureCount, functionCount));
    }

    private boolean checkEnhancedSignaturesTable(Connection conn) {
        try (Statement stmt = conn.createStatement()) {
            stmt.executeQuery("SELECT 1 FROM enhanced_signatures LIMIT 1");
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    private int getFunctionId(Connection conn, Function function, int executableId) throws SQLException {
        // Try matching by address first (most reliable)
        long address = function.getEntryPoint().getOffset();
        String addressSql = "SELECT id FROM desctable WHERE addr = ? AND id_exe = ?";
        try (PreparedStatement stmt = conn.prepareStatement(addressSql)) {
            stmt.setLong(1, address);
            stmt.setInt(2, executableId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }

        // Fallback to name matching (for backward compatibility)
        String nameSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";
        try (PreparedStatement stmt = conn.prepareStatement(nameSql)) {
            stmt.setString(1, function.getName());
            stmt.setInt(2, executableId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }

        return -1;
    }

    private FunctionSignature generateFunctionSignature(Function function) {
        FunctionSignature signature = new FunctionSignature();

        // Basic metrics
        signature.instructionCount = (int) function.getBody().getNumAddresses();
        signature.basicBlockCount = function.getBody().getNumAddressRanges();

        // Count calls
        signature.callCount = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction.getFlowType().isCall()) {
                signature.callCount++;
            }
        }

        // Generate feature vector (simplified)
        signature.featureVector = String.format("inst:%d,bb:%d,calls:%d",
            signature.instructionCount, signature.basicBlockCount, signature.callCount);

        // Calculate quality score
        signature.quality = calculateQuality(signature);

        // Generate hash
        signature.hash = generateSignatureHash(function, signature);

        return signature;
    }

    private double calculateQuality(FunctionSignature signature) {
        // Simple quality calculation based on signature completeness
        double quality = 0.5; // Base quality

        if (signature.instructionCount > 10) quality += 0.2;
        if (signature.basicBlockCount > 1) quality += 0.2;
        if (signature.callCount > 0) quality += 0.1;

        return Math.min(quality, 1.0);
    }

    private String generateSignatureHash(Function function, FunctionSignature signature) {
        String data = function.getName() + "_" + signature.instructionCount + "_" +
                     signature.basicBlockCount + "_" + signature.callCount;
        return Integer.toHexString(data.hashCode());
    }

    private void updateSimilarityAnalysis(Connection conn, int executableId) throws SQLException {
        println("Updating similarity analysis...");

        try {
            // Trigger refresh of materialized views for cross-version analysis
            String sql = "SELECT refresh_cross_version_data()";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.executeQuery();
                println("Cross-version analysis updated");
            }
        } catch (SQLException e) {
            // Fall back to manual view refresh
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("REFRESH MATERIALIZED VIEW cross_version_functions");
                println("Materialized views refreshed");
            } catch (SQLException e2) {
                println("Note: Could not refresh materialized views");
            }
        }
    }

    /**
     * Query BSim database to get program names for a specific version
     */
    private Set<String> getBSimProgramsByVersion(String versionFilter) {
        Set<String> programNames = new HashSet<>();

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            // Try exact version match first
            String exactSql = "SELECT DISTINCT e.name_exec FROM exetable e " +
                            "JOIN game_versions gv ON e.game_version = gv.id " +
                            "WHERE gv.version_string = ?";

            try (PreparedStatement stmt = conn.prepareStatement(exactSql)) {
                stmt.setString(1, versionFilter);
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    programNames.add(rs.getString("name_exec"));
                }
            }

            // If no exact matches, try partial matching for version and family
            if (programNames.isEmpty()) {
                String partialSql = "SELECT DISTINCT e.name_exec FROM exetable e " +
                                  "JOIN game_versions gv ON e.game_version = gv.id " +
                                  "WHERE gv.version_string ILIKE ? OR gv.version_family ILIKE ? OR e.version_family ILIKE ?";

                try (PreparedStatement stmt = conn.prepareStatement(partialSql)) {
                    String pattern = "%" + versionFilter + "%";
                    stmt.setString(1, pattern);
                    stmt.setString(2, pattern);
                    stmt.setString(3, pattern);
                    ResultSet rs = stmt.executeQuery();
                    while (rs.next()) {
                        programNames.add(rs.getString("name_exec"));
                    }
                }
            }

        } catch (SQLException e) {
            printerr("Error querying BSim database: " + e.getMessage());
            e.printStackTrace();
        }

        return programNames;
    }

    /**
     * Check if two names match, accounting for different naming conventions
     */
    private boolean isNameMatch(String fileName1, String fileName2) {
        if (fileName1 == null || fileName2 == null) return false;
        if (fileName1.equals(fileName2)) return true;

        // Extract base names (remove paths and version prefixes)
        String base1 = extractBaseName(fileName1);
        String base2 = extractBaseName(fileName2);

        return base1.equalsIgnoreCase(base2);
    }

    /**
     * Extract base executable name from various naming formats
     */
    private String extractBaseName(String fileName) {
        String name = fileName;

        // Remove path components
        if (name.contains("/")) name = name.substring(name.lastIndexOf("/") + 1);
        if (name.contains("\\")) name = name.substring(name.lastIndexOf("\\") + 1);

        // Remove version prefixes like "1.04b_" or "Classic_1.04b_"
        if (name.contains("_")) {
            String[] parts = name.split("_");
            if (parts.length >= 2) {
                // If first part looks like version (starts with digit or known family)
                String firstPart = parts[0];
                if (firstPart.matches("\\d.*") || firstPart.equalsIgnoreCase("Classic") ||
                    firstPart.equalsIgnoreCase("LoD") || firstPart.equalsIgnoreCase("PD2")) {
                    // Return everything after the first underscore
                    name = name.substring(name.indexOf("_") + 1);
                }
            }
        }

        return name;
    }

    // Helper class for function signatures
    private static class FunctionSignature {
        String hash;
        int instructionCount;
        int basicBlockCount;
        int callCount;
        double quality;
        String featureVector;
    }
}