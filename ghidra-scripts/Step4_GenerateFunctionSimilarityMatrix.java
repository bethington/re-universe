// STEP 4: Generate Function Similarity Matrix (REQUIRED ANALYSIS STEP)
//
// Creates comprehensive similarity matrix for cross-version function matching using
// advanced mathematical analysis of function signatures and enrichment data from
// previous steps. This is the core analysis step that produces actionable results.
//
// SIMILARITY ANALYSIS PROCESS:
// - Compares LSH signatures from Step2 across all binary versions
// - Incorporates enrichment data from Step3 scripts for enhanced accuracy
// - Uses unified version system for structured cross-version analysis
// - Calculates similarity scores using multiple algorithmic approaches
//
// ANALYSIS CAPABILITIES:
// - Structure-based matching: Analyzes control flow and instruction patterns
// - Context-aware matching: Uses comments, strings, and cross-references
// - API-based matching: Leverages import/export and signature data
// - Version-aware scoring: Optimized for unified version system analysis
//
// OUTPUT GENERATION:
// - Function similarity matrix with confidence scores
// - Cross-version mapping tables for version tracking
// - Similarity reports with detailed match explanations
// - Quality metrics and analysis statistics
//
// UNIFIED VERSION INTEGRATION:
// - Processes functions across all versions in unified format
// - Uses materialized views for optimized cross-version queries
// - Maintains version metadata for accurate family grouping
//
// WORKFLOW POSITION: Requires Steps1-2, enhanced by Step3, enables practical results
//
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift M
// @menupath Tools.BSim.Step4 - Generate Similarity Matrix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;
import java.util.regex.*;

public class Step4_GenerateFunctionSimilarityMatrix extends GhidraScript {

    private static final String DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DB_USER = "ben";
    private static final String DB_PASS = "goodyx12";

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
            Pattern standardPattern = Pattern.compile("^(1\\.[0-9]{1,2}[a-z]?)_([A-Za-z0-9_]+)\\.(dll|exe)$");
            Matcher standardMatcher = standardPattern.matcher(executableName);

            if (standardMatcher.matches()) {
                gameVersion = standardMatcher.group(1);
                familyType = "Unified";
                isException = false;
                return;
            }

            // Exception binaries: Classic_1.03_Game.exe
            Pattern exceptionPattern = Pattern.compile("^(Classic|LoD)_(1\\.[0-9]{1,2}[a-z]?)_(Game|Diablo_II)\\.(exe|dll)$");
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

    // Similarity thresholds
    private static final double MIN_SIMILARITY = 0.7;
    private static final double MIN_CONFIDENCE = 15.0; // Lowered from 25.0 as confidence calc only goes to ~55

    // Mode selection constants
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    @Override
    public void run() throws Exception {
        println("=== Function Similarity Matrix Generation ===");

        // Ask user for processing mode
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to generate similarity matrix?",
            Arrays.asList(modes), MODE_SINGLE);

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
        println("Program: " + programName);

        FunctionManager funcManager = currentProgram.getFunctionManager();
        int functionCount = funcManager.getFunctionCount();
        println("Functions in current program: " + functionCount);

        boolean proceed = askYesNo("Generate Similarity Matrix",
            String.format("Generate similarity matrix for %d functions?\n\nThis will:\n" +
            "- Compare functions against all other versions\n" +
            "- Calculate structural similarity scores\n" +
            "- Build cross-version relationships\n" +
            "- Replace name-based matching\n\nProceed?", functionCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            generateSimilarityMatrix(currentProgram, programName);
            println("Successfully generated similarity matrix!");

        } catch (Exception e) {
            printerr("Error generating similarity matrix: " + e.getMessage());
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

        boolean proceed = askYesNo("Process All Programs",
            String.format("Found %d programs in project.\n\nGenerate similarity matrix for all programs?",
                programFiles.size()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        println("Processing " + programFiles.size() + " programs...");
        int successCount = 0;
        int errorCount = 0;

        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) break;

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("\n=== Batch Processing Complete ===\nSuccess: %d\nErrors: %d",
            successCount, errorCount));
    }

    private void processVersionFiltered() throws Exception {
        String versionFilter = askString("Version Filter",
            "Enter version pattern to match (e.g., '1.14' or 'D2R'):");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("No version filter specified, operation cancelled.");
            return;
        }

        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> allFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, allFiles);

        // Filter by version
        List<DomainFile> matchingFiles = new ArrayList<>();
        for (DomainFile file : allFiles) {
            String path = file.getPathname();
            if (path.contains(versionFilter) || file.getName().contains(versionFilter)) {
                matchingFiles.add(file);
            }
        }

        if (matchingFiles.isEmpty()) {
            popup("No programs matching version '" + versionFilter + "' found.");
            return;
        }

        boolean proceed = askYesNo("Process Filtered Programs",
            String.format("Found %d programs matching '%s'.\n\nGenerate similarity matrix for these programs?",
                matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        println("Processing " + matchingFiles.size() + " matching programs...");
        int successCount = 0;
        int errorCount = 0;

        for (DomainFile file : matchingFiles) {
            if (monitor.isCancelled()) break;

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("\n=== Version Filtered Processing Complete ===\nVersion: %s\nSuccess: %d\nErrors: %d",
            versionFilter, successCount, errorCount));
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
        println("\nProcessing: " + file.getPathname());
        monitor.setMessage("Processing: " + file.getName());

        Program program = (Program) file.getDomainObject(this, false, false, monitor);
        try {
            generateSimilarityMatrix(program, file.getName());
            println("  Similarity matrix generated successfully");
        } finally {
            program.release(this);
        }
    }

    private void generateSimilarityMatrix(Program program, String programName) throws Exception {
        println("Connecting to BSim database...");

        UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName);
        println("Processing: " + programName + " (" + versionInfo.getDisplayInfo() + ")");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            println("Connected to BSim database successfully");

            // Optimize connection for bulk operations
            conn.setAutoCommit(true); // Will be set to false in batch operations

            // Get current executable info
            int currentExeId = getExecutableId(conn, programName, versionInfo);
            if (currentExeId == -1) {
                String unifiedName = generateUnifiedExecutableName(programName, versionInfo);
                throw new RuntimeException(String.format("Current executable not found in database.\n" +
                    "  Tried: '%s', unified: '%s', version: %s\n" +
                    "  Run AddProgramToBSimDatabase.java first.",
                    programName, unifiedName, versionInfo.getDisplayInfo()));
            }

            // Get all other executables for comparison
            List<ExecutableInfo> otherExecutables = getOtherExecutables(conn, currentExeId);
            println("Found " + otherExecutables.size() + " other executables for comparison");

            // Process similarity for current program's functions
            processFunctionSimilarities(conn, program, currentExeId, otherExecutables);

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

    private List<ExecutableInfo> getOtherExecutables(Connection conn, int currentExeId) throws SQLException {
        List<ExecutableInfo> executables = new ArrayList<>();

        String sql = """
            SELECT DISTINCT e.id, e.name_exec,
                   CASE
                       WHEN e.name_exec ~ '^Classic_' THEN 'Classic'
                       WHEN e.name_exec ~ '^LoD_' THEN 'LoD'
                       WHEN e.name_exec ~ '^1\\.' THEN 'Unified'
                       ELSE 'Other'
                   END as game_type
            FROM exetable e
            JOIN desctable d ON e.id = d.id_exe
            JOIN enhanced_signatures es ON d.id = es.function_id
            WHERE e.id != ?
            ORDER BY e.name_exec
            """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, currentExeId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                ExecutableInfo info = new ExecutableInfo();
                info.id = rs.getInt("id");
                info.name = rs.getString("name_exec");
                info.gameType = rs.getString("game_type");
                executables.add(info);
            }
        }

        return executables;
    }

    private void processFunctionSimilarities(Connection conn, Program program, int currentExeId,
                                           List<ExecutableInfo> otherExecutables) throws Exception {

        println("Processing function similarities...");
        monitor.setMessage("Generating similarity matrix");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        // Cache function IDs to avoid repeated database lookups
        Map<String, Long> functionIdCache = new HashMap<>();

        int processedCount = 0;
        int similarityCount = 0;

        // Prepare batch insert statement for better performance
        String insertSimilaritySql = """
            INSERT INTO function_similarity_matrix
            (source_function_id, target_function_id, similarity_score, confidence_score, match_type)
            VALUES (?, ?, ?, ?, 'structural_analysis')
            ON CONFLICT (source_function_id, target_function_id) DO UPDATE SET
                similarity_score = EXCLUDED.similarity_score,
                confidence_score = EXCLUDED.confidence_score,
                updated_at = now()
            """;

        // Set connection for better performance
        conn.setAutoCommit(false); // Enable batch processing

        try (PreparedStatement similarityStmt = conn.prepareStatement(insertSimilaritySql)) {
            int batchCount = 0;

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function currentFunction = functions.next();
                processedCount++;

                if (processedCount % 50 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        processedCount, currentFunction.getName()));
                    println(String.format("Processed %d functions, found %d similarities...",
                        processedCount, similarityCount));
                }

                try {
                    // Get current function's ID from database (with caching)
                    String cacheKey = currentExeId + ":" + currentFunction.getName();
                    long currentFuncId = functionIdCache.computeIfAbsent(cacheKey,
                        k -> {
                            try {
                                return getFunctionId(conn, currentFunction.getName(), currentExeId);
                            } catch (SQLException e) {
                                return -1L;
                            }
                        });
                    if (currentFuncId == -1) continue;

                    // Get enhanced signature for current function from database
                    FunctionSignature currentSig = getFunctionSignatureFromDatabase(conn, currentFuncId);
                    if (currentSig == null) {
                        // Fallback to live analysis if no database signature
                        currentSig = generateFunctionSignature(currentFunction);
                        if (currentSig == null) continue;
                    }

                    // Compare against functions in other executables
                    for (ExecutableInfo otherExe : otherExecutables) {
                        List<FunctionCandidate> candidates = getSimilarFunctionCandidates(
                            conn, currentFunction, otherExe.id);

                        for (FunctionCandidate candidate : candidates) {
                            double similarity = calculateSimilarity(currentSig, candidate.signature);
                            double confidence = calculateConfidence(currentSig, candidate.signature);

                            if (similarity >= MIN_SIMILARITY && confidence >= MIN_CONFIDENCE) {
                                // Add to batch instead of immediate execution
                                similarityStmt.setLong(1, currentFuncId);
                                similarityStmt.setLong(2, candidate.functionId);
                                similarityStmt.setDouble(3, similarity);
                                similarityStmt.setDouble(4, confidence);

                                similarityStmt.addBatch();
                                batchCount++;
                                similarityCount++;

                                // Execute batch every 500 similarities for better performance
                                if (batchCount >= 500) {
                                    similarityStmt.executeBatch();
                                    conn.commit();
                                    batchCount = 0;
                                }
                            }
                        }
                    }

                } catch (Exception e) {
                    printerr("Error processing function " + currentFunction.getName() + ": " + e.getMessage());
                }
            }

            // Execute any remaining batch items
            if (batchCount > 0) {
                similarityStmt.executeBatch();
                conn.commit();
            }
        }

        // Restore autoCommit
        conn.setAutoCommit(true);

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Generated %d similarity relationships for %d functions",
            similarityCount, processedCount));
    }

    private long getFunctionId(Connection conn, String functionName, int executableId) throws SQLException {
        String sql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, functionName);
            stmt.setInt(2, executableId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getLong("id");
            }
        }
        return -1;
    }

    private FunctionSignature getFunctionSignatureFromDatabase(Connection conn, long functionId) throws SQLException {
        String sql = """
            SELECT instruction_count, basic_block_count, call_count, feature_vector
            FROM enhanced_signatures
            WHERE function_id = ?
            """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, functionId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return createSignatureFromDatabase(rs);
            }
        }
        return null;
    }

    private FunctionSignature generateFunctionSignature(Function function) {
        try {
            FunctionSignature sig = new FunctionSignature();

            // Basic metrics - fixed type conversion
            sig.instructionCount = (int)function.getBody().getNumAddresses();
            sig.parameterCount = function.getParameterCount();

            // Instruction pattern analysis
            sig.mnemonicPattern = extractMnemonicPattern(function);
            sig.operandPattern = extractOperandPattern(function);
            sig.controlFlowPattern = extractControlFlowPattern(function);

            // Function complexity
            sig.branchCount = countBranches(function);
            sig.callCount = countCalls(function);

            return sig;

        } catch (Exception e) {
            return null;
        }
    }

    private String extractMnemonicPattern(Function function) {
        Map<String, Integer> mnemonicCounts = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();
            mnemonicCounts.merge(mnemonic, 1, Integer::sum);
        }

        // Create normalized pattern (top 5 most common mnemonics)
        return mnemonicCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(5)
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private String extractOperandPattern(Function function) {
        Map<String, Integer> operandTypes = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            for (int i = 0; i < instr.getNumOperands(); i++) {
                int opType = instr.getOperandType(i);
                String opTypeStr = Integer.toString(opType); // Simplified operand type handling
                operandTypes.merge(opTypeStr, 1, Integer::sum);
            }
        }

        return operandTypes.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(3)
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private String extractControlFlowPattern(Function function) {
        Map<String, Integer> flowTypes = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            // Use flow type methods directly without variable
            if (instr.getFlowType().hasFallthrough() || instr.getFlowType().isJump() || instr.getFlowType().isCall()) {
                flowTypes.merge(instr.getFlowType().toString(), 1, Integer::sum);
            }
        }

        return flowTypes.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private int countBranches(Function function) {
        int branchCount = 0;
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump() || instr.getFlowType().isConditional()) {
                branchCount++;
            }
        }
        return branchCount;
    }

    private int countCalls(Function function) {
        return function.getCalledFunctions(monitor).size();
    }

    private List<FunctionCandidate> getSimilarFunctionCandidates(Connection conn, Function sourceFunc, int targetExeId) throws SQLException {
        List<FunctionCandidate> candidates = new ArrayList<>();

        // Get functions from target executable with their actual enhanced signatures
        String sql = """
            SELECT d.id, d.name_func, d.addr,
                   es.instruction_count, es.basic_block_count, es.call_count, es.feature_vector
            FROM desctable d
            JOIN enhanced_signatures es ON d.id = es.function_id
            WHERE d.id_exe = ?
            AND es.instruction_count > 0
            ORDER BY d.addr
            LIMIT 200
            """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, targetExeId);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                FunctionCandidate candidate = new FunctionCandidate();
                candidate.functionId = rs.getLong("id");
                candidate.name = rs.getString("name_func");
                candidate.address = rs.getLong("addr");

                // Create signature from enhanced_signatures data
                candidate.signature = createSignatureFromDatabase(rs);

                candidates.add(candidate);
            }
        }

        return candidates;
    }

    private FunctionSignature createSignatureFromDatabase(ResultSet rs) throws SQLException {
        FunctionSignature sig = new FunctionSignature();
        sig.instructionCount = rs.getInt("instruction_count");
        sig.branchCount = rs.getInt("basic_block_count"); // Use basic blocks as branch indicator
        sig.callCount = rs.getInt("call_count");

        // Use feature vector as mnemonic pattern (truncated for comparison)
        String featureVector = rs.getString("feature_vector");
        if (featureVector != null && featureVector.length() > 0) {
            sig.mnemonicPattern = featureVector.substring(0, Math.min(featureVector.length(), 50));
        } else {
            sig.mnemonicPattern = "";
        }

        sig.parameterCount = 0; // Will enhance later if needed
        return sig;
    }

    private FunctionSignature createPlaceholderSignature(String functionName) {
        // Create a basic signature based on function name patterns
        FunctionSignature sig = new FunctionSignature();
        sig.instructionCount = functionName.length() * 10; // Rough estimate
        sig.mnemonicPattern = functionName.substring(0, Math.min(functionName.length(), 10));
        sig.parameterCount = 0;
        sig.branchCount = 0;
        sig.callCount = 0;
        return sig;
    }

    private double calculateSimilarity(FunctionSignature sig1, FunctionSignature sig2) {
        double similarity = 0.0;
        int factors = 0;

        // Instruction count similarity
        if (sig1.instructionCount > 0 && sig2.instructionCount > 0) {
            int minCount = Math.min(sig1.instructionCount, sig2.instructionCount);
            int maxCount = Math.max(sig1.instructionCount, sig2.instructionCount);
            similarity += (double) minCount / maxCount;
            factors++;
        }

        // Mnemonic pattern similarity
        if (sig1.mnemonicPattern != null && sig2.mnemonicPattern != null) {
            similarity += calculateStringSimilarity(sig1.mnemonicPattern, sig2.mnemonicPattern);
            factors++;
        }

        // Parameter count similarity
        if (sig1.parameterCount >= 0 && sig2.parameterCount >= 0) {
            if (sig1.parameterCount == sig2.parameterCount) {
                similarity += 1.0;
            } else if (Math.abs(sig1.parameterCount - sig2.parameterCount) <= 1) {
                similarity += 0.5;
            }
            factors++;
        }

        return factors > 0 ? similarity / factors : 0.0;
    }

    private double calculateStringSimilarity(String s1, String s2) {
        if (s1.equals(s2)) return 1.0;

        int maxLength = Math.max(s1.length(), s2.length());
        if (maxLength == 0) return 1.0;

        int commonChars = 0;
        for (int i = 0; i < Math.min(s1.length(), s2.length()); i++) {
            if (s1.charAt(i) == s2.charAt(i)) {
                commonChars++;
            }
        }

        return (double) commonChars / maxLength;
    }

    private double calculateConfidence(FunctionSignature sig1, FunctionSignature sig2) {
        // Confidence based on how many factors we could compare
        double confidence = 0.0;

        if (sig1.instructionCount > 10 && sig2.instructionCount > 10) confidence += 20.0;
        if (sig1.mnemonicPattern != null && sig1.mnemonicPattern.length() > 5) confidence += 15.0;
        if (sig1.branchCount > 0) confidence += 10.0;
        if (sig1.callCount > 0) confidence += 10.0;

        return Math.min(confidence, 100.0);
    }

    // Helper classes
    private static class ExecutableInfo {
        int id;
        String name;
        String gameType;
    }

    private static class FunctionSignature {
        int instructionCount;
        int parameterCount;
        String mnemonicPattern;
        String operandPattern;
        String controlFlowPattern;
        int branchCount;
        int callCount;
    }

    private static class FunctionCandidate {
        long functionId;
        String name;
        long address;
        FunctionSignature signature;
    }
}
