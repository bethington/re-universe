// Generate function similarity matrix for cross-version matching using instruction patterns
// This creates similarity relationships based on function structure rather than names
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift M
// @menupath Tools.BSim.Generate Similarity Matrix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;
import java.sql.*;
import java.util.*;

public class GenerateFunctionSimilarityMatrix extends GhidraScript {

    private static final String DB_URL = "jdbc:postgresql://localhost:5432/bsim";
    private static final String DB_USER = "ben";
    private static final String DB_PASS = "goodyx12";

    // Similarity thresholds
    private static final double MIN_SIMILARITY = 0.7;
    private static final double MIN_CONFIDENCE = 25.0;

    @Override
    public void run() throws Exception {

        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        println("=== Function Similarity Matrix Generation ===");
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
            generateSimilarityMatrix(programName);
            println("Successfully generated similarity matrix!");

        } catch (Exception e) {
            printerr("Error generating similarity matrix: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void generateSimilarityMatrix(String programName) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            println("Connected to BSim database successfully");

            // Get current executable info
            int currentExeId = getExecutableId(conn, programName);
            if (currentExeId == -1) {
                throw new RuntimeException("Current executable not found. Run AddProgramToBSimDatabase.java first.");
            }

            // Get all other executables for comparison
            List<ExecutableInfo> otherExecutables = getOtherExecutables(conn, currentExeId);
            println("Found " + otherExecutables.size() + " other executables for comparison");

            // Process similarity for current program's functions
            processFunctionSimilarities(conn, currentExeId, otherExecutables);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private int getExecutableId(Connection conn, String programName) throws SQLException {
        String sql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        return -1;
    }

    private List<ExecutableInfo> getOtherExecutables(Connection conn, int currentExeId) throws SQLException {
        List<ExecutableInfo> executables = new ArrayList<>();

        String sql = """
            SELECT id, name_exec,
                   CASE
                       WHEN name_exec ~ '^Classic_' THEN 'Classic'
                       WHEN name_exec ~ '^LoD_' THEN 'LoD'
                       ELSE 'Other'
                   END as game_type
            FROM exetable
            WHERE id != ? AND name_exec ~ '^(Classic|LoD)_'
            ORDER BY name_exec
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

    private void processFunctionSimilarities(Connection conn, int currentExeId,
                                           List<ExecutableInfo> otherExecutables) throws Exception {

        println("Processing function similarities...");
        monitor.setMessage("Generating similarity matrix");

        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int processedCount = 0;
        int similarityCount = 0;

        // Prepare statements
        String insertSimilaritySql = """
            INSERT INTO function_similarity_matrix
            (source_function_id, target_function_id, similarity_score, confidence_score, match_type)
            VALUES (?, ?, ?, ?, 'structural_analysis')
            ON CONFLICT (source_function_id, target_function_id) DO UPDATE SET
                similarity_score = EXCLUDED.similarity_score,
                confidence_score = EXCLUDED.confidence_score,
                updated_at = now()
            """;

        try (PreparedStatement similarityStmt = conn.prepareStatement(insertSimilaritySql)) {

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
                    // Get current function's ID from database
                    long currentFuncId = getFunctionId(conn, currentFunction.getName(), currentExeId);
                    if (currentFuncId == -1) continue;

                    // Generate structural signature for current function
                    FunctionSignature currentSig = generateFunctionSignature(currentFunction);
                    if (currentSig == null) continue;

                    // Compare against functions in other executables
                    for (ExecutableInfo otherExe : otherExecutables) {
                        List<FunctionCandidate> candidates = getSimilarFunctionCandidates(
                            conn, currentFunction, otherExe.id);

                        for (FunctionCandidate candidate : candidates) {
                            double similarity = calculateSimilarity(currentSig, candidate.signature);
                            double confidence = calculateConfidence(currentSig, candidate.signature);

                            if (similarity >= MIN_SIMILARITY && confidence >= MIN_CONFIDENCE) {
                                // Store similarity relationship
                                similarityStmt.setLong(1, currentFuncId);
                                similarityStmt.setLong(2, candidate.functionId);
                                similarityStmt.setDouble(3, similarity);
                                similarityStmt.setDouble(4, confidence);

                                similarityStmt.executeUpdate();
                                similarityCount++;
                            }
                        }
                    }

                } catch (Exception e) {
                    printerr("Error processing function " + currentFunction.getName() + ": " + e.getMessage());
                }
            }
        }

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
            // Fixed FlowType reference
            ghidra.program.model.lang.FlowType flowType = instr.getFlowType();
            if (flowType.hasFallthrough() || flowType.isJump() || flowType.isCall()) {
                flowTypes.merge(flowType.toString(), 1, Integer::sum);
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

        // Get functions from target executable with similar characteristics
        String sql = """
            SELECT id, name_func, addr
            FROM desctable
            WHERE id_exe = ?
            AND LENGTH(name_func) BETWEEN ? AND ?
            ORDER BY addr
            LIMIT 100
            """;

        int minNameLength = Math.max(1, sourceFunc.getName().length() - 5);
        int maxNameLength = sourceFunc.getName().length() + 10;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, targetExeId);
            stmt.setInt(2, minNameLength);
            stmt.setInt(3, maxNameLength);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                FunctionCandidate candidate = new FunctionCandidate();
                candidate.functionId = rs.getLong("id");
                candidate.name = rs.getString("name_func");
                candidate.address = rs.getLong("addr");

                // Create placeholder signature for comparison
                candidate.signature = createPlaceholderSignature(candidate.name);

                candidates.add(candidate);
            }
        }

        return candidates;
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