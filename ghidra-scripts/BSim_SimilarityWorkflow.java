// BSim Similarity-Based Cross-Version Matching Workflow
// Compatible with Ghidra 11.4.2 - Database-driven similarity analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift W
// @menupath Tools.BSim.Similarity Workflow

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;
import java.sql.*;
import java.util.*;

public class BSim_SimilarityWorkflow extends GhidraScript {

    private static final String DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DB_USER = "ben";
    private static final String DB_PASS = "goodyx12";
    private static final double MIN_SIMILARITY = 0.75;
    private static final double MIN_CONFIDENCE = 30.0;
    private static final int MAX_COMPARISONS = 2000; // Limit for performance

    @Override
    public void run() throws Exception {

        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        println("=== BSim Similarity-Based Cross-Version Matching ===");
        println("Program: " + programName);

        // Ask user for workflow mode
        String[] modes = {
            "Generate Enhanced Signatures Only",
            "Generate + Find Similar Functions",
            "Query Existing Similarities",
            "Full Workflow (Recommended)"
        };

        String selectedMode = askChoice("Select Workflow Mode",
            "What would you like to do?",
            Arrays.asList(modes), modes[3]);

        if (selectedMode.equals(modes[0])) {
            generateSignatures();
        } else if (selectedMode.equals(modes[1])) {
            generateSignatures();
            findSimilarFunctions();
        } else if (selectedMode.equals(modes[2])) {
            queryExistingSimilarities();
        } else if (selectedMode.equals(modes[3])) {
            runFullWorkflow();
        }
    }

    private void runFullWorkflow() throws Exception {
        println("\n=== Running Full BSim Similarity Workflow ===");

        boolean proceed = askYesNo("Full BSim Workflow",
            "This will:\n" +
            "1. Generate enhanced signatures for all functions\n" +
            "2. Compare against similar functions in other versions\n" +
            "3. Populate similarity matrix in database\n" +
            "4. Update cross-version relationships\n\n" +
            "This may take significant time. Proceed?");

        if (!proceed) {
            println("Workflow cancelled by user");
            return;
        }

        try {
            // Step 1: Generate signatures
            println("\n--- Step 1: Generating Enhanced Signatures ---");
            generateSignatures();

            // Step 2: Find similar functions
            println("\n--- Step 2: Finding Similar Functions ---");
            findSimilarFunctions();

            // Step 3: Update database relationships
            println("\n--- Step 3: Updating Database ---");
            updateCrossVersionRelationships();

            println("\n✅ Full BSim workflow completed successfully!");

        } catch (Exception e) {
            printerr("Error in BSim workflow: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void generateSignatures() throws Exception {
        println("Generating enhanced function signatures...");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            int executableId = getExecutableId(conn, currentProgram.getName());
            if (executableId == -1) {
                throw new RuntimeException("Executable not found. Please run AddProgramToBSimDatabase.java first.");
            }

            generateProgramSignatures(conn, executableId);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private void generateProgramSignatures(Connection conn, int executableId) throws Exception {
        println("Processing functions for signature generation...");

        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int totalFunctions = funcManager.getFunctionCount();
        int processedCount = 0;
        int signatureCount = 0;

        String insertSql = """
            INSERT INTO enhanced_signatures
            (function_id, lsh_vector, feature_count, signature_quality, instruction_count,
             parameter_count, branch_count, call_count, mnemonic_pattern, control_flow_pattern)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (function_id) DO UPDATE SET
                lsh_vector = EXCLUDED.lsh_vector,
                signature_quality = EXCLUDED.signature_quality,
                created_at = NOW()
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";

        try (PreparedStatement insertStmt = conn.prepareStatement(insertSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                processedCount++;

                if (processedCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d of %d: %s",
                        processedCount, totalFunctions, function.getName()));
                    println(String.format("Processed %d/%d functions...", processedCount, totalFunctions));
                }

                try {
                    // Get function ID
                    funcIdStmt.setString(1, function.getName());
                    funcIdStmt.setInt(2, executableId);
                    ResultSet rs = funcIdStmt.executeQuery();

                    if (!rs.next()) {
                        rs.close();
                        continue;
                    }

                    long functionId = rs.getLong("id");
                    rs.close();

                    // Generate signature
                    FunctionSignature signature = createEnhancedSignature(function);
                    if (signature != null) {
                        insertStmt.setLong(1, functionId);
                        insertStmt.setBytes(2, signature.vectorData);
                        insertStmt.setInt(3, signature.featureCount);
                        insertStmt.setDouble(4, signature.quality);
                        insertStmt.setInt(5, signature.instructionCount);
                        insertStmt.setInt(6, signature.parameterCount);
                        insertStmt.setInt(7, signature.branchCount);
                        insertStmt.setInt(8, signature.callCount);
                        insertStmt.setString(9, signature.mnemonicPattern);
                        insertStmt.setString(10, signature.controlFlowPattern);

                        insertStmt.executeUpdate();
                        signatureCount++;
                    }

                } catch (Exception e) {
                    printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                }
            }
        }

        println(String.format("Generated %d enhanced signatures for %d functions",
            signatureCount, processedCount));
    }

    private FunctionSignature createEnhancedSignature(Function function) {
        try {
            FunctionSignature sig = new FunctionSignature();

            // Basic metrics
            AddressSetView body = function.getBody();
            sig.instructionCount = (int)body.getNumAddresses();
            sig.parameterCount = function.getParameterCount();

            // Extract features
            List<Integer> features = extractFunctionFeatures(function);
            sig.vectorData = createSignatureVector(features);
            sig.featureCount = features.size();

            // Pattern analysis
            sig.mnemonicPattern = extractMnemonicPattern(function);
            sig.controlFlowPattern = extractControlFlowPattern(function);

            // Complexity metrics
            sig.branchCount = countBranches(function);
            sig.callCount = function.getCalledFunctions(monitor).size();

            // Quality assessment
            sig.quality = calculateSignatureQuality(sig);

            return sig;

        } catch (Exception e) {
            return null;
        }
    }

    private List<Integer> extractFunctionFeatures(Function function) {
        List<Integer> features = new ArrayList<>();

        try {
            AddressSetView body = function.getBody();
            InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();

                // Instruction features
                features.add(instr.getMnemonicString().hashCode());
                features.add(instr.getFlowType().hashCode());

                // Operand features
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    features.add(instr.getOperandType(i));
                }
            }

            // Structural features
            features.add((int)function.getBody().getNumAddresses());
            features.add(function.getParameterCount());

        } catch (Exception e) {
            // Return partial features
        }

        return features;
    }

    private byte[] createSignatureVector(List<Integer> features) {
        if (features.isEmpty()) {
            return new byte[32];
        }

        byte[] vector = new byte[32]; // 256 bits

        for (int i = 0; i < 256; i++) {
            int hash = 0;
            for (Integer feature : features) {
                hash ^= (feature >>> (i % 32)) & 1;
            }

            if ((hash & 1) == 1) {
                vector[i / 8] |= (1 << (i % 8));
            }
        }

        return vector;
    }

    private String extractMnemonicPattern(Function function) {
        Map<String, Integer> mnemonics = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            mnemonics.merge(instr.getMnemonicString(), 1, Integer::sum);
        }

        return mnemonics.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(5)
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private String extractControlFlowPattern(Function function) {
        Map<String, Integer> flows = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            // Use flow type methods directly without variable
            if (instr.getFlowType().hasFallthrough() || instr.getFlowType().isJump() || instr.getFlowType().isCall()) {
                flows.merge(instr.getFlowType().toString(), 1, Integer::sum);
            }
        }

        return flows.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private int countBranches(Function function) {
        int count = 0;
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump() || instr.getFlowType().isConditional()) {
                count++;
            }
        }
        return count;
    }

    private double calculateSignatureQuality(FunctionSignature sig) {
        double quality = 0.0;

        if (sig.instructionCount > 10) quality += 0.3;
        if (sig.featureCount > 20) quality += 0.2;
        if (sig.branchCount > 0) quality += 0.2;
        if (sig.callCount > 0) quality += 0.2;
        if (sig.mnemonicPattern != null && sig.mnemonicPattern.length() > 10) quality += 0.1;

        return Math.min(quality, 1.0);
    }

    private void findSimilarFunctions() throws Exception {
        println("Finding similar functions across versions...");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            int executableId = getExecutableId(conn, currentProgram.getName());
            findAndStoreSimilarities(conn, executableId);

        } catch (SQLException e) {
            printerr("Error finding similarities: " + e.getMessage());
            throw e;
        }
    }

    private void findAndStoreSimilarities(Connection conn, int currentExeId) throws SQLException {
        println("Comparing against other executables...");

        String compareSql = """
            SELECT
                d1.id as source_id, d1.name_func as source_name,
                d2.id as target_id, d2.name_func as target_name,
                e2.name_exec as target_exe,
                es1.lsh_vector as source_vector,
                es2.lsh_vector as target_vector,
                es1.instruction_count as source_instr,
                es2.instruction_count as target_instr
            FROM enhanced_signatures es1
            JOIN desctable d1 ON es1.function_id = d1.id
            JOIN enhanced_signatures es2 ON es2.function_id != es1.function_id
            JOIN desctable d2 ON es2.function_id = d2.id
            JOIN exetable e2 ON d2.id_exe = e2.id
            WHERE d1.id_exe = ?
            AND d2.id_exe != ?
            AND es1.signature_quality > 0.5
            AND es2.signature_quality > 0.5
            LIMIT ?
            """;

        String insertSimilaritySql = """
            INSERT INTO function_similarity_matrix
            (source_function_id, target_function_id, similarity_score, confidence_score, match_type)
            VALUES (?, ?, ?, ?, 'enhanced_signature')
            ON CONFLICT (source_function_id, target_function_id) DO UPDATE SET
                similarity_score = EXCLUDED.similarity_score,
                confidence_score = EXCLUDED.confidence_score,
                updated_at = NOW()
            """;

        int similarityCount = 0;

        try (PreparedStatement compareStmt = conn.prepareStatement(compareSql);
             PreparedStatement insertStmt = conn.prepareStatement(insertSimilaritySql)) {

            compareStmt.setInt(1, currentExeId);
            compareStmt.setInt(2, currentExeId);
            compareStmt.setInt(3, MAX_COMPARISONS);

            ResultSet rs = compareStmt.executeQuery();

            while (rs.next() && !monitor.isCancelled()) {
                try {
                    byte[] sourceVector = rs.getBytes("source_vector");
                    byte[] targetVector = rs.getBytes("target_vector");

                    double similarity = calculateVectorSimilarity(sourceVector, targetVector);
                    double confidence = calculateConfidence(
                        rs.getInt("source_instr"),
                        rs.getInt("target_instr"),
                        similarity
                    );

                    if (similarity >= MIN_SIMILARITY && confidence >= MIN_CONFIDENCE) {
                        insertStmt.setLong(1, rs.getLong("source_id"));
                        insertStmt.setLong(2, rs.getLong("target_id"));
                        insertStmt.setDouble(3, similarity);
                        insertStmt.setDouble(4, confidence);

                        insertStmt.executeUpdate();
                        similarityCount++;

                        if (similarityCount % 100 == 0) {
                            println("Found " + similarityCount + " similarity matches...");
                        }
                    }

                } catch (SQLException e) {
                    // Continue with next comparison
                }
            }
        }

        println(String.format("Found %d similarity relationships", similarityCount));
    }

    private double calculateVectorSimilarity(byte[] vector1, byte[] vector2) {
        if (vector1 == null || vector2 == null || vector1.length != vector2.length) {
            return 0.0;
        }

        int matches = 0;
        int totalBits = vector1.length * 8;

        for (int i = 0; i < vector1.length; i++) {
            byte v1 = vector1[i];
            byte v2 = vector2[i];

            // Count matching bits
            for (int bit = 0; bit < 8; bit++) {
                int b1 = (v1 >> bit) & 1;
                int b2 = (v2 >> bit) & 1;
                if (b1 == b2) {
                    matches++;
                }
            }
        }

        return (double) matches / totalBits;
    }

    private double calculateConfidence(int instrCount1, int instrCount2, double similarity) {
        // Size similarity factor
        int minCount = Math.min(instrCount1, instrCount2);
        int maxCount = Math.max(instrCount1, instrCount2);
        double sizeSimilarity = (double) minCount / maxCount;

        // Confidence based on instruction count and similarity
        double confidence = similarity * 50.0;
        if (minCount > 20) confidence += 20.0;
        if (sizeSimilarity > 0.8) confidence += 15.0;
        if (similarity > 0.9) confidence += 15.0;

        return Math.min(confidence, 100.0);
    }

    private void updateCrossVersionRelationships() throws SQLException {
        println("Refreshing cross-version relationships...");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String refreshSql = "SELECT refresh_cross_version_data()";
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(refreshSql);
                println("Cross-version relationships updated successfully");
            }
        }
    }

    private void queryExistingSimilarities() throws Exception {
        println("Querying existing similarities from database...");

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String querySql = """
                SELECT
                    s.name_func as source_function,
                    t.name_func as target_function,
                    se.name_exec as source_executable,
                    te.name_exec as target_executable,
                    fsm.similarity_score,
                    fsm.confidence_score
                FROM function_similarity_matrix fsm
                JOIN desctable s ON fsm.source_function_id = s.id
                JOIN desctable t ON fsm.target_function_id = t.id
                JOIN exetable se ON s.id_exe = se.id
                JOIN exetable te ON t.id_exe = te.id
                WHERE fsm.similarity_score >= ?
                ORDER BY fsm.similarity_score DESC
                LIMIT 50
                """;

            try (PreparedStatement stmt = conn.prepareStatement(querySql)) {
                stmt.setDouble(1, MIN_SIMILARITY);
                ResultSet rs = stmt.executeQuery();

                println("\n=== Top Function Similarities ===");
                int count = 0;
                while (rs.next() && count < 20) {
                    printf("%.3f: %s (%s) -> %s (%s)\n",
                        rs.getDouble("similarity_score"),
                        rs.getString("source_function"),
                        rs.getString("source_executable"),
                        rs.getString("target_function"),
                        rs.getString("target_executable"));
                    count++;
                }
            }
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

    // Helper class for function signatures
    private static class FunctionSignature {
        byte[] vectorData;
        int featureCount;
        double quality;
        int instructionCount;
        int parameterCount;
        int branchCount;
        int callCount;
        String mnemonicPattern;
        String controlFlowPattern;
    }
}
