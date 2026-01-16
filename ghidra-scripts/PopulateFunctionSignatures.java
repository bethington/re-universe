// Populate function parameters and return types into BSim database
// Creates extended schema for function signature analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift S
// @menupath Tools.BSim.Populate Function Signatures

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import java.sql.*;
import java.util.*;

public class PopulateFunctionSignatures extends GhidraScript {

    private static final String DEFAULT_DB_URL = "jdbc:postgresql://localhost:5432/bsim";
    private static final String DEFAULT_DB_USER = "ben";
    private static final String DEFAULT_DB_PASS = "goodyx12";

    @Override
    public void run() throws Exception {

        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        println("=== BSim Function Signature Population Script ===");
        println("Program: " + programName);

        // Count functions with signatures
        int functionsCount = currentProgram.getFunctionManager().getFunctionCount();
        println("Total functions: " + functionsCount);

        boolean proceed = askYesNo("Populate Function Signatures",
            String.format("Add function signatures for %d functions to BSim database?\n\nThis will:\n" +
            "- Create function_signatures table if needed\n" +
            "- Extract parameter and return type information\n" +
            "- Enable signature-based cross-version analysis\n\nProceed?", functionsCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            populateFunctionSignatures(programName);
            println("Successfully populated function signatures into BSim database!");

        } catch (Exception e) {
            printerr("Error populating function signatures: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void populateFunctionSignatures(String programName) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {
            println("Connected to BSim database successfully");

            // Create extended schema if needed
            createSignatureSchema(conn);

            // Get executable ID
            int executableId = getExecutableId(conn, programName);
            if (executableId == -1) {
                throw new RuntimeException("Executable not found in BSim database. Please populate functions first.");
            }

            println("Executable ID: " + executableId);

            // Process function signatures
            processFunctionSignatures(conn, executableId, programName);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private void createSignatureSchema(Connection conn) throws SQLException {
        println("Creating function signature schema...");

        String createTableSql = """
            CREATE TABLE IF NOT EXISTS function_signatures (
                id SERIAL PRIMARY KEY,
                function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
                function_name TEXT NOT NULL,
                return_type TEXT,
                return_type_size INTEGER,
                parameter_count INTEGER DEFAULT 0,
                calling_convention TEXT,
                has_varargs BOOLEAN DEFAULT false,
                signature_hash TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS function_parameters (
                id SERIAL PRIMARY KEY,
                signature_id BIGINT REFERENCES function_signatures(id) ON DELETE CASCADE,
                parameter_index INTEGER NOT NULL,
                parameter_name TEXT,
                parameter_type TEXT,
                parameter_size INTEGER,
                is_pointer BOOLEAN DEFAULT false,
                is_array BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_function_signatures_function_id ON function_signatures(function_id);
            CREATE INDEX IF NOT EXISTS idx_function_signatures_executable_id ON function_signatures(executable_id);
            CREATE INDEX IF NOT EXISTS idx_function_parameters_signature_id ON function_parameters(signature_id);
            """;

        try (Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
            println("Function signature schema created/verified");
        }
    }

    private int getExecutableId(Connection conn, String programName) throws SQLException {
        String selectSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return rs.getInt("id");
            }
            return -1;
        }
    }

    private void processFunctionSignatures(Connection conn, int executableId, String programName) throws Exception {
        println("Processing function signatures...");
        monitor.setMessage("Processing function signatures for BSim");

        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int processedCount = 0;
        int signatureCount = 0;

        // Prepare statements
        String insertSignatureSql = """
            INSERT INTO function_signatures
            (function_id, executable_id, function_name, return_type, return_type_size,
             parameter_count, calling_convention, has_varargs, signature_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (function_id) DO UPDATE SET
                return_type = EXCLUDED.return_type,
                parameter_count = EXCLUDED.parameter_count,
                calling_convention = EXCLUDED.calling_convention,
                has_varargs = EXCLUDED.has_varargs,
                signature_hash = EXCLUDED.signature_hash,
                updated_at = NOW()
            RETURNING id
            """;

        String insertParameterSql = """
            INSERT INTO function_parameters
            (signature_id, parameter_index, parameter_name, parameter_type,
             parameter_size, is_pointer, is_array)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";

        try (PreparedStatement signatureStmt = conn.prepareStatement(insertSignatureSql);
             PreparedStatement parameterStmt = conn.prepareStatement(insertParameterSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                processedCount++;

                if (processedCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        processedCount, function.getName()));
                    println(String.format("Processed %d functions...", processedCount));
                }

                try {
                    // Get BSim function ID
                    funcIdStmt.setString(1, function.getName());
                    funcIdStmt.setInt(2, executableId);
                    ResultSet rs = funcIdStmt.executeQuery();

                    if (rs.next()) {
                        long functionId = rs.getLong("id");

                        // Insert function signature
                        if (insertFunctionSignature(signatureStmt, parameterStmt, function, functionId, executableId)) {
                            signatureCount++;
                        }
                    }
                    rs.close();

                } catch (SQLException e) {
                    printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                }
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d functions, added %d function signatures to database",
            processedCount, signatureCount));
    }

    private boolean insertFunctionSignature(PreparedStatement signatureStmt, PreparedStatement parameterStmt,
                                          Function function, long functionId, int executableId) throws SQLException {

        // Extract function signature information
        FunctionSignature signature = function.getSignature();

        String returnType = "void";
        int returnTypeSize = 0;
        if (signature.getReturnType() != null) {
            returnType = signature.getReturnType().getDisplayName();
            returnTypeSize = signature.getReturnType().getLength();
        }

        Parameter[] parameters = signature.getArguments();
        int parameterCount = parameters.length;
        boolean hasVarargs = signature.hasVarArgs();
        String callingConvention = function.getCallingConventionName();

        // Generate signature hash for similarity matching
        String signatureHash = generateSignatureHash(function, signature);

        // Insert function signature
        signatureStmt.setLong(1, functionId);
        signatureStmt.setInt(2, executableId);
        signatureStmt.setString(3, function.getName());
        signatureStmt.setString(4, returnType);
        signatureStmt.setInt(5, returnTypeSize);
        signatureStmt.setInt(6, parameterCount);
        signatureStmt.setString(7, callingConvention);
        signatureStmt.setBoolean(8, hasVarargs);
        signatureStmt.setString(9, signatureHash);

        ResultSet rs = signatureStmt.executeQuery();
        if (rs.next()) {
            long signatureId = rs.getLong("id");

            // Insert parameters
            for (int i = 0; i < parameters.length; i++) {
                Parameter param = parameters[i];
                insertParameter(parameterStmt, signatureId, i, param);
            }

            rs.close();
            return true;
        }

        return false;
    }

    private void insertParameter(PreparedStatement parameterStmt, long signatureId,
                               int index, Parameter param) throws SQLException {

        String paramName = param.getName();
        if (paramName == null || paramName.trim().isEmpty()) {
            paramName = "param" + index;
        }

        DataType paramType = param.getDataType();
        String typeName = paramType.getDisplayName();
        int typeSize = paramType.getLength();
        boolean isPointer = paramType instanceof Pointer;
        boolean isArray = paramType instanceof Array;

        parameterStmt.setLong(1, signatureId);
        parameterStmt.setInt(2, index);
        parameterStmt.setString(3, paramName);
        parameterStmt.setString(4, typeName);
        parameterStmt.setInt(5, typeSize);
        parameterStmt.setBoolean(6, isPointer);
        parameterStmt.setBoolean(7, isArray);

        parameterStmt.executeUpdate();
    }

    private String generateSignatureHash(Function function, FunctionSignature signature) {
        // Generate a hash based on function signature for similarity matching
        StringBuilder sigBuilder = new StringBuilder();

        // Add return type
        if (signature.getReturnType() != null) {
            sigBuilder.append(signature.getReturnType().getDisplayName()).append(":");
        }

        // Add parameter types
        Parameter[] params = signature.getArguments();
        for (Parameter param : params) {
            sigBuilder.append(param.getDataType().getDisplayName()).append(",");
        }

        // Add calling convention
        sigBuilder.append(function.getCallingConventionName());

        return Integer.toHexString(sigBuilder.toString().hashCode());
    }
}