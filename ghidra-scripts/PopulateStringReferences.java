// Populate string references into BSim database for enhanced similarity analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift T
// @menupath Tools.BSim.Populate String References

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import java.sql.*;
import java.util.*;

public class PopulateStringReferences extends GhidraScript {

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
        println("=== BSim String References Population Script ===");
        println("Program: " + programName);

        // Count strings in program
        int stringCount = countStringReferences();
        println("String references found: " + stringCount);

        if (stringCount == 0) {
            popup("No string references found in this program.");
            return;
        }

        boolean proceed = askYesNo("Populate String References",
            String.format("Add %d string references to BSim database?\n\nThis will:\n" +
            "- Extract all string literals and references\n" +
            "- Link strings to functions that reference them\n" +
            "- Enable string-based similarity analysis\n\nProceed?", stringCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            populateStringReferences(programName);
            println("Successfully populated string references into BSim database!");

        } catch (Exception e) {
            printerr("Error populating string references: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private int countStringReferences() {
        Data[] strings = findStrings(currentProgram.getMemory(), 4, 1, true, true);
        return strings.length;
    }

    private void populateStringReferences(String programName) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {
            println("Connected to BSim database successfully");

            // Create string schema if needed
            createStringSchema(conn);

            // Get executable ID
            int executableId = getExecutableId(conn, programName);
            if (executableId == -1) {
                throw new RuntimeException("Executable not found in BSim database. Please populate functions first.");
            }

            println("Executable ID: " + executableId);

            // Process string references
            processStringReferences(conn, executableId, programName);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private void createStringSchema(Connection conn) throws SQLException {
        println("Creating string references schema...");

        String createTableSql = """
            CREATE TABLE IF NOT EXISTS string_references (
                id SERIAL PRIMARY KEY,
                executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
                string_address BIGINT NOT NULL,
                string_value TEXT NOT NULL,
                string_length INTEGER,
                string_type TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS function_string_refs (
                id SERIAL PRIMARY KEY,
                function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                string_id BIGINT REFERENCES string_references(id) ON DELETE CASCADE,
                reference_type TEXT, -- 'direct', 'indirect', 'parameter'
                reference_address BIGINT,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(function_id, string_id, reference_address)
            );

            CREATE INDEX IF NOT EXISTS idx_string_refs_executable ON string_references(executable_id);
            CREATE INDEX IF NOT EXISTS idx_string_refs_value ON string_references(string_value);
            CREATE INDEX IF NOT EXISTS idx_function_string_refs_function ON function_string_refs(function_id);
            CREATE INDEX IF NOT EXISTS idx_function_string_refs_string ON function_string_refs(string_id);
            """;

        try (Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
            println("String references schema created/verified");
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

    private void processStringReferences(Connection conn, int executableId, String programName) throws Exception {
        println("Processing string references...");
        monitor.setMessage("Processing string references for BSim");

        // Find all strings in the program
        Data[] strings = findStrings(currentProgram.getMemory(), 4, 1, true, true);

        int processedCount = 0;
        int stringCount = 0;
        int referenceCount = 0;

        // Prepare statements
        String insertStringSql = """
            INSERT INTO string_references
            (executable_id, string_address, string_value, string_length, string_type)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (executable_id, string_address) DO UPDATE SET
                string_value = EXCLUDED.string_value,
                string_length = EXCLUDED.string_length,
                string_type = EXCLUDED.string_type
            RETURNING id
            """;

        String insertRefSql = """
            INSERT INTO function_string_refs
            (function_id, string_id, reference_type, reference_address)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (function_id, string_id, reference_address) DO NOTHING
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE id_exe = ? AND addr <= ? ORDER BY addr DESC LIMIT 1";

        try (PreparedStatement stringStmt = conn.prepareStatement(insertStringSql);
             PreparedStatement refStmt = conn.prepareStatement(insertRefSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            for (Data stringData : strings) {
                if (monitor.isCancelled()) break;

                processedCount++;

                if (processedCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing string %d of %d",
                        processedCount, strings.length));
                    println(String.format("Processed %d strings...", processedCount));
                }

                try {
                    // Insert string
                    Address stringAddr = stringData.getAddress();
                    Object value = stringData.getValue();
                    String stringValue = value != null ? value.toString() : "";

                    if (stringValue.length() < 4 || stringValue.length() > 1000) {
                        continue; // Skip very short or very long strings
                    }

                    stringStmt.setInt(1, executableId);
                    stringStmt.setLong(2, stringAddr.getOffset());
                    stringStmt.setString(3, stringValue);
                    stringStmt.setInt(4, stringValue.length());
                    stringStmt.setString(5, getStringType(stringData));

                    ResultSet rs = stringStmt.executeQuery();
                    if (rs.next()) {
                        long stringId = rs.getLong("id");
                        stringCount++;

                        // Find functions that reference this string
                        referenceCount += findFunctionReferences(conn, refStmt, funcIdStmt,
                            stringAddr, stringId, executableId);
                    }
                    rs.close();

                } catch (SQLException e) {
                    printerr("Error processing string at " + stringData.getAddress() + ": " + e.getMessage());
                }
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d strings, added %d strings with %d function references to database",
            processedCount, stringCount, referenceCount));
    }

    private String getStringType(Data stringData) {
        DataType dt = stringData.getDataType();
        if (dt instanceof StringDataType) {
            return "string";
        } else if (dt instanceof UnicodeDataType) {
            return "unicode";
        } else if (dt instanceof StringUTF8DataType) {
            return "utf8";
        }
        return "unknown";
    }

    private int findFunctionReferences(Connection conn, PreparedStatement refStmt,
                                     PreparedStatement funcIdStmt, Address stringAddr,
                                     long stringId, int executableId) throws SQLException {

        int refCount = 0;

        // Find all references to this string
        Reference[] references = getReferencesTo(stringAddr);

        for (Reference ref : references) {
            Address refAddr = ref.getFromAddress();

            // Find the function containing this reference
            funcIdStmt.setInt(1, executableId);
            funcIdStmt.setLong(2, refAddr.getOffset());

            ResultSet rs = funcIdStmt.executeQuery();
            if (rs.next()) {
                long functionId = rs.getLong("id");

                // Insert function-string reference
                refStmt.setLong(1, functionId);
                refStmt.setLong(2, stringId);
                refStmt.setString(3, getReferenceType(ref));
                refStmt.setLong(4, refAddr.getOffset());

                try {
                    refStmt.executeUpdate();
                    refCount++;
                } catch (SQLException e) {
                    // Ignore duplicate key errors
                    if (!e.getMessage().contains("duplicate key")) {
                        throw e;
                    }
                }
            }
            rs.close();
        }

        return refCount;
    }

    private String getReferenceType(Reference ref) {
        RefType refType = ref.getReferenceType();
        if (refType.isData()) {
            return "direct";
        } else if (refType.isCall()) {
            return "parameter";
        } else if (refType.isJump()) {
            return "indirect";
        }
        return "unknown";
    }
}