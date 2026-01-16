// Populate import/export tables into BSim database for API usage analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift I
// @menupath Tools.BSim.Populate Import/Export Tables

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import java.sql.*;
import java.util.*;

public class PopulateImportExports extends GhidraScript {

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
        println("=== BSim Import/Export Population Script ===");
        println("Program: " + programName);

        // Count imports and exports
        int importCount = countImports();
        int exportCount = countExports();
        println("Imports found: " + importCount);
        println("Exports found: " + exportCount);

        if (importCount == 0 && exportCount == 0) {
            popup("No imports or exports found in this program.");
            return;
        }

        boolean proceed = askYesNo("Populate Import/Export Data",
            String.format("Add %d imports and %d exports to BSim database?\n\nThis will:\n" +
            "- Extract all external API calls and dependencies\n" +
            "- Link imports/exports to functions that use them\n" +
            "- Enable API usage pattern analysis\n\nProceed?", importCount, exportCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            populateImportExports(programName);
            println("Successfully populated import/export data into BSim database!");

        } catch (Exception e) {
            printerr("Error populating import/export data: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private int countImports() {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getExternalSymbols();
        int count = 0;
        while (symbols.hasNext()) {
            symbols.next();
            count++;
        }
        return count;
    }

    private int countExports() {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbolIterator(true);
        int count = 0;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.isExternalEntryPoint()) {
                count++;
            }
        }
        return count;
    }

    private void populateImportExports(String programName) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {
            println("Connected to BSim database successfully");

            // Create import/export schema if needed
            createImportExportSchema(conn);

            // Get executable ID
            int executableId = getExecutableId(conn, programName);
            if (executableId == -1) {
                throw new RuntimeException("Executable not found in BSim database. Please populate functions first.");
            }

            println("Executable ID: " + executableId);

            // Process imports and exports
            processImports(conn, executableId, programName);
            processExports(conn, executableId, programName);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private void createImportExportSchema(Connection conn) throws SQLException {
        println("Creating import/export schema...");

        String createTableSql = """
            CREATE TABLE IF NOT EXISTS api_imports (
                id SERIAL PRIMARY KEY,
                executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
                library_name TEXT,
                function_name TEXT NOT NULL,
                ordinal INTEGER,
                import_address BIGINT,
                import_type TEXT, -- 'name', 'ordinal', 'delay'
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(executable_id, library_name, function_name, import_address)
            );

            CREATE TABLE IF NOT EXISTS api_exports (
                id SERIAL PRIMARY KEY,
                executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
                function_name TEXT NOT NULL,
                export_address BIGINT,
                ordinal INTEGER,
                is_forwarded BOOLEAN DEFAULT false,
                forward_target TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(executable_id, function_name, export_address)
            );

            CREATE TABLE IF NOT EXISTS function_api_usage (
                id SERIAL PRIMARY KEY,
                function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                api_import_id BIGINT REFERENCES api_imports(id) ON DELETE CASCADE,
                call_address BIGINT,
                call_type TEXT, -- 'direct', 'indirect', 'thunk'
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(function_id, api_import_id, call_address)
            );

            CREATE INDEX IF NOT EXISTS idx_api_imports_executable ON api_imports(executable_id);
            CREATE INDEX IF NOT EXISTS idx_api_imports_library ON api_imports(library_name);
            CREATE INDEX IF NOT EXISTS idx_api_imports_function ON api_imports(function_name);
            CREATE INDEX IF NOT EXISTS idx_api_exports_executable ON api_exports(executable_id);
            CREATE INDEX IF NOT EXISTS idx_function_api_usage_function ON function_api_usage(function_id);
            """;

        try (Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
            println("Import/export schema created/verified");
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

    private void processImports(Connection conn, int executableId, String programName) throws Exception {
        println("Processing imports...");
        monitor.setMessage("Processing imports for BSim");

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator externalSymbols = symbolTable.getExternalSymbols();

        int processedCount = 0;
        int importCount = 0;
        int apiUsageCount = 0;

        String insertImportSql = """
            INSERT INTO api_imports
            (executable_id, library_name, function_name, ordinal, import_address, import_type)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (executable_id, library_name, function_name, import_address) DO UPDATE SET
                ordinal = EXCLUDED.ordinal,
                import_type = EXCLUDED.import_type
            RETURNING id
            """;

        String insertUsageSql = """
            INSERT INTO function_api_usage
            (function_id, api_import_id, call_address, call_type)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (function_id, api_import_id, call_address) DO NOTHING
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE id_exe = ? AND addr <= ? ORDER BY addr DESC LIMIT 1";

        try (PreparedStatement importStmt = conn.prepareStatement(insertImportSql);
             PreparedStatement usageStmt = conn.prepareStatement(insertUsageSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            while (externalSymbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = externalSymbols.next();
                processedCount++;

                if (processedCount % 50 == 0) {
                    monitor.setMessage(String.format("Processing import %d: %s",
                        processedCount, symbol.getName()));
                }

                try {
                    // Extract import information
                    String functionName = symbol.getName();
                    String libraryName = getLibraryName(symbol);
                    Address symbolAddr = symbol.getAddress();

                    if (functionName == null || functionName.isEmpty()) {
                        continue;
                    }

                    // Insert import record
                    importStmt.setInt(1, executableId);
                    importStmt.setString(2, libraryName);
                    importStmt.setString(3, functionName);
                    importStmt.setNull(4, Types.INTEGER); // ordinal
                    importStmt.setLong(5, symbolAddr != null ? symbolAddr.getOffset() : 0);
                    importStmt.setString(6, "name");

                    ResultSet rs = importStmt.executeQuery();
                    if (rs.next()) {
                        long importId = rs.getLong("id");
                        importCount++;

                        // Find functions that use this import
                        apiUsageCount += findApiUsage(conn, usageStmt, funcIdStmt,
                            symbol, importId, executableId);
                    }
                    rs.close();

                } catch (SQLException e) {
                    printerr("Error processing import " + symbol.getName() + ": " + e.getMessage());
                }
            }
        }

        println(String.format("Processed %d imports, added %d imports with %d API usages",
            processedCount, importCount, apiUsageCount));
    }

    private void processExports(Connection conn, int executableId, String programName) throws Exception {
        println("Processing exports...");

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbolIterator(true);

        int exportCount = 0;

        String insertExportSql = """
            INSERT INTO api_exports
            (executable_id, function_name, export_address, ordinal, is_forwarded)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (executable_id, function_name, export_address) DO NOTHING
            """;

        try (PreparedStatement exportStmt = conn.prepareStatement(insertExportSql)) {

            while (symbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = symbols.next();

                if (symbol.isExternalEntryPoint() || symbol.isGlobal()) {
                    String functionName = symbol.getName();
                    Address symbolAddr = symbol.getAddress();

                    if (functionName != null && !functionName.isEmpty() && symbolAddr != null) {
                        exportStmt.setInt(1, executableId);
                        exportStmt.setString(2, functionName);
                        exportStmt.setLong(3, symbolAddr.getOffset());
                        exportStmt.setNull(4, Types.INTEGER); // ordinal
                        exportStmt.setBoolean(5, false); // is_forwarded

                        try {
                            exportStmt.executeUpdate();
                            exportCount++;
                        } catch (SQLException e) {
                            // Ignore duplicate key errors
                            if (!e.getMessage().contains("duplicate key")) {
                                throw e;
                            }
                        }
                    }
                }
            }
        }

        println(String.format("Added %d exports to database", exportCount));
    }

    private String getLibraryName(Symbol symbol) {
        ExternalLocation extLoc = symbol.getExternalLocation();
        if (extLoc != null) {
            String libraryName = extLoc.getLibraryName();
            if (libraryName != null && !libraryName.isEmpty()) {
                return libraryName;
            }
        }
        return "unknown";
    }

    private int findApiUsage(Connection conn, PreparedStatement usageStmt,
                           PreparedStatement funcIdStmt, Symbol apiSymbol,
                           long importId, int executableId) throws SQLException {

        int usageCount = 0;

        // Find all references to this API
        Reference[] references = getReferencesTo(apiSymbol.getAddress());

        for (Reference ref : references) {
            Address refAddr = ref.getFromAddress();

            // Find the function containing this reference
            funcIdStmt.setInt(1, executableId);
            funcIdStmt.setLong(2, refAddr.getOffset());

            ResultSet rs = funcIdStmt.executeQuery();
            if (rs.next()) {
                long functionId = rs.getLong("id");

                // Insert API usage
                usageStmt.setLong(1, functionId);
                usageStmt.setLong(2, importId);
                usageStmt.setLong(3, refAddr.getOffset());
                usageStmt.setString(4, getCallType(ref));

                try {
                    usageStmt.executeUpdate();
                    usageCount++;
                } catch (SQLException e) {
                    // Ignore duplicate key errors
                    if (!e.getMessage().contains("duplicate key")) {
                        throw e;
                    }
                }
            }
            rs.close();
        }

        return usageCount;
    }

    private String getCallType(Reference ref) {
        RefType refType = ref.getReferenceType();
        if (refType.isCall()) {
            return "direct";
        } else if (refType.isIndirect()) {
            return "indirect";
        } else if (refType.isJump()) {
            return "thunk";
        }
        return "unknown";
    }
}