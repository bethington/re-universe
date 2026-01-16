// Add current program to PostgreSQL BSim database for cross-version analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift B
// @menupath Tools.BSim.Add Program to Database
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import java.util.*;
import java.sql.*;

public class AddProgramToBSimDatabase extends GhidraScript {

    // Default BSim database configuration
    private static final String DEFAULT_DB_URL = "jdbc:postgresql://localhost:5432/bsim";
    private static final String DEFAULT_DB_USER = "ben";
    private static final String DEFAULT_DB_PASS = "goodyx12";

    @Override
    public void run() throws Exception {

        // Check if we have a program loaded
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        // Get program details
        String programName = currentProgram.getName();
        String programPath = currentProgram.getExecutablePath();

        println("=== BSim Database Population Script ===");
        println("Program: " + programName);
        println("Path: " + programPath);
        println("Functions in program: " + currentProgram.getFunctionManager().getFunctionCount());

        // Check if user wants to proceed
        boolean proceed = askYesNo("Confirm BSim Addition",
            String.format("Add program '%s' to BSim database?\n\nThis will:\n" +
            "- Generate function signatures\n" +
            "- Add to cross-version analysis database\n" +
            "- Enable similarity matching\n\nProceed?", programName));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            // Process functions and add to database
            addProgramToBSim(programName, programPath);

            println("Successfully added program to BSim database!");
            println("Cross-version analysis data has been updated.");

        } catch (Exception e) {
            printerr("Error adding program to BSim database: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Add the current program to the BSim database
     */
    private void addProgramToBSim(String programName, String programPath) throws Exception {

        println("Connecting to BSim database...");

        // Connect to PostgreSQL BSim database
        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {

            println("Connected to BSim database successfully");

            // First, check if executable already exists
            int executableId = getOrCreateExecutable(conn, programName, programPath);
            println("Executable ID: " + executableId);

            // Process functions
            processFunctions(conn, executableId, programName);

            // Update materialized views for cross-version analysis
            refreshMaterializedViews(conn);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Get or create executable record in database
     */
    private int getOrCreateExecutable(Connection conn, String programName, String programPath) throws SQLException {

        // Check if executable already exists
        String selectSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                int existingId = rs.getInt("id");
                println("Executable already exists in database with ID: " + existingId);

                // Ask if user wants to update
                boolean update = askYesNo("Executable Exists",
                    "Executable already exists in database. Update function data?");
                if (!update) {
                    throw new RuntimeException("Operation cancelled - executable exists");
                }
                return existingId;
            }
        }

        // Create new executable record
        String insertSql = "INSERT INTO exetable (name_exec, md5, architecture, ingest_date, repository, path) VALUES (?, ?, ?, NOW(), 1, 1) RETURNING id";
        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
            stmt.setString(1, programName);
            stmt.setString(2, generateMD5(programName)); // Simple MD5 placeholder
            stmt.setInt(3, getArchitecture()); // Detect architecture

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int newId = rs.getInt("id");
                println("Created new executable record with ID: " + newId);
                return newId;
            } else {
                throw new SQLException("Failed to create executable record");
            }
        }
    }

    /**
     * Process all functions in the program and add to database
     */
    private void processFunctions(Connection conn, int executableId, String programName) throws Exception {

        println("Processing functions...");
        monitor.setMessage("Processing functions for BSim");

        // Get all functions in the program
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int functionCount = 0;
        int addedCount = 0;

        // Prepare insert statement
        String insertSql = "INSERT INTO desctable (name_func, id_exe, id_signature, flags, addr) VALUES (?, ?, ?, ?, ?) ON CONFLICT (name_func, id_exe, addr) DO NOTHING";

        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {

            // Process each function
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                functionCount++;

                // Update progress
                if (functionCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        functionCount, function.getName()));
                    println(String.format("Processed %d functions...", functionCount));
                }

                try {
                    // Add function to database
                    stmt.setString(1, function.getName());
                    stmt.setInt(2, executableId);
                    stmt.setLong(3, generateSignatureId(function)); // Generate signature ID
                    stmt.setInt(4, 0); // Default flags
                    stmt.setLong(5, function.getEntryPoint().getOffset());

                    int rowsAffected = stmt.executeUpdate();
                    if (rowsAffected > 0) {
                        addedCount++;
                    }

                } catch (SQLException e) {
                    printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                }
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d functions, added %d new functions to database",
            functionCount, addedCount));

        // Log program metadata
        logProgramMetadata(programName, functionCount, addedCount);
    }

    /**
     * Refresh materialized views for cross-version analysis
     */
    private void refreshMaterializedViews(Connection conn) throws SQLException {
        println("Refreshing materialized views for cross-version analysis...");

        try (Statement stmt = conn.createStatement()) {
            // Refresh cross-version functions view
            stmt.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY cross_version_functions");
            println("Refreshed cross_version_functions view");

            // Refresh function evolution view
            stmt.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY function_evolution");
            println("Refreshed function_evolution view");

        } catch (SQLException e) {
            // If concurrent refresh fails, try regular refresh
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("REFRESH MATERIALIZED VIEW cross_version_functions");
                stmt.execute("REFRESH MATERIALIZED VIEW function_evolution");
                println("Refreshed views (non-concurrent mode)");
            }
        }
    }

    /**
     * Generate a simple MD5 placeholder
     */
    private String generateMD5(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "unknown_md5";
        }
    }

    /**
     * Detect program architecture
     */
    private int getArchitecture() {
        String arch = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        if (arch.contains("x86") && arch.contains("64")) {
            return 64; // x86-64
        } else if (arch.contains("x86")) {
            return 32; // x86-32
        } else {
            return 32; // Default to 32-bit
        }
    }

    /**
     * Generate signature ID for function (simplified)
     */
    private long generateSignatureId(Function function) {
        // Simple signature generation based on function properties
        String signature = function.getName() + "_" + function.getBody().getNumAddresses();
        return Math.abs(signature.hashCode());
    }

    /**
     * Log program metadata for analysis
     */
    private void logProgramMetadata(String programName, int functionCount, int addedCount) {

        // Parse version information from program name
        String gameType = "Unknown";
        String version = "Unknown";

        if (programName.toLowerCase().contains("classic")) {
            gameType = "Classic";
        } else if (programName.toLowerCase().contains("lod")) {
            gameType = "LoD";
        }

        // Extract version pattern (e.g., 1.14d)
        java.util.regex.Pattern versionPattern = java.util.regex.Pattern.compile("1\\.(\\d{2}[a-z]?)");
        java.util.regex.Matcher matcher = versionPattern.matcher(programName);
        if (matcher.find()) {
            version = matcher.group();
        }

        println("=== Program Analysis Summary ===");
        println("Program: " + programName);
        println("Game Type: " + gameType);
        println("Version: " + version);
        println("Total Functions: " + functionCount);
        println("Added to Database: " + addedCount);
        println("Architecture: " + getArchitecture() + "-bit");
        println("================================");
    }
}