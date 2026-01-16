// Simple BSim Database Population Script
// Directly adds program functions to BSim database without complex signature generation
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift P
// @menupath Tools.BSim.Simple Population

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.sql.*;

public class SimpleBSimPopulation extends GhidraScript {

    @Override
    public void run() throws Exception {

        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();

        println("=== Simple BSim Population Script ===");
        println("Program: " + programName);
        println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());

        boolean proceed = askYesNo("Add to BSim Database",
            "Add '" + programName + "' to BSim database for cross-version analysis?");

        if (!proceed) {
            println("Operation cancelled");
            return;
        }

        try {
            populateDatabase(programName);
            println("SUCCESS: Program added to BSim database!");
        } catch (Exception e) {
            printerr("ERROR: " + e.getMessage());
            throw e;
        }
    }

    private void populateDatabase(String programName) throws Exception {
        String url = "jdbc:postgresql://localhost:5432/bsim";
        String user = "ben";
        String pass = "goodyx12";

        try (Connection conn = DriverManager.getConnection(url, user, pass)) {

            // Create or get executable record
            int execId = createExecutableRecord(conn, programName);
            println("Executable ID: " + execId);

            // Add functions
            addFunctions(conn, execId);

            // Refresh views
            refreshViews(conn);

            println("Database population completed successfully");
        }
    }

    private int createExecutableRecord(Connection conn, String programName) throws SQLException {

        // Check if exists
        String selectSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                println("Executable already exists, updating functions...");
                return rs.getInt("id");
            }
        }

        // Create new record
        String insertSql = "INSERT INTO exetable (name_exec, md5, architecture, ingest_date) VALUES (?, ?, ?, NOW()) RETURNING id";
        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
            stmt.setString(1, programName);
            stmt.setString(2, "script_generated_" + System.currentTimeMillis());
            stmt.setInt(3, 32); // Default to 32-bit

            ResultSet rs = stmt.executeQuery();
            rs.next();
            int newId = rs.getInt("id");
            println("Created new executable record: " + newId);
            return newId;
        }
    }

    private void addFunctions(Connection conn, int execId) throws Exception {
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        String sql = "INSERT INTO desctable (name_func, id_exe, id_signature, flags, addr) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            int count = 0;

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                count++;

                if (count % 100 == 0) {
                    println("Processed " + count + " functions...");
                }

                stmt.setString(1, func.getName());
                stmt.setInt(2, execId);
                stmt.setLong(3, Math.abs(func.getName().hashCode())); // Simple signature
                stmt.setInt(4, 0);
                stmt.setLong(5, func.getEntryPoint().getOffset());

                stmt.addBatch();

                if (count % 1000 == 0) {
                    stmt.executeBatch();
                }
            }

            stmt.executeBatch();
            println("Added " + count + " functions to database");
        }
    }

    private void refreshViews(Connection conn) throws SQLException {
        println("Refreshing materialized views...");
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("REFRESH MATERIALIZED VIEW cross_version_functions");
            stmt.execute("REFRESH MATERIALIZED VIEW function_evolution");
            println("Views refreshed successfully");
        }
    }
}