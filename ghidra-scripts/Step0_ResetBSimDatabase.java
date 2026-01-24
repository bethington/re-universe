// STEP 0: Reset BSim Database (DESTRUCTIVE - USE WITH CAUTION)
//
// Wipes all program and function data from the BSim database, returning it to
// a clean state ready for fresh data import starting with Step1.
//
// THIS SCRIPT WILL DELETE:
// - All executables (exetable)
// - All functions (desctable)
// - All enhanced signatures (enhanced_signatures)
// - All function comments (function_comments)
// - All cross-references and relationships
//
// THE FOLLOWING ARE PRESERVED:
// - Database schema and tables
// - Game version definitions (game_versions)
// - Database configuration
//
// USE CASE: Starting fresh with a new set of binaries or after major changes
// to the analysis workflow that require re-processing everything.
//
// WARNING: This operation is IRREVERSIBLE. All data will be permanently deleted.
//
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift 0
// @menupath Tools.BSim.Step0 - Reset Database (DANGER)

import ghidra.app.script.GhidraScript;
import java.sql.*;
import java.util.*;

public class Step0_ResetBSimDatabase extends GhidraScript {

    private static final String DEFAULT_DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DEFAULT_DB_USER = "ben";
    private static final String DEFAULT_DB_PASS = "goodyx12";

    @Override
    public void run() throws Exception {
        println("╔═══════════════════════════════════════════════════════════════╗");
        println("║          STEP 0: RESET BSIM DATABASE                          ║");
        println("║                                                               ║");
        println("║  ⚠️  WARNING: THIS WILL DELETE ALL DATA! ⚠️                    ║");
        println("╚═══════════════════════════════════════════════════════════════╝");
        println("");

        // First confirmation
        boolean proceed1 = askYesNo("⚠️ DATABASE RESET WARNING ⚠️",
            "This will PERMANENTLY DELETE all data from the BSim database:\n\n" +
            "• All executables and their metadata\n" +
            "• All function records and signatures\n" +
            "• All enhanced signatures\n" +
            "• All function comments\n\n" +
            "This action CANNOT be undone!\n\n" +
            "Are you SURE you want to proceed?");

        if (!proceed1) {
            println("Operation cancelled by user (first confirmation)");
            return;
        }

        // Connect and show current data counts
        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {
            println("Connected to BSim database");
            println("");

            // Get current data counts
            Map<String, Integer> counts = getCurrentDataCounts(conn);
            
            println("Current Database Contents:");
            println("═══════════════════════════════════════════════════════════════");
            for (Map.Entry<String, Integer> entry : counts.entrySet()) {
                println(String.format("  %-30s: %,d records", entry.getKey(), entry.getValue()));
            }
            println("═══════════════════════════════════════════════════════════════");
            println("");

            int totalRecords = counts.values().stream().mapToInt(Integer::intValue).sum();
            
            if (totalRecords == 0) {
                println("Database is already empty. Nothing to delete.");
                popup("Database is already empty!\n\nNo data to delete.");
                return;
            }

            // Second confirmation with record count
            boolean proceed2 = askYesNo("⚠️ FINAL CONFIRMATION ⚠️",
                String.format("You are about to DELETE %,d total records!\n\n" +
                    "This includes:\n" +
                    "• %,d executables\n" +
                    "• %,d functions\n" +
                    "• %,d enhanced signatures\n" +
                    "• %,d function comments\n\n" +
                    "Type 'YES' in your mind and click Yes to confirm.\n\n" +
                    "LAST CHANCE TO CANCEL!",
                    totalRecords,
                    counts.getOrDefault("Executables (exetable)", 0),
                    counts.getOrDefault("Functions (desctable)", 0),
                    counts.getOrDefault("Enhanced Signatures", 0),
                    counts.getOrDefault("Function Comments", 0)));

            if (!proceed2) {
                println("Operation cancelled by user (final confirmation)");
                return;
            }

            // Perform the reset
            println("");
            println("🔥 INITIATING DATABASE RESET...");
            println("");

            // Delete in correct order (respecting foreign key constraints)
            deleteAllData(conn);

            // Verify deletion
            Map<String, Integer> afterCounts = getCurrentDataCounts(conn);
            int remainingRecords = afterCounts.values().stream().mapToInt(Integer::intValue).sum();

            println("");
            println("═══════════════════════════════════════════════════════════════");
            println("                    RESET COMPLETE");
            println("═══════════════════════════════════════════════════════════════");
            println(String.format("  Records deleted: %,d", totalRecords));
            println(String.format("  Records remaining: %,d", remainingRecords));
            println("");
            println("The database is now ready for fresh data import.");
            println("Run Step1_AddProgramToBSimDatabase to begin populating.");
            println("═══════════════════════════════════════════════════════════════");

            popup("Database Reset Complete!\n\n" +
                String.format("Deleted %,d records.\n\n", totalRecords) +
                "The database is now empty and ready for fresh data.\n" +
                "Run Step1 to begin importing programs.");

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Get current record counts for all relevant tables
     */
    private Map<String, Integer> getCurrentDataCounts(Connection conn) throws SQLException {
        Map<String, Integer> counts = new LinkedHashMap<>();  // Preserve order

        // Check each table
        counts.put("Executables (exetable)", getTableCount(conn, "exetable"));
        counts.put("Functions (desctable)", getTableCount(conn, "desctable"));
        counts.put("Enhanced Signatures", getTableCount(conn, "enhanced_signatures"));
        counts.put("Function Comments", getTableCount(conn, "function_comments"));
        counts.put("Vector Table (vectable)", getTableCount(conn, "vectable"));
        counts.put("Callgraph Entries", getTableCount(conn, "callgraphtable"));

        return counts;
    }

    /**
     * Get row count for a table (returns 0 if table doesn't exist)
     */
    private int getTableCount(Connection conn, String tableName) {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + tableName)) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            // Table might not exist
            println("  (Table '" + tableName + "' not found or empty)");
        }
        return 0;
    }

    /**
     * Delete all data from relevant tables in correct order
     */
    private void deleteAllData(Connection conn) throws SQLException {
        conn.setAutoCommit(false);
        
        try {
            // Delete in order to respect foreign key constraints
            // Child tables first, then parent tables
            
            // 1. Delete enhanced signatures (references desctable)
            deleteFromTable(conn, "enhanced_signatures", "Enhanced Signatures");
            
            // 2. Delete function comments (references desctable)
            deleteFromTable(conn, "function_comments", "Function Comments");
            
            // 3. Delete callgraph entries (references desctable)
            deleteFromTable(conn, "callgraphtable", "Callgraph Entries");
            
            // 4. Delete vector table entries (references desctable)  
            deleteFromTable(conn, "vectable", "Vector Table");
            
            // 5. Delete functions/desctable (references exetable)
            deleteFromTable(conn, "desctable", "Functions");
            
            // 6. Delete executables (parent table)
            deleteFromTable(conn, "exetable", "Executables");

            conn.commit();
            println("");
            println("✓ All data successfully deleted");
            
        } catch (SQLException e) {
            conn.rollback();
            printerr("Error during deletion, rolling back: " + e.getMessage());
            throw e;
        } finally {
            conn.setAutoCommit(true);
        }
    }

    /**
     * Delete all rows from a table
     */
    private void deleteFromTable(Connection conn, String tableName, String displayName) {
        try (Statement stmt = conn.createStatement()) {
            // Use TRUNCATE for speed, fall back to DELETE if TRUNCATE fails
            try {
                stmt.execute("TRUNCATE TABLE " + tableName + " CASCADE");
                println("  ✓ Truncated " + displayName);
            } catch (SQLException truncateError) {
                // TRUNCATE might fail due to permissions or locks, try DELETE
                int deleted = stmt.executeUpdate("DELETE FROM " + tableName);
                println("  ✓ Deleted " + deleted + " records from " + displayName);
            }
        } catch (SQLException e) {
            println("  ⏭ Skipped " + displayName + " (table may not exist: " + e.getMessage() + ")");
        }
    }
}
