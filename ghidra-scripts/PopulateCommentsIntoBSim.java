// Populate function comments into BSim database for enhanced analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift C
// @menupath Tools.BSim.Populate Comments

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import java.sql.*;
import java.util.*;

public class PopulateCommentsIntoBSim extends GhidraScript {

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
        println("=== BSim Comment Population Script ===");
        println("Program: " + programName);

        // Count functions with comments
        int functionsWithComments = countFunctionsWithComments();
        println("Functions with comments: " + functionsWithComments);

        if (functionsWithComments == 0) {
            popup("No functions with comments found in this program.");
            return;
        }

        boolean proceed = askYesNo("Populate Comments",
            String.format("Add %d function comments to BSim database?\n\nThis will:\n" +
            "- Extract all function comments\n" +
            "- Associate comments with BSim function records\n" +
            "- Enable comment-based analysis\n\nProceed?", functionsWithComments));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            populateComments(programName);
            println("Successfully populated comments into BSim database!");

        } catch (Exception e) {
            printerr("Error populating comments: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private int countFunctionsWithComments() {
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);
        int count = 0;

        while (functions.hasNext()) {
            Function func = functions.next();
            if (hasComments(func)) {
                count++;
            }
        }
        return count;
    }

    private boolean hasComments(Function func) {
        CodeUnit cu = currentProgram.getListing().getCodeUnitAt(func.getEntryPoint());
        if (cu == null) return false;

        String plateComment = cu.getComment(CodeUnit.PLATE_COMMENT);
        String preComment = cu.getComment(CodeUnit.PRE_COMMENT);
        String postComment = cu.getComment(CodeUnit.POST_COMMENT);
        String eolComment = cu.getComment(CodeUnit.EOL_COMMENT);

        return (plateComment != null && !plateComment.trim().isEmpty()) ||
               (preComment != null && !preComment.trim().isEmpty()) ||
               (postComment != null && !postComment.trim().isEmpty()) ||
               (eolComment != null && !eolComment.trim().isEmpty());
    }

    private void populateComments(String programName) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {
            println("Connected to BSim database successfully");

            // Get executable ID
            int executableId = getExecutableId(conn, programName);
            if (executableId == -1) {
                throw new RuntimeException("Executable not found in BSim database. Please populate functions first.");
            }

            println("Executable ID: " + executableId);

            // Process function comments
            processComments(conn, executableId, programName);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
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

    private void processComments(Connection conn, int executableId, String programName) throws Exception {
        println("Processing function comments...");
        monitor.setMessage("Processing function comments for BSim");

        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int processedCount = 0;
        int commentCount = 0;

        // Prepare statements for comment insertion
        String insertCommentSql = "INSERT INTO core_comment (content, content_html, entity_type, entity_id, entity_name, created_at, updated_at, is_deleted, parent_id, user_id) VALUES (?, ?, ?, ?, ?, NOW(), NOW(), false, NULL, 1) ON CONFLICT DO NOTHING";

        // Get function ID from BSim database
        String getFunctionIdSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";

        try (PreparedStatement commentStmt = conn.prepareStatement(insertCommentSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                processedCount++;

                if (processedCount % 50 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        processedCount, function.getName()));
                }

                if (hasComments(function)) {
                    // Get BSim function ID
                    funcIdStmt.setString(1, function.getName());
                    funcIdStmt.setInt(2, executableId);
                    ResultSet rs = funcIdStmt.executeQuery();

                    if (rs.next()) {
                        long functionId = rs.getLong("id");

                        // Extract and insert all comment types
                        commentCount += insertFunctionComments(commentStmt, function, functionId);
                    }
                    rs.close();
                }
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d functions, added %d comments to database",
            processedCount, commentCount));
    }

    private int insertFunctionComments(PreparedStatement commentStmt, Function function, long functionId) throws SQLException {
        CodeUnit cu = currentProgram.getListing().getCodeUnitAt(function.getEntryPoint());
        if (cu == null) return 0;

        int insertedCount = 0;

        // Insert different comment types
        String[] commentTypes = {"PLATE", "PRE", "POST", "EOL"};
        int[] commentCodes = {CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT,
                              CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT};

        for (int i = 0; i < commentTypes.length; i++) {
            String comment = cu.getComment(commentCodes[i]);
            if (comment != null && !comment.trim().isEmpty()) {

                // Clean and format comment
                String cleanComment = comment.trim();
                String htmlComment = convertToHtml(cleanComment);

                commentStmt.setString(1, cleanComment);
                commentStmt.setString(2, htmlComment);
                commentStmt.setString(3, "function");
                commentStmt.setLong(4, functionId);
                commentStmt.setString(5, function.getName() + "_" + commentTypes[i]);

                try {
                    int rowsAffected = commentStmt.executeUpdate();
                    if (rowsAffected > 0) {
                        insertedCount++;
                    }
                } catch (SQLException e) {
                    printerr("Error inserting comment for function " + function.getName() +
                            " (" + commentTypes[i] + "): " + e.getMessage());
                }
            }
        }

        return insertedCount;
    }

    private String convertToHtml(String comment) {
        // Basic HTML conversion for comment content
        return comment
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
            .replace("\n", "<br>")
            .replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;");
    }
}