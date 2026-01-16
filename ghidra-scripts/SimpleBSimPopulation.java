// Simple BSim Database Population Script
// Directly adds program functions to BSim database without complex signature generation
// Supports: Single program, All programs in project, or Version-filtered programs
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift P
// @menupath Tools.BSim.Simple Population

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;

public class SimpleBSimPopulation extends GhidraScript {

    private static final String DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DB_USER = "ben";
    private static final String DB_PASS = "goodyx12";

    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    @Override
    public void run() throws Exception {

        println("=== Simple BSim Population Script ===");

        // Ask user which mode to use
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to populate the BSim database?", Arrays.asList(modes), MODE_SINGLE);

        if (selectedMode == null) {
            println("Operation cancelled by user");
            return;
        }

        println("Selected mode: " + selectedMode);

        try {
            if (MODE_SINGLE.equals(selectedMode)) {
                processSingleProgram();
            } else if (MODE_ALL.equals(selectedMode)) {
                processAllPrograms();
            } else if (MODE_VERSION.equals(selectedMode)) {
                processVersionFiltered();
            }

            println("BSim population completed!");

        } catch (Exception e) {
            printerr("ERROR: " + e.getMessage());
            throw e;
        }
    }

    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        println("Program: " + programName);
        println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());

        boolean proceed = askYesNo("Add to BSim Database",
            "Add '" + programName + "' to BSim database for cross-version analysis?");

        if (!proceed) {
            println("Operation cancelled");
            return;
        }

        populateDatabase(currentProgram, programName);
        println("SUCCESS: Program added to BSim database!");
    }

    private void processAllPrograms() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is open. Please open a Ghidra project first.");
            return;
        }

        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(project.getProjectData().getRootFolder(), programFiles);

        if (programFiles.isEmpty()) {
            popup("No programs found in the project.");
            return;
        }

        println("Found " + programFiles.size() + " programs in project");

        boolean proceed = askYesNo("Process All Programs",
            String.format("Add all %d programs to BSim database?", programFiles.size()));

        if (!proceed) {
            println("Operation cancelled");
            return;
        }

        processProgramFiles(programFiles);
    }

    private void processVersionFiltered() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is open. Please open a Ghidra project first.");
            return;
        }

        String versionFilter = askString("Version Filter",
            "Enter version pattern to match (e.g., '1.14', 'LoD', 'Classic'):", "1.14");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("Operation cancelled - no filter provided");
            return;
        }

        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(project.getProjectData().getRootFolder(), programFiles);

        List<DomainFile> matchingFiles = new ArrayList<>();
        for (DomainFile file : programFiles) {
            String path = file.getPathname().toLowerCase();
            if (path.contains(versionFilter.toLowerCase())) {
                matchingFiles.add(file);
            }
        }

        if (matchingFiles.isEmpty()) {
            popup("No programs matching filter '" + versionFilter + "' found.");
            return;
        }

        println("Found " + matchingFiles.size() + " programs matching '" + versionFilter + "'");

        boolean proceed = askYesNo("Process Filtered Programs",
            String.format("Add %d programs matching '%s' to BSim database?", matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled");
            return;
        }

        processProgramFiles(matchingFiles);
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

    private void processProgramFiles(List<DomainFile> files) throws Exception {
        int successCount = 0;
        int errorCount = 0;

        for (int i = 0; i < files.size(); i++) {
            DomainFile file = files.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, files.size(), file.getName()));

            if (monitor.isCancelled()) {
                println("Operation cancelled by user");
                break;
            }

            try {
                Program program = (Program) file.getDomainObject(this, true, false, monitor);
                try {
                    populateDatabase(program, program.getName());
                    println("  Added: " + file.getName());
                    successCount++;
                } finally {
                    program.release(this);
                }
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("Completed: %d successful, %d errors", successCount, errorCount));
    }

    private void populateDatabase(Program program, String programName) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            int execId = createExecutableRecord(conn, programName);
            addFunctions(conn, execId, program);
            refreshViews(conn);
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

    private void addFunctions(Connection conn, int execId, Program program) throws Exception {
        FunctionManager funcManager = program.getFunctionManager();
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