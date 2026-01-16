// STEP 1: Add Programs to BSim Database (REQUIRED FIRST STEP)
//
// Primary ingestion script for adding executables to the PostgreSQL BSim database.
// This is the mandatory first step in the BSim analysis workflow - all other scripts
// depend on binaries being successfully added to the database through this script.
//
// UNIFIED VERSION SYSTEM SUPPORT:
// - Standard binaries: 1.03_D2Game.dll → version: 1.03, family: Unified
// - Exception binaries: Classic_1.03_Game.exe → version: 1.03, family: Classic
// - Automatic version detection and database field population
// - Validates naming conventions and prompts for non-standard formats
//
// PROCESSING MODES:
// - Single Program: Process currently opened program in Ghidra
// - All Programs: Batch process all programs in current project
// - Version Filter: Process programs matching specific version pattern
//
// DATABASE OPERATIONS:
// - Creates executable records with unified version metadata
// - Extracts and stores function information for similarity analysis
// - Populates base tables required for subsequent BSim operations
// - Uses remote PostgreSQL database (10.0.0.30:5432) for enterprise deployment
//
// WORKFLOW POSITION: Must be run before Step2 (signature generation)
//
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift B
// @menupath Tools.BSim.Step1 - Add Program to Database
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramDB;
import ghidra.base.project.GhidraProject;
import java.util.*;
import java.sql.*;
import java.util.regex.*;

public class Step1_AddProgramToBSimDatabase extends GhidraScript {

    // Default BSim database configuration
    private static final String DEFAULT_DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DEFAULT_DB_USER = "ben";
    private static final String DEFAULT_DB_PASS = "goodyx12";

    // Processing mode
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    // Flag to auto-update existing executables without prompting
    private boolean autoUpdateExisting = false;

    // Helper class for unified version parsing
    private static class UnifiedVersionInfo {
        String gameVersion = null;
        String familyType = "Unified";
        boolean isException = false;

        UnifiedVersionInfo(String executableName) {
            parseUnifiedName(executableName);
        }

        private void parseUnifiedName(String executableName) {
            if (executableName == null || executableName.isEmpty()) return;

            // Extract version from unified naming convention
            // Standard binaries: 1.03_D2Game.dll -> version: 1.03, family: Unified
            Pattern standardPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)_([A-Za-z0-9_]+)\\.(dll|exe)$");
            Matcher standardMatcher = standardPattern.matcher(executableName);

            if (standardMatcher.matches()) {
                gameVersion = standardMatcher.group(1);
                familyType = "Unified";
                isException = false;
                return;
            }

            // Exception binaries: Classic_1.03_Game.exe -> version: 1.03, family: Classic
            Pattern exceptionPattern = Pattern.compile("^(Classic|LoD)_(1\\.[0-9]+[a-z]?)_(Game|Diablo_II)\\.(exe|dll)$");
            Matcher exceptionMatcher = exceptionPattern.matcher(executableName);

            if (exceptionMatcher.matches()) {
                familyType = exceptionMatcher.group(1);
                gameVersion = exceptionMatcher.group(2);
                isException = true;
                return;
            }

            // Fallback: try to extract version from filename
            Pattern versionPattern = Pattern.compile("(1\\.[0-9]+[a-z]?)");
            Matcher versionMatcher = versionPattern.matcher(executableName);
            if (versionMatcher.find()) {
                gameVersion = versionMatcher.group(1);
                // Determine family based on version (older versions = Classic, newer = LoD)
                if (isClassicVersion(gameVersion)) {
                    familyType = "Classic";
                } else {
                    familyType = "LoD";
                }
            }
        }

        private boolean isClassicVersion(String version) {
            // Versions 1.00-1.06b are Classic era
            String[] classicVersions = {"1.00", "1.01", "1.02", "1.03", "1.04", "1.04b", "1.04c", "1.05", "1.05b", "1.06", "1.06b"};
            for (String classicVer : classicVersions) {
                if (version.equals(classicVer)) {
                    return true;
                }
            }
            return false;
        }

        public boolean isValidUnifiedFormat() {
            return gameVersion != null && !gameVersion.equals("Unknown");
        }

        public String getDisplayInfo() {
            if (!isValidUnifiedFormat()) {
                return "Invalid/Unknown format";
            }

            if (isException) {
                return String.format("%s %s (Exception Binary)", familyType, gameVersion);
            } else {
                return String.format("Unified %s (Standard Binary)", gameVersion);
            }
        }
    }

    @Override
    public void run() throws Exception {

        println("=== BSim Database Population Script ===");
        println("Supports version-aware naming: 1.03_D2Game.dll, Classic_1.03_Game.exe");

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

            println("BSim database population completed!");

        } catch (Exception e) {
            printerr("Error during BSim population: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Process only the currently open program
     */
    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();

        // Parse unified version information
        UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName);

        // Get the project path
        String programPath = "";
        DomainFile domainFile = currentProgram.getDomainFile();
        if (domainFile != null) {
            programPath = domainFile.getPathname();
        } else {
            programPath = currentProgram.getExecutablePath();
        }

        println("Program: " + programName);
        println("Project Path: " + programPath);
        println("Version Info: " + versionInfo.getDisplayInfo());
        println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());

        if (!versionInfo.isValidUnifiedFormat()) {
            boolean proceed = askYesNo("Non-Unified Format Detected",
                "This executable doesn't follow the unified naming convention.\n" +
                "Expected formats:\n" +
                "  Standard: 1.03_D2Game.dll\n" +
                "  Exception: Classic_1.03_Game.exe\n\n" +
                "Proceed anyway?");

            if (!proceed) {
                println("Operation cancelled - invalid naming format");
                return;
            }
        }

        boolean proceed = askYesNo("Confirm BSim Addition",
            String.format("Add program '%s' to BSim database?\n\nVersion Info: %s",
                programName, versionInfo.getDisplayInfo()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        addProgramToBSim(currentProgram, programName, programPath, versionInfo);
        println("Successfully added " + programName + " to BSim database!");
    }

    /**
     * Process all programs in the Ghidra project
     */
    private void processAllPrograms() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is open. Please open a Ghidra project first.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        // Collect all program files
        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        if (programFiles.isEmpty()) {
            popup("No programs found in the project.");
            return;
        }

        // Validate unified naming convention
        int validCount = 0;
        int invalidCount = 0;
        for (DomainFile file : programFiles) {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName());
            if (versionInfo.isValidUnifiedFormat()) {
                validCount++;
            } else {
                invalidCount++;
            }
        }

        println("Found " + programFiles.size() + " programs in project");
        println("  Valid unified format: " + validCount);
        println("  Invalid/unknown format: " + invalidCount);

        if (invalidCount > 0) {
            boolean proceed = askYesNo("Invalid Formats Detected",
                String.format("%d files don't follow unified naming convention.\n" +
                "These will be processed with limited version info.\n\n" +
                "Continue?", invalidCount));

            if (!proceed) {
                println("Operation cancelled due to naming format issues");
                return;
            }
        }

        boolean proceed = askYesNo("Process All Programs",
            String.format("Add all %d programs to BSim database?\n\nThis may take a while.", programFiles.size()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        // Ask if user wants to auto-update existing executables
        autoUpdateExisting = askYesNo("Auto-Update Existing",
            "Automatically update existing executables without prompting for each one?");

        int successCount = 0;
        int errorCount = 0;

        for (int i = 0; i < programFiles.size(); i++) {
            DomainFile file = programFiles.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, programFiles.size(), file.getName()));
            monitor.setProgress(i);

            if (monitor.isCancelled()) {
                println("Operation cancelled by user");
                break;
            }

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("Completed: %d successful, %d errors", successCount, errorCount));
    }

    /**
     * Process programs matching a version filter
     */
    private void processVersionFiltered() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is open. Please open a Ghidra project first.");
            return;
        }

        // Ask for version filter
        String versionFilter = askString("Version Filter",
            "Enter version pattern to match (e.g., '1.03', '1.13c', 'Classic'):", "1.03");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("Operation cancelled - no filter provided");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        // Collect matching program files
        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        // Filter by version using unified format
        List<DomainFile> matchingFiles = new ArrayList<>();
        for (DomainFile file : programFiles) {
            String fileName = file.getName();
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(fileName);

            // Match against version, family type, or filename
            if (fileName.toLowerCase().contains(versionFilter.toLowerCase()) ||
                (versionInfo.gameVersion != null && versionInfo.gameVersion.contains(versionFilter)) ||
                versionInfo.familyType.toLowerCase().contains(versionFilter.toLowerCase())) {
                matchingFiles.add(file);
            }
        }

        if (matchingFiles.isEmpty()) {
            popup("No programs matching filter '" + versionFilter + "' found.");
            return;
        }

        println("Found " + matchingFiles.size() + " programs matching '" + versionFilter + "'");

        // Show matching files with version info
        println("Matching programs:");
        for (DomainFile file : matchingFiles) {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName());
            println("  - " + file.getName() + " (" + versionInfo.getDisplayInfo() + ")");
        }

        boolean proceed = askYesNo("Process Filtered Programs",
            String.format("Add %d programs matching '%s' to BSim database?", matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        autoUpdateExisting = askYesNo("Auto-Update Existing",
            "Automatically update existing executables without prompting for each one?");

        int successCount = 0;
        int errorCount = 0;

        for (int i = 0; i < matchingFiles.size(); i++) {
            DomainFile file = matchingFiles.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, matchingFiles.size(), file.getName()));
            monitor.setProgress(i);

            if (monitor.isCancelled()) {
                println("Operation cancelled by user");
                break;
            }

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("Completed: %d successful, %d errors", successCount, errorCount));
    }

    /**
     * Recursively collect all program files from a folder
     */
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

    /**
     * Process a single project file
     */
    private void processProjectFile(DomainFile file) throws Exception {
        println("Processing: " + file.getPathname());

        // Open the program
        Program program = (Program) file.getDomainObject(this, true, false, monitor);

        try {
            String programName = program.getName();
            String programPath = file.getPathname();
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName);

            addProgramToBSim(program, programName, programPath, versionInfo);
            println("  Added " + programName + " (" + versionInfo.getDisplayInfo() + ") to BSim database");

        } finally {
            program.release(this);
        }
    }

    /**
     * Add a program to the BSim database with unified version support
     */
    private void addProgramToBSim(Program program, String programName, String programPath, UnifiedVersionInfo versionInfo) throws Exception {

        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {

            println("Connected to BSim database successfully");

            // Get or create executable with unified version info
            int executableId = getOrCreateExecutableUnified(conn, programName, programPath, versionInfo);
            println("Executable ID: " + executableId);

            // Process functions
            processFunctions(conn, executableId, programName, program);

            // Update materialized views for cross-version analysis
            refreshMaterializedViews(conn);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Get or create executable record with unified version support
     */
    private int getOrCreateExecutableUnified(Connection conn, String programName, String programPath, UnifiedVersionInfo versionInfo) throws SQLException {

        // Check if executable already exists
        String selectSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                int existingId = rs.getInt("id");
                println("Executable already exists in database with ID: " + existingId);

                // Update version info using unified schema function
                try {
                    String updateSql = "SELECT populate_version_fields_from_filename()";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                        updateStmt.executeQuery();
                        println("  Updated version fields using unified system");
                    }
                } catch (SQLException e) {
                    println("  Note: Could not update version fields (function may not exist)");
                }

                // Check if auto-update is enabled
                if (!autoUpdateExisting) {
                    boolean update = askYesNo("Executable Exists",
                        "Executable already exists in database. Update function data?");
                    if (!update) {
                        throw new RuntimeException("Operation cancelled - executable exists");
                    }
                } else {
                    println("  Auto-updating existing executable...");
                }
                return existingId;
            }
        }

        // Create new executable record with unified version system
        String insertSql = "INSERT INTO exetable (name_exec, md5, architecture, ingest_date, game_version) " +
            "VALUES (?, ?, ?, NOW(), ?) RETURNING id";

        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
            stmt.setString(1, programName);
            stmt.setString(2, generateMD5(programName));
            stmt.setString(3, getArchitectureString());
            stmt.setString(4, versionInfo.gameVersion);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int newId = rs.getInt("id");
                println("Created new executable record with ID: " + newId);
                println("  " + versionInfo.getDisplayInfo());

                // Trigger version field population
                try {
                    String populateSql = "SELECT populate_version_fields_from_filename()";
                    try (PreparedStatement populateStmt = conn.prepareStatement(populateSql)) {
                        populateStmt.executeQuery();
                        println("  Version fields populated using unified schema");
                    }
                } catch (SQLException e) {
                    println("  Note: Version field population function not available");
                }

                return newId;
            }
        } catch (SQLException e) {
            // Fall back to basic insert without version field
            println("  Note: Using basic insert (unified version schema not available)");
            String basicInsertSql = "INSERT INTO exetable (name_exec, md5, architecture, ingest_date) " +
                "VALUES (?, ?, ?, NOW()) RETURNING id";
            try (PreparedStatement stmt = conn.prepareStatement(basicInsertSql)) {
                stmt.setString(1, programName);
                stmt.setString(2, generateMD5(programName));
                stmt.setString(3, getArchitectureString());

                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    int newId = rs.getInt("id");
                    println("Created new executable record with ID: " + newId);
                    return newId;
                }
            }
        }

        throw new SQLException("Failed to create executable record");
    }

    /**
     * Process all functions in the program and add to database
     */
    private void processFunctions(Connection conn, int executableId, String programName, Program program) throws Exception {

        println("Processing functions...");
        monitor.setMessage("Processing functions for BSim");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int functionCount = 0;
        int addedCount = 0;
        int skippedCount = 0;

        String checkSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ? AND addr = ?";
        String insertSql = "INSERT INTO desctable (name_func, id_exe, id_signature, flags, addr) VALUES (?, ?, ?, ?, ?)";

        try (PreparedStatement checkStmt = conn.prepareStatement(checkSql);
             PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                functionCount++;

                if (functionCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        functionCount, function.getName()));
                }

                try {
                    // Check if function already exists
                    checkStmt.setString(1, function.getName());
                    checkStmt.setInt(2, executableId);
                    checkStmt.setLong(3, function.getEntryPoint().getOffset());
                    ResultSet rs = checkStmt.executeQuery();

                    if (rs.next()) {
                        skippedCount++;
                        rs.close();
                        continue;
                    }
                    rs.close();

                    // Add function to database
                    insertStmt.setString(1, function.getName());
                    insertStmt.setInt(2, executableId);
                    insertStmt.setLong(3, generateSignatureId(function));
                    insertStmt.setInt(4, 0);
                    insertStmt.setLong(5, function.getEntryPoint().getOffset());

                    int rowsAffected = insertStmt.executeUpdate();
                    if (rowsAffected > 0) {
                        addedCount++;
                    }

                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate key")) {
                        printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                    } else {
                        skippedCount++;
                    }
                }
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d functions, added %d new, skipped %d existing",
            functionCount, addedCount, skippedCount));
    }

    /**
     * Refresh materialized views for cross-version analysis
     */
    private void refreshMaterializedViews(Connection conn) throws SQLException {
        println("Refreshing materialized views for cross-version analysis...");

        try (Statement stmt = conn.createStatement()) {
            // Use the unified system refresh function
            stmt.execute("SELECT refresh_cross_version_data()");
            println("Refreshed cross-version materialized views");
        } catch (SQLException e) {
            // Fall back to manual refresh
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("REFRESH MATERIALIZED VIEW cross_version_functions");
                println("Refreshed cross_version_functions view");
            } catch (SQLException e2) {
                println("Note: Could not refresh materialized views");
            }
        }
    }

    /**
     * Generate MD5 hash for executable
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
     * Get architecture as string for unified schema
     */
    private String getArchitectureString() {
        String arch = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        if (arch.contains("x86") && arch.contains("64")) {
            return "x64";
        } else if (arch.contains("x86")) {
            return "x86";
        } else {
            return "unknown";
        }
    }

    /**
     * Generate signature ID for function
     */
    private long generateSignatureId(Function function) {
        String signature = function.getName() + "_" + function.getBody().getNumAddresses();
        return Math.abs(signature.hashCode());
    }
}