// STEP 1: Add Programs to BSim Database (REQUIRED FIRST STEP)
//
// Primary ingestion script for adding executables to the PostgreSQL BSim database.
// This is the mandatory first step in the BSim analysis workflow - all other scripts
// depend on binaries being successfully added to the database through this script.
//
// UNIFIED VERSION SYSTEM SUPPORT:
// - Folder structure parsing (PREFERRED): /Classic/1.01/, /LoD/1.07/, /PD2/
// - Mod support with base version tracking: PD2 → 1.13c-PD2, PoD → 1.13c-PoD
// - Filename parsing (fallback): 1.03_D2Game.dll, Classic_1.03_Game.exe
// - Automatic version detection from project organization
// - Supports mixed naming conventions during migration
// - Validates detected information and provides clear feedback
//
// PROCESSING MODES:
// - Single Program: Process currently opened program in Ghidra
// - All Programs: Batch process all programs in current project
// - Version Filter: Process programs matching specific version pattern
//
// DATABASE OPERATIONS:
// - Creates executable records with unified version metadata
// - Extracts and stores function information for similarity analysis
// - Applies comprehensive function tagging (library, game logic, utility, mod-relevant)
// - Analyzes function complexity, calling patterns, and architectural features
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
        String detectionMethod = "unknown";

        UnifiedVersionInfo(String executableName, String projectPath) {
            // Try folder structure parsing first (preferred method)
            if (parseFromFolderStructure(projectPath)) {
                detectionMethod = "folder_structure";
                return;
            }

            // Fallback to filename parsing
            parseUnifiedName(executableName);
            if (gameVersion != null) {
                detectionMethod = "filename";
            } else {
                detectionMethod = "fallback";
                familyType = "Unknown";
                gameVersion = "Unknown";
            }
        }

        // Legacy constructor for backward compatibility
        UnifiedVersionInfo(String executableName) {
            this(executableName, null);
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

        /**
         * Parse version and family information from folder structure
         * Expected structure: /Classic/1.01/, /LoD/1.07/, /PD2/
         */
        private boolean parseFromFolderStructure(String projectPath) {
            if (projectPath == null || projectPath.isEmpty()) {
                return false;
            }

            // Normalize path separators and remove leading/trailing slashes
            String normalizedPath = projectPath.replace("\\", "/").replaceAll("^/+|/+$", "");

            // Split path into components
            String[] pathComponents = normalizedPath.split("/");

            // Look for patterns in the path components
            for (int i = 0; i < pathComponents.length; i++) {
                String component = pathComponents[i];

                // Check for family indicators (Classic, LoD, and mods)
                if (component.equals("Classic") || component.equals("LoD") || isModFolder(component)) {
                    familyType = component;

                    // Look for version in next component
                    if (i + 1 < pathComponents.length) {
                        String nextComponent = pathComponents[i + 1];

                        // Check if next component looks like a version (1.xx format)
                        Pattern versionPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)$");
                        Matcher versionMatcher = versionPattern.matcher(nextComponent);

                        if (versionMatcher.matches()) {
                            gameVersion = nextComponent;

                            // Handle mods and standard versions
                            if (isModFolder(component)) {
                                String baseVersion = getModBaseVersion(component);
                                familyType = component;
                                isException = true;
                                // Track as mod with base version (e.g., "1.13c-PD2")
                                gameVersion = baseVersion + "-" + component;
                            } else {
                                // Classic/LoD with proper version
                                isException = (component.equals("Classic") || component.equals("LoD"));
                            }

                            return true;
                        }
                    }

                    // Special case: Mod folder without version subfolder
                    if (isModFolder(component)) {
                        String baseVersion = getModBaseVersion(component);
                        familyType = component;
                        gameVersion = baseVersion + "-" + component;
                        isException = true;
                        return true;
                    }
                }
            }

            return false;
        }

        /**
         * Check if a folder component represents a mod
         */
        private boolean isModFolder(String component) {
            // Known Diablo 2 mods - add more as needed
            String[] knownMods = {"PD2", "PoD", "MedianXL", "Eastern Sun", "Requiem"};
            for (String mod : knownMods) {
                if (component.equals(mod)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Get the base Diablo 2 version that a mod is built upon
         */
        private String getModBaseVersion(String modName) {
            // Map mods to their base versions
            switch (modName) {
                case "PD2":
                    return "1.13c";  // Project Diablo 2 is based on 1.13c
                case "PoD":
                    return "1.13c";  // Path of Diablo typically based on 1.13c
                case "MedianXL":
                    return "1.13c";  // Median XL latest versions
                case "Eastern Sun":
                    return "1.13c";  // Eastern Sun mod
                case "Requiem":
                    return "1.13c";  // Requiem mod
                default:
                    return "1.13c";  // Default to 1.13c for unknown mods
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
                return String.format("Invalid/Unknown format (detection: %s)", detectionMethod);
            }

            String baseInfo;
            if (isException) {
                baseInfo = String.format("%s %s", familyType, gameVersion);
            } else {
                baseInfo = String.format("Unified %s", gameVersion);
            }

            // Add detection method for transparency
            return String.format("%s (detected via %s)", baseInfo, detectionMethod);
        }
    }

    @Override
    public void run() throws Exception {

        println("=== BSim Database Population Script ===");
        println("Supports folder structure: /Classic/1.01/, /LoD/1.07/, /PD2/");
        println("Mod support: PD2 → 1.13c-PD2, PoD → 1.13c-PoD, MedianXL → 1.13c-MedianXL");
        println("Fallback filename parsing: 1.03_D2Game.dll, Classic_1.03_Game.exe");

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

        // Get the project path
        String programPath = "";
        DomainFile domainFile = currentProgram.getDomainFile();
        if (domainFile != null) {
            programPath = domainFile.getPathname();
        } else {
            programPath = currentProgram.getExecutablePath();
        }

        // Parse unified version information
        UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName, programPath);

        println("Program: " + programName);
        println("Project Path: " + programPath);
        println("Version Info: " + versionInfo.getDisplayInfo());
        println("  - Family: " + versionInfo.familyType);
        println("  - Version: " + versionInfo.gameVersion);
        println("  - Detection: " + versionInfo.detectionMethod);
        println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());

        if (!versionInfo.isValidUnifiedFormat()) {
            boolean proceed = askYesNo("Version Detection Failed",
                "Could not detect version information from folder structure or filename.\n" +
                "Expected folder structure: /Classic/1.01/, /LoD/1.07/, /PD2/\n" +
                "Or filename formats: 1.03_D2Game.dll, Classic_1.03_Game.exe\n\n" +
                "Detection attempted via: " + versionInfo.detectionMethod + "\n" +
                "Program path: " + programPath + "\n\n" +
                "Proceed with unknown version info?");

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
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName(), file.getPathname());
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
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(fileName, file.getPathname());

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
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName(), file.getPathname());
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
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName, programPath);

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

            // Set up transaction handling
            conn.setAutoCommit(false);

            try {
                // Get or create executable with unified version info
                int executableId = getOrCreateExecutableUnified(conn, programName, programPath, versionInfo);
                println("Executable ID: " + executableId);

                // Process functions
                processFunctions(conn, executableId, programName, program);

                // Update materialized views for cross-version analysis
                refreshMaterializedViews(conn);

                // Commit transaction
                conn.commit();
                println("Transaction committed successfully");

            } catch (Exception e) {
                // Rollback on error
                conn.rollback();
                println("Transaction rolled back due to error");
                throw e;
            }

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Get or create executable record with unified version support
     */
    private int getOrCreateExecutableUnified(Connection conn, String programName, String programPath, UnifiedVersionInfo versionInfo) throws SQLException {

        // Generate unified executable name that matches database constraints
        String unifiedName = generateUnifiedExecutableName(programName, versionInfo);

        // Check if executable already exists
        String selectSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setString(1, unifiedName);
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
            stmt.setString(1, unifiedName);
            stmt.setString(2, generateMD5(unifiedName));
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
                stmt.setString(1, unifiedName);
                stmt.setString(2, generateMD5(unifiedName));
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
        String insertSql = "INSERT INTO desctable (name_func, id_exe, id_signature, flags, addr) VALUES (?, ?, ?, ?, ?) RETURNING id";

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

                    ResultSet insertRs = insertStmt.executeQuery();
                    if (insertRs.next()) {
                        int functionId = insertRs.getInt("id");
                        addedCount++;

                        // Apply comprehensive function tagging and analysis
                        applyFunctionTags(program, function);

                        // Store detailed function analysis metrics with known function ID
                        storeFunctionAnalysisWithId(conn, function, functionId, executableId, program);

                        // Store function tags with known function ID
                        storeFunctionTagsWithId(conn, function, functionId, executableId);
                    }
                    insertRs.close();

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
        println("Applied comprehensive function tagging for " + addedCount + " new functions");
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

    /**
     * Comprehensive Function Analysis and Tagging System
     * Applies multiple categories of tags for reverse engineering, modding, and analysis
     */
    private void applyFunctionTags(Program program, Function function) {
        try {
            // Get function information
            String functionName = function.getName();
            Address entryPoint = function.getEntryPoint();

            // Start Ghidra transaction for function tag modifications
            int transactionID = program.startTransaction("Apply Function Tags");
            try {
                // Clear existing auto-generated tags to avoid duplicates
                clearAutoTags(function);

                // Apply all tagging categories
                applyLibraryFunctionTags(function, functionName);
                applyFunctionTypeTags(program, function);
                applyCallingPatternTags(program, function);
                applyGameLogicTags(program, function, functionName);
                applyUtilityFunctionTags(program, function);
                applyModRelevantTags(program, function);
                applyComplexityTags(program, function);
                applyArchitecturalTags(program, function);

            } finally {
                // End Ghidra transaction
                program.endTransaction(transactionID, true);
            }

        } catch (Exception e) {
            // Don't fail the entire process if tagging fails
            println("Warning: Could not tag function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store detailed function analysis metrics in the database
     */
    private void storeFunctionAnalysis(Connection conn, Function function, int executableId, Program program) {
        try {
            // Calculate comprehensive function metrics
            FunctionAnalysisMetrics metrics = calculateFunctionMetrics(program, function);

            // Store function analysis data
            String insertAnalysisSql = """
                INSERT INTO function_analysis
                (function_id, executable_id, function_name, entry_address, instruction_count,
                 basic_block_count, cyclomatic_complexity, calls_made, calls_received,
                 has_loops, has_recursion, max_depth, stack_frame_size, calling_convention,
                 is_leaf_function, is_library_function, is_thunk, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (function_id, executable_id) DO UPDATE SET
                instruction_count = EXCLUDED.instruction_count,
                cyclomatic_complexity = EXCLUDED.cyclomatic_complexity,
                analysis_timestamp = CURRENT_TIMESTAMP
            """;

            try (PreparedStatement stmt = conn.prepareStatement(insertAnalysisSql)) {
                stmt.setInt(1, getFunctionId(conn, function, executableId));
                stmt.setInt(2, executableId);
                stmt.setString(3, function.getName());
                stmt.setLong(4, function.getEntryPoint().getOffset());
                stmt.setInt(5, metrics.instructionCount);
                stmt.setInt(6, metrics.basicBlockCount);
                stmt.setInt(7, metrics.cyclomaticComplexity);
                stmt.setInt(8, metrics.callsMade);
                stmt.setInt(9, metrics.callsReceived);
                stmt.setBoolean(10, metrics.hasLoops);
                stmt.setBoolean(11, metrics.hasRecursion);
                stmt.setInt(12, metrics.maxDepth);
                stmt.setInt(13, metrics.stackFrameSize);
                stmt.setString(14, function.getCallingConventionName());
                stmt.setBoolean(15, metrics.isLeafFunction);
                stmt.setBoolean(16, metrics.isLibraryFunction);
                stmt.setBoolean(17, function.isThunk());
                stmt.setFloat(18, metrics.confidenceScore);

                stmt.executeUpdate();
            }

            // Store function tags in database
            storeFunctionTags(conn, function, executableId);

        } catch (SQLException e) {
            // Log but don't fail the entire process
            println("Warning: Could not store analysis for function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store function tags in the database
     */
    private void storeFunctionTags(Connection conn, Function function, int executableId) throws SQLException {
        int functionId = getFunctionId(conn, function, executableId);

        // Clear existing auto-generated tags
        String deleteSql = "DELETE FROM function_tags WHERE function_id = ? AND executable_id = ? AND auto_generated = true";
        try (PreparedStatement deleteStmt = conn.prepareStatement(deleteSql)) {
            deleteStmt.setInt(1, functionId);
            deleteStmt.setInt(2, executableId);
            deleteStmt.executeUpdate();
        }

        // Insert new tags
        String insertSql = """
            INSERT INTO function_tags (function_id, executable_id, tag_category, tag_value, confidence, auto_generated)
            VALUES (?, ?, ?, ?, ?, true)
            ON CONFLICT (function_id, executable_id, tag_category, tag_value) DO NOTHING
        """;

        try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
            // Get all tags from Ghidra and convert to strings
            Set<ghidra.program.model.listing.FunctionTag> functionTags = function.getTags();

            for (ghidra.program.model.listing.FunctionTag tagObj : functionTags) {
                String tag = tagObj.getName();
                if (tag.contains("_")) {
                    String[] parts = tag.split("_", 2);
                    String category = parts[0];
                    String value = parts.length > 1 ? parts[1] : tag;

                    insertStmt.setInt(1, functionId);
                    insertStmt.setInt(2, executableId);
                    insertStmt.setString(3, category);
                    insertStmt.setString(4, value);
                    insertStmt.setFloat(5, 1.0f); // Default confidence
                    insertStmt.executeUpdate();
                }
            }
        }
    }

    /**
     * Get function ID from the database
     */
    private int getFunctionId(Connection conn, Function function, int executableId) throws SQLException {
        String sql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ? AND addr = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, function.getName());
            stmt.setInt(2, executableId);
            stmt.setLong(3, function.getEntryPoint().getOffset());

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        throw new SQLException("Function not found in database: " + function.getName());
    }

    /**
     * Store function analysis with known function ID (more efficient)
     */
    private void storeFunctionAnalysisWithId(Connection conn, Function function, int functionId, int executableId, Program program) {
        try {
            // Calculate comprehensive function metrics
            FunctionAnalysisMetrics metrics = calculateFunctionMetrics(program, function);

            // Store function analysis data
            String insertAnalysisSql = """
                INSERT INTO function_analysis
                (function_id, executable_id, function_name, entry_address, instruction_count,
                 basic_block_count, cyclomatic_complexity, calls_made, calls_received,
                 has_loops, has_recursion, max_depth, stack_frame_size, calling_convention,
                 is_leaf_function, is_library_function, is_thunk, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (function_id, executable_id) DO UPDATE SET
                instruction_count = EXCLUDED.instruction_count,
                cyclomatic_complexity = EXCLUDED.cyclomatic_complexity,
                analysis_timestamp = CURRENT_TIMESTAMP
            """;

            try (PreparedStatement stmt = conn.prepareStatement(insertAnalysisSql)) {
                stmt.setInt(1, functionId);
                stmt.setInt(2, executableId);
                stmt.setString(3, function.getName());
                stmt.setLong(4, function.getEntryPoint().getOffset());
                stmt.setInt(5, metrics.instructionCount);
                stmt.setInt(6, metrics.basicBlockCount);
                stmt.setInt(7, metrics.cyclomaticComplexity);
                stmt.setInt(8, metrics.callsMade);
                stmt.setInt(9, metrics.callsReceived);
                stmt.setBoolean(10, metrics.hasLoops);
                stmt.setBoolean(11, metrics.hasRecursion);
                stmt.setInt(12, metrics.maxDepth);
                stmt.setInt(13, metrics.stackFrameSize);
                stmt.setString(14, metrics.callingConvention);
                stmt.setBoolean(15, metrics.isLeafFunction);
                stmt.setBoolean(16, metrics.isLibraryFunction);
                stmt.setBoolean(17, metrics.isThunk);
                stmt.setFloat(18, metrics.confidenceScore);

                stmt.executeUpdate();
            }

        } catch (SQLException e) {
            // Log but don't fail the entire process
            println("Warning: Could not store analysis for function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store function tags with known function ID (more efficient)
     */
    private void storeFunctionTagsWithId(Connection conn, Function function, int functionId, int executableId) {
        try {
            // Clear existing auto-generated tags
            String deleteSql = "DELETE FROM function_tags WHERE function_id = ? AND executable_id = ? AND auto_generated = true";
            try (PreparedStatement deleteStmt = conn.prepareStatement(deleteSql)) {
                deleteStmt.setInt(1, functionId);
                deleteStmt.setInt(2, executableId);
                deleteStmt.executeUpdate();
            }

            // Insert new tags from Ghidra function tags
            String insertSql = """
                INSERT INTO function_tags (function_id, executable_id, tag_category, tag_value, confidence, auto_generated)
                VALUES (?, ?, ?, ?, ?, true)
                ON CONFLICT (function_id, executable_id, tag_category, tag_value) DO NOTHING
            """;

            try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                // Get all tags from Ghidra and convert to strings
                Set<ghidra.program.model.listing.FunctionTag> functionTags = function.getTags();

                for (ghidra.program.model.listing.FunctionTag tagObj : functionTags) {
                    String tag = tagObj.getName();
                    if (tag.contains("_")) {
                        String[] parts = tag.split("_", 2);
                        String category = parts[0];
                        String value = parts.length > 1 ? parts[1] : tag;

                        insertStmt.setInt(1, functionId);
                        insertStmt.setInt(2, executableId);
                        insertStmt.setString(3, category);
                        insertStmt.setString(4, value);
                        insertStmt.setFloat(5, 0.8f); // Default confidence
                        insertStmt.executeUpdate();
                    }
                }
            }

        } catch (SQLException e) {
            println("Warning: Could not tag function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Calculate comprehensive function metrics
     */
    private FunctionAnalysisMetrics calculateFunctionMetrics(Program program, Function function) {
        FunctionAnalysisMetrics metrics = new FunctionAnalysisMetrics();

        try {
            AddressSetView body = function.getBody();

            // Count instructions
            InstructionIterator instructions = program.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                instructions.next();
                metrics.instructionCount++;
            }

            // Analyze function calls
            Set<Function> calledFunctions = function.getCalledFunctions(null);
            Set<Function> callingFunctions = function.getCallingFunctions(null);
            metrics.callsMade = calledFunctions.size();
            metrics.callsReceived = callingFunctions.size();

            // Determine function characteristics
            metrics.isLeafFunction = calledFunctions.isEmpty();
            metrics.isLibraryFunction = isLibraryFunction(function.getName());
            metrics.callingConvention = function.getCallingConventionName();
            metrics.isThunk = function.isThunk();

            // Basic complexity estimation
            metrics.cyclomaticComplexity = estimateCyclomaticComplexity(program, function);
            metrics.confidenceScore = calculateConfidenceScore(metrics);

        } catch (Exception e) {
            // Set defaults on error
            metrics.confidenceScore = 0.5f;
        }

        return metrics;
    }

    /**
     * Estimate cyclomatic complexity (simplified)
     */
    private int estimateCyclomaticComplexity(Program program, Function function) {
        try {
            AddressSetView body = function.getBody();
            int branches = 0;

            InstructionIterator instructions = program.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();

                // Check if instruction has conditional or jump flow
                if (instr.getFlowType().isConditional() || instr.getFlowType().isJump()) {
                    branches++;
                }
            }

            return Math.max(1, branches); // Minimum complexity is 1
        } catch (Exception e) {
            return 1; // Default complexity
        }
    }

    /**
     * Calculate confidence score based on available metrics
     */
    private float calculateConfidenceScore(FunctionAnalysisMetrics metrics) {
        float score = 0.5f; // Base score

        if (metrics.instructionCount > 5) score += 0.2f;
        if (metrics.cyclomaticComplexity > 1) score += 0.1f;
        if (!metrics.isLibraryFunction) score += 0.2f;

        return Math.min(1.0f, score);
    }

    /**
     * Check if function appears to be a library function
     */
    private boolean isLibraryFunction(String functionName) {
        return functionName.startsWith("_") ||
               functionName.contains("@") ||
               isCRuntimeFunction(functionName) ||
               isDiablo2Library(functionName);
    }

    /**
     * Helper class to store function analysis metrics
     */
    private static class FunctionAnalysisMetrics {
        int instructionCount = 0;
        int basicBlockCount = 0;
        int cyclomaticComplexity = 1;
        int callsMade = 0;
        int callsReceived = 0;
        boolean hasLoops = false;
        boolean hasRecursion = false;
        int maxDepth = 0;
        int stackFrameSize = 0;
        boolean isLeafFunction = false;
        boolean isLibraryFunction = false;
        float confidenceScore = 0.5f;
        String callingConvention = "UNKNOWN";
        boolean isThunk = false;
    }

    /**
     * Clear existing auto-generated tags to prevent duplicates
     */
    private void clearAutoTags(Function function) {
        String[] autoTagPrefixes = {
            "LIBRARY_", "FUNCTION_", "GAME_LOGIC_", "UTILITY_", "MOD_",
            "COMPLEXITY_", "ARCH_", "PATTERN_"
        };

        for (String prefix : autoTagPrefixes) {
            function.removeTag(prefix);
        }
    }

    /**
     * Detect and tag library functions (Windows API, game engine libraries, etc.)
     */
    private void applyLibraryFunctionTags(Function function, String functionName) {

        // Windows API Detection
        if (isWindowsApiFunction(functionName)) {
            function.addTag("LIBRARY_WINDOWS_API");

            // Specific API categories
            if (functionName.matches(".*(?i)(createfile|readfile|writefile|getfileattributes).*")) {
                function.addTag("LIBRARY_FILE_IO");
            } else if (functionName.matches(".*(?i)(createprocess|exitprocess|createthread).*")) {
                function.addTag("LIBRARY_PROCESS_THREAD");
            } else if (functionName.matches(".*(?i)(virtualalloc|heapalloc|malloc).*")) {
                function.addTag("LIBRARY_MEMORY");
            } else if (functionName.matches(".*(?i)(socket|send|recv|connect).*")) {
                function.addTag("LIBRARY_NETWORK");
            }
        }

        // DirectX and Graphics Libraries
        if (functionName.matches(".*(?i)(d3d|directdraw|direct3d|opengl|glide).*")) {
            function.addTag("LIBRARY_GRAPHICS");
        }

        // Audio Libraries
        if (functionName.matches(".*(?i)(directsound|dsound|winmm|audio).*")) {
            function.addTag("LIBRARY_AUDIO");
        }

        // C Runtime Library
        if (isCRuntimeFunction(functionName)) {
            function.addTag("LIBRARY_CRT");
        }

        // Diablo 2 specific libraries
        if (isDiablo2Library(functionName)) {
            function.addTag("LIBRARY_DIABLO2_ENGINE");
        }
    }

    /**
     * Tag functions by their type (thunk, ordinal, pointer, entry, etc.)
     */
    private void applyFunctionTypeTags(Program program, Function function) {
        String functionName = function.getName();

        // Thunk functions (jump trampolines)
        if (function.isThunk()) {
            function.addTag("FUNCTION_THUNK");
        }

        // Functions exported by ordinal
        if (functionName.matches(".*ordinal_\\d+.*") || functionName.matches(".*Ordinal\\d+.*")) {
            function.addTag("FUNCTION_ORDINAL");
        }

        // Function pointers and callbacks
        if (functionName.contains("_ptr") || functionName.contains("Callback") ||
            functionName.contains("Handler") || functionName.contains("Proc")) {
            function.addTag("FUNCTION_POINTER");
        }

        // Entry points
        if (functionName.equals("entry") || functionName.equals("_start") ||
            functionName.equals("DllMain") || functionName.equals("WinMain")) {
            function.addTag("FUNCTION_ENTRY");
        }

        // External functions (imports)
        if (function.isExternal()) {
            function.addTag("FUNCTION_EXTERNAL");
        }
    }

    /**
     * Analyze calling patterns and tag accordingly
     */
    private void applyCallingPatternTags(Program program, Function function) {
        try {
            // Get function calls
            Set<Function> calledFunctions = function.getCalledFunctions(null);
            Set<Function> callingFunctions = function.getCallingFunctions(null);

            // Leaf functions (don't call other functions)
            if (calledFunctions.isEmpty()) {
                function.addTag("FUNCTION_LEAF");
            }

            // Functions that only call library/system functions
            if (!calledFunctions.isEmpty() && onlyCallsLibraryFunctions(calledFunctions)) {
                function.addTag("FUNCTION_ISOLATED");
            }

            // Highly connected functions (called by many other functions)
            if (callingFunctions.size() > 10) {
                function.addTag("FUNCTION_HEAVILY_USED");
            }

            // Functions that are never called (potential dead code)
            if (callingFunctions.isEmpty() && !function.isExternal() &&
                !function.getName().equals("entry")) {
                function.addTag("FUNCTION_UNUSED");
            }

        } catch (Exception e) {
            // Ignore calling pattern analysis errors
        }
    }

    /**
     * Identify and tag game logic functions (high-value reverse engineering targets)
     */
    private void applyGameLogicTags(Program program, Function function, String functionName) {

        // Player and Character Logic
        if (functionName.matches(".*(?i)(player|char|character|stats?).*")) {
            function.addTag("GAME_LOGIC_PLAYER");
        }

        // Combat and Damage Systems
        if (functionName.matches(".*(?i)(damage|combat|attack|hit|crit|defense).*")) {
            function.addTag("GAME_LOGIC_COMBAT");
        }

        // Item and Inventory Systems
        if (functionName.matches(".*(?i)(item|inventory|equip|drop|pick|loot).*")) {
            function.addTag("GAME_LOGIC_ITEMS");
        }

        // Skills and Spells
        if (functionName.matches(".*(?i)(skill|spell|magic|cast|mana).*")) {
            function.addTag("GAME_LOGIC_SKILLS");
        }

        // AI and Monster Logic
        if (functionName.matches(".*(?i)(monster|ai|enemy|mob|npc).*")) {
            function.addTag("GAME_LOGIC_AI");
        }

        // Network and Multiplayer
        if (functionName.matches(".*(?i)(network|multiplayer|sync|packet|client|server).*")) {
            function.addTag("GAME_LOGIC_NETWORK");
        }

        // World and Level Generation
        if (functionName.matches(".*(?i)(level|world|map|generate|seed|terrain).*")) {
            function.addTag("GAME_LOGIC_WORLD");
        }

        // Quest and Story Logic
        if (functionName.matches(".*(?i)(quest|story|dialog|npc|trigger).*")) {
            function.addTag("GAME_LOGIC_QUEST");
        }
    }

    /**
     * Identify utility functions
     */
    private void applyUtilityFunctionTags(Program program, Function function) {
        String functionName = function.getName();

        // String manipulation functions
        if (functionName.matches(".*(?i)(string|str|text|format|parse|convert).*")) {
            function.addTag("UTILITY_STRING");
        }

        // Mathematical functions
        if (functionName.matches(".*(?i)(math|calc|sin|cos|sqrt|pow|random|rand).*")) {
            function.addTag("UTILITY_MATH");
        }

        // Memory management
        if (functionName.matches(".*(?i)(alloc|free|memory|mem|pool|buffer).*")) {
            function.addTag("UTILITY_MEMORY");
        }

        // File operations
        if (functionName.matches(".*(?i)(file|read|write|save|load|config).*")) {
            function.addTag("UTILITY_FILE");
        }

        // Data conversion
        if (functionName.matches(".*(?i)(convert|transform|encode|decode|serialize).*")) {
            function.addTag("UTILITY_CONVERSION");
        }

        // Logging and debugging
        if (functionName.matches(".*(?i)(log|debug|print|trace|dump).*")) {
            function.addTag("UTILITY_DEBUG");
        }
    }

    /**
     * Tag functions relevant for modders
     */
    private void applyModRelevantTags(Program program, Function function) {
        String functionName = function.getName();

        // Data-driven functions (load from files, configurable)
        if (functionName.matches(".*(?i)(load|config|data|table|init|setup).*")) {
            function.addTag("MOD_DATA_DRIVEN");
        }

        // UI and interface functions
        if (functionName.matches(".*(?i)(ui|menu|interface|button|dialog|window).*")) {
            function.addTag("MOD_UI");
        }

        // Rendering and visual functions
        if (functionName.matches(".*(?i)(render|draw|sprite|texture|color|effect).*")) {
            function.addTag("MOD_VISUAL");
        }

        // Audio and sound functions
        if (functionName.matches(".*(?i)(sound|audio|music|sfx|play).*")) {
            function.addTag("MOD_AUDIO");
        }

        // Functions commonly hooked by mods
        if (isCommonlyHookedFunction(functionName)) {
            function.addTag("MOD_HOOKABLE");
        }
    }

    /**
     * Tag based on function complexity for analysis prioritization
     */
    private void applyComplexityTags(Program program, Function function) {
        try {
            // Get basic complexity metrics
            AddressSetView body = function.getBody();
            int instructionCount = 0;
            int basicBlockCount = 0;

            // Count instructions
            InstructionIterator instructions = program.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                instructions.next();
                instructionCount++;
            }

            // Estimate complexity
            if (instructionCount < 10) {
                function.addTag("COMPLEXITY_TRIVIAL");
            } else if (instructionCount < 50) {
                function.addTag("COMPLEXITY_SIMPLE");
            } else if (instructionCount < 200) {
                function.addTag("COMPLEXITY_MODERATE");
            } else if (instructionCount < 500) {
                function.addTag("COMPLEXITY_COMPLEX");
            } else {
                function.addTag("COMPLEXITY_VERY_COMPLEX");
            }

        } catch (Exception e) {
            function.addTag("COMPLEXITY_UNKNOWN");
        }
    }

    /**
     * Architecture and calling convention specific tags
     */
    private void applyArchitecturalTags(Program program, Function function) {

        // Calling convention
        String callingConvention = function.getCallingConventionName();
        if (callingConvention != null) {
            function.addTag("ARCH_CALLING_" + callingConvention.toUpperCase());
        }

        // Stack frame analysis
        if (function.hasNoReturn()) {
            function.addTag("ARCH_NO_RETURN");
        }

        if (function.hasVarArgs()) {
            function.addTag("ARCH_VARARGS");
        }
    }

    // Helper methods for function classification

    private boolean isWindowsApiFunction(String functionName) {
        return functionName.startsWith("_") &&
               (functionName.contains("@") ||  // stdcall convention
                functionName.toLowerCase().matches(".*(get|set|create|open|close|read|write|alloc|free).*"));
    }

    private boolean isCRuntimeFunction(String functionName) {
        String[] crtPatterns = {
            "malloc", "free", "calloc", "realloc", "printf", "scanf", "strlen",
            "strcmp", "strcpy", "memcpy", "memset", "exit", "abort"
        };

        String lowerName = functionName.toLowerCase();
        for (String pattern : crtPatterns) {
            if (lowerName.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDiablo2Library(String functionName) {
        String[] d2Patterns = {
            "storm", "fog", "d2client", "d2common", "d2game", "d2gfx",
            "d2win", "d2lang", "d2net", "d2sound", "d2cmp"
        };

        String lowerName = functionName.toLowerCase();
        for (String pattern : d2Patterns) {
            if (lowerName.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean onlyCallsLibraryFunctions(Set<Function> calledFunctions) {
        for (Function called : calledFunctions) {
            if (!called.isExternal() && !called.getName().startsWith("_")) {
                return false;
            }
        }
        return true;
    }

    private boolean isCommonlyHookedFunction(String functionName) {
        String[] commonHooks = {
            "D2CLIENT_", "D2COMMON_", "D2GAME_", "GetUnitStat", "SetUnitStat",
            "GameDraw", "GameInput", "PlayerMove", "ItemClick", "SkillCast",
            "DamageCalc", "GameLoop", "PacketSend", "PacketReceive"
        };

        for (String hook : commonHooks) {
            if (functionName.contains(hook)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate unified executable name that matches database constraint patterns
     */
    private String generateUnifiedExecutableName(String programName, UnifiedVersionInfo versionInfo) {
        // Extract just the filename without any path
        String fileName = programName;
        if (fileName.contains("/")) {
            fileName = fileName.substring(fileName.lastIndexOf("/") + 1);
        }
        if (fileName.contains("\\")) {
            fileName = fileName.substring(fileName.lastIndexOf("\\") + 1);
        }

        // Normalize filename to remove spaces and special characters
        fileName = fileName.replace(" ", "_");

        // Handle special cases for Game.exe and Diablo II.exe
        if (fileName.equals("Game.exe") || fileName.equals("Diablo_II.exe")) {
            // Use pattern: (Classic|LoD)_1.[version]_Diablo_II.exe
            return String.format("%s_%s_Diablo_II.exe", versionInfo.familyType, versionInfo.gameVersion);
        }

        // For all other executables, use pattern: 1.[version]_[FileName].dll/exe
        return String.format("%s_%s", versionInfo.gameVersion, fileName);
    }
}