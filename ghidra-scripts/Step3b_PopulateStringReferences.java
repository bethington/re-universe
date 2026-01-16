// STEP 3b: Populate String References (OPTIONAL ENRICHMENT)
//
// Extracts string references from functions and stores them in the BSim database
// for enhanced similarity analysis. String references provide strong indicators
// for function identification, especially for library functions and error handling.
//
// STRING EXTRACTION TYPES:
// - Direct string literals referenced by functions
// - Imported string references from external libraries
// - Debug/error message strings that identify function purpose
// - Configuration and format strings that indicate functionality
//
// ANALYSIS ENHANCEMENT:
// - Enables string-based function matching across versions
// - Identifies functions by unique string patterns
// - Improves accuracy for library function identification
// - Supports malware analysis through string fingerprinting
//
// CROSS-VERSION ANALYSIS:
// - Tracks string changes between software versions
// - Identifies functions that maintain consistent string usage
// - Detects version-specific modifications through string analysis
//
// WORKFLOW POSITION: Optional after Step1-2, enhances Step4-5 results
// DEPENDENCIES: Requires functions to be added via Step1
//
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift T
// @menupath Tools.BSim.Step3b - Populate String References (Optional)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.util.string.FoundString;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;

public class Step3b_PopulateStringReferences extends GhidraScript {

    private static final String DEFAULT_DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DEFAULT_DB_USER = "ben";
    private static final String DEFAULT_DB_PASS = "goodyx12";

    // Mode selection constants
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    @Override
    public void run() throws Exception {
        println("=== BSim String References Population Script ===");

        // Ask user for processing mode
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to populate string references?",
            Arrays.asList(modes), MODE_SINGLE);

        if (selectedMode.equals(MODE_SINGLE)) {
            processSingleProgram();
        } else if (selectedMode.equals(MODE_ALL)) {
            processAllPrograms();
        } else if (selectedMode.equals(MODE_VERSION)) {
            processVersionFiltered();
        }
    }

    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        println("Program: " + programName);

        // Count strings in program
        int stringCount = countStringReferences(currentProgram);
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
            populateStringReferences(currentProgram, programName);
            println("Successfully populated string references into BSim database!");

        } catch (Exception e) {
            printerr("Error populating string references: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void processAllPrograms() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        if (programFiles.isEmpty()) {
            popup("No program files found in the project.");
            return;
        }

        boolean proceed = askYesNo("Process All Programs",
            String.format("Found %d programs in project.\n\nPopulate string references for all programs?",
                programFiles.size()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        println("Processing " + programFiles.size() + " programs...");
        int successCount = 0;
        int errorCount = 0;

        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) break;

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("\n=== Batch Processing Complete ===\nSuccess: %d\nErrors: %d",
            successCount, errorCount));
    }

    private void processVersionFiltered() throws Exception {
        String versionFilter = askString("Version Filter",
            "Enter version pattern to match (e.g., '1.14' or 'D2R'):");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("No version filter specified, operation cancelled.");
            return;
        }

        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> allFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, allFiles);

        // Filter by version
        List<DomainFile> matchingFiles = new ArrayList<>();
        for (DomainFile file : allFiles) {
            String path = file.getPathname();
            if (path.contains(versionFilter) || file.getName().contains(versionFilter)) {
                matchingFiles.add(file);
            }
        }

        if (matchingFiles.isEmpty()) {
            popup("No programs matching version '" + versionFilter + "' found.");
            return;
        }

        boolean proceed = askYesNo("Process Filtered Programs",
            String.format("Found %d programs matching '%s'.\n\nPopulate string references for these programs?",
                matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        println("Processing " + matchingFiles.size() + " matching programs...");
        int successCount = 0;
        int errorCount = 0;

        for (DomainFile file : matchingFiles) {
            if (monitor.isCancelled()) break;

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("\n=== Version Filtered Processing Complete ===\nVersion: %s\nSuccess: %d\nErrors: %d",
            versionFilter, successCount, errorCount));
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

    private void processProjectFile(DomainFile file) throws Exception {
        println("\nProcessing: " + file.getPathname());
        monitor.setMessage("Processing: " + file.getName());

        Program program = (Program) file.getDomainObject(this, false, false, monitor);
        try {
            populateStringReferences(program, file.getName());
            println("  String references populated successfully");
        } finally {
            program.release(this);
        }
    }

    private int countStringReferences(Program program) {
        List<FoundString> strings = findStrings(program.getMemory(), 4, 1, true, true);
        return strings.size();
    }

    private void populateStringReferences(Program program, String programName) throws Exception {
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
            processStringReferences(conn, program, executableId, programName);

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

    private void processStringReferences(Connection conn, Program program, int executableId, String programName) throws Exception {
        println("Processing string references...");
        monitor.setMessage("Processing string references for BSim");

        // Find all strings in the program
        List<FoundString> strings = findStrings(program.getMemory(), 4, 1, true, true);

        int processedCount = 0;
        int stringCount = 0;
        int referenceCount = 0;
        int skippedCount = 0;
        int totalStrings = strings.size();

        // Check if string already exists
        String checkStringSql = "SELECT id FROM string_references WHERE executable_id = ? AND string_address = ?";
        
        // Insert without ON CONFLICT for compatibility
        String insertStringSql = """
            INSERT INTO string_references
            (executable_id, string_address, string_value, string_length, string_type)
            VALUES (?, ?, ?, ?, ?)
            RETURNING id
            """;

        // Check if reference already exists
        String checkRefSql = "SELECT id FROM function_string_refs WHERE function_id = ? AND string_id = ? AND reference_address = ?";
        
        String insertRefSql = """
            INSERT INTO function_string_refs
            (function_id, string_id, reference_type, reference_address)
            VALUES (?, ?, ?, ?)
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE id_exe = ? AND addr <= ? ORDER BY addr DESC LIMIT 1";

        try (PreparedStatement checkStringStmt = conn.prepareStatement(checkStringSql);
             PreparedStatement stringStmt = conn.prepareStatement(insertStringSql);
             PreparedStatement checkRefStmt = conn.prepareStatement(checkRefSql);
             PreparedStatement refStmt = conn.prepareStatement(insertRefSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            for (FoundString foundString : strings) {
                if (monitor.isCancelled()) break;

                processedCount++;

                if (processedCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing string %d of %d",
                        processedCount, totalStrings));
                    println(String.format("Processed %d strings...", processedCount));
                }

                try {
                    // Insert string
                    Address stringAddr = foundString.getAddress();
                    String stringValue = foundString.getString(program.getMemory());

                    if (stringValue == null || stringValue.length() < 4 || stringValue.length() > 1000) {
                        continue; // Skip null, very short or very long strings
                    }

                    // Check if string already exists
                    checkStringStmt.setInt(1, executableId);
                    checkStringStmt.setLong(2, stringAddr.getOffset());
                    ResultSet checkRs = checkStringStmt.executeQuery();
                    
                    long stringId;
                    if (checkRs.next()) {
                        // String exists, use existing ID
                        stringId = checkRs.getLong("id");
                        skippedCount++;
                        checkRs.close();
                    } else {
                        checkRs.close();
                        
                        // Insert new string
                        stringStmt.setInt(1, executableId);
                        stringStmt.setLong(2, stringAddr.getOffset());
                        stringStmt.setString(3, stringValue);
                        stringStmt.setInt(4, stringValue.length());
                        stringStmt.setString(5, getStringType(foundString));

                        ResultSet rs = stringStmt.executeQuery();
                        if (rs.next()) {
                            stringId = rs.getLong("id");
                            stringCount++;
                        } else {
                            rs.close();
                            continue;
                        }
                        rs.close();
                    }

                    // Find functions that reference this string
                    referenceCount += findFunctionReferences(conn, checkRefStmt, refStmt, funcIdStmt,
                        stringAddr, stringId, executableId);

                } catch (SQLException e) {
                    printerr("Error processing string at " + foundString.getAddress() + ": " + e.getMessage());
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

    private String getStringType(FoundString foundString) {
        // Determine string type based on FoundString properties
        if (foundString.getDataType() != null) {
            DataType dt = foundString.getDataType();
            if (dt instanceof StringDataType) {
                return "string";
            } else if (dt instanceof UnicodeDataType) {
                return "unicode";
            } else if (dt instanceof StringUTF8DataType) {
                return "utf8";
            }
        }
        return "unknown";
    }

    private int findFunctionReferences(Connection conn, PreparedStatement checkRefStmt, 
                                     PreparedStatement refStmt, PreparedStatement funcIdStmt, 
                                     Address stringAddr, long stringId, int executableId) throws SQLException {

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

                // Check if reference already exists
                checkRefStmt.setLong(1, functionId);
                checkRefStmt.setLong(2, stringId);
                checkRefStmt.setLong(3, refAddr.getOffset());
                ResultSet checkRs = checkRefStmt.executeQuery();
                if (checkRs.next()) {
                    // Reference exists, skip
                    checkRs.close();
                    rs.close();
                    continue;
                }
                checkRs.close();

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