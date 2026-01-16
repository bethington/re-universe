// Populate cross-references (XREFs) into BSim database for call graph analysis
// @author Claude Code Assistant
// @category BSim
// @keybinding ctrl shift X
// @menupath Tools.BSim.Populate Cross References

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;

public class PopulateCrossReferences extends GhidraScript {

    private static final String DEFAULT_DB_URL = "jdbc:postgresql://10.0.0.30:5432/bsim";
    private static final String DEFAULT_DB_USER = "ben";
    private static final String DEFAULT_DB_PASS = "goodyx12";

    // Mode selection constants
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    @Override
    public void run() throws Exception {
        println("=== BSim Cross-References Population Script ===");

        // Ask user for processing mode
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to populate cross-references?",
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

        // Count functions for reference estimation
        int functionCount = currentProgram.getFunctionManager().getFunctionCount();
        println("Functions in program: " + functionCount);
        println("Estimated cross-references: " + (functionCount * 5) + " (approximate)");

        boolean proceed = askYesNo("Populate Cross-References",
            String.format("Analyze cross-references for %d functions?\n\nThis will:\n" +
            "- Extract function call relationships\n" +
            "- Build call graph data\n" +
            "- Enable caller/callee analysis\n" +
            "- Support control flow similarity\n\nProceed?", functionCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            populateCrossReferences(currentProgram, programName);
            println("Successfully populated cross-references into BSim database!");

        } catch (Exception e) {
            printerr("Error populating cross-references: " + e.getMessage());
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
            String.format("Found %d programs in project.\n\nPopulate cross-references for all programs?",
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
            String.format("Found %d programs matching '%s'.\n\nPopulate cross-references for these programs?",
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
            populateCrossReferences(program, file.getName());
            println("  Cross-references populated successfully");
        } finally {
            program.release(this);
        }
    }

    private void populateCrossReferences(Program program, String programName) throws Exception {
        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(DEFAULT_DB_URL, DEFAULT_DB_USER, DEFAULT_DB_PASS)) {
            println("Connected to BSim database successfully");

            // Create cross-reference schema if needed
            createCrossRefSchema(conn);

            // Get executable ID
            int executableId = getExecutableId(conn, programName);
            if (executableId == -1) {
                throw new RuntimeException("Executable not found in BSim database. Please populate functions first.");
            }

            println("Executable ID: " + executableId);

            // Process cross-references
            processCrossReferences(conn, program, executableId, programName);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private void createCrossRefSchema(Connection conn) throws SQLException {
        println("Creating cross-references schema...");

        String createTableSql = """
            CREATE TABLE IF NOT EXISTS function_calls (
                id SERIAL PRIMARY KEY,
                executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
                caller_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                callee_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                call_address BIGINT NOT NULL,
                call_type TEXT, -- 'direct', 'indirect', 'conditional', 'unconditional'
                reference_type TEXT, -- 'call', 'jump', 'data'
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(caller_function_id, callee_function_id, call_address)
            );

            CREATE TABLE IF NOT EXISTS data_references (
                id SERIAL PRIMARY KEY,
                executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
                function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                target_address BIGINT NOT NULL,
                reference_address BIGINT NOT NULL,
                reference_type TEXT, -- 'read', 'write', 'read_write'
                data_type TEXT, -- 'global', 'stack', 'heap', 'string'
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(function_id, target_address, reference_address)
            );

            CREATE TABLE IF NOT EXISTS call_graph_metrics (
                id SERIAL PRIMARY KEY,
                function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
                incoming_calls INTEGER DEFAULT 0,
                outgoing_calls INTEGER DEFAULT 0,
                data_references INTEGER DEFAULT 0,
                call_depth INTEGER DEFAULT 0,
                is_leaf BOOLEAN DEFAULT false,
                is_entry_point BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(function_id)
            );

            CREATE INDEX IF NOT EXISTS idx_function_calls_caller ON function_calls(caller_function_id);
            CREATE INDEX IF NOT EXISTS idx_function_calls_callee ON function_calls(callee_function_id);
            CREATE INDEX IF NOT EXISTS idx_data_references_function ON data_references(function_id);
            CREATE INDEX IF NOT EXISTS idx_call_graph_metrics_function ON call_graph_metrics(function_id);
            """;

        try (Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
            println("Cross-references schema created/verified");
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

    private void processCrossReferences(Connection conn, Program program, int executableId, String programName) throws Exception {
        println("Processing cross-references...");
        monitor.setMessage("Processing cross-references for BSim");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int processedCount = 0;
        int callCount = 0;
        int dataRefCount = 0;

        // Prepare statements
        String insertCallSql = """
            INSERT INTO function_calls
            (executable_id, caller_function_id, callee_function_id, call_address, call_type, reference_type)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (caller_function_id, callee_function_id, call_address) DO NOTHING
            """;

        String insertDataRefSql = """
            INSERT INTO data_references
            (executable_id, function_id, target_address, reference_address, reference_type, data_type)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (function_id, target_address, reference_address) DO NOTHING
            """;

        String insertMetricsSql = """
            INSERT INTO call_graph_metrics
            (function_id, incoming_calls, outgoing_calls, data_references, is_leaf, is_entry_point)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (function_id) DO UPDATE SET
                incoming_calls = EXCLUDED.incoming_calls,
                outgoing_calls = EXCLUDED.outgoing_calls,
                data_references = EXCLUDED.data_references,
                is_leaf = EXCLUDED.is_leaf,
                is_entry_point = EXCLUDED.is_entry_point
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";

        // Create function name to ID mapping for performance
        Map<String, Long> functionIdMap = createFunctionIdMap(conn, executableId);

        try (PreparedStatement callStmt = conn.prepareStatement(insertCallSql);
             PreparedStatement dataRefStmt = conn.prepareStatement(insertDataRefSql);
             PreparedStatement metricsStmt = conn.prepareStatement(insertMetricsSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                processedCount++;

                if (processedCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        processedCount, function.getName()));
                    println(String.format("Processed %d functions...", processedCount));
                }

                try {
                    Long functionId = functionIdMap.get(function.getName());
                    if (functionId == null) continue;

                    // Process function calls
                    int outgoingCalls = processFunctionCalls(callStmt, program, function, functionId,
                        functionIdMap, executableId);
                    callCount += outgoingCalls;

                    // Process data references
                    int dataRefs = processDataReferences(dataRefStmt, program, function, functionId, executableId);
                    dataRefCount += dataRefs;

                    // Calculate and insert metrics
                    insertFunctionMetrics(metricsStmt, function, functionId, outgoingCalls, dataRefs);

                } catch (SQLException e) {
                    printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                }
            }
        }

        // Update incoming call counts
        updateIncomingCallCounts(conn);

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d functions, added %d function calls and %d data references",
            processedCount, callCount, dataRefCount));
    }

    private Map<String, Long> createFunctionIdMap(Connection conn, int executableId) throws SQLException {
        Map<String, Long> functionIdMap = new HashMap<>();

        String selectSql = "SELECT id, name_func FROM desctable WHERE id_exe = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setInt(1, executableId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                functionIdMap.put(rs.getString("name_func"), rs.getLong("id"));
            }
        }

        return functionIdMap;
    }

    private int processFunctionCalls(PreparedStatement callStmt, Program program, Function function,
                                   long functionId, Map<String, Long> functionIdMap,
                                   int executableId) throws SQLException {

        int callCount = 0;

        // Get all calls made by this function
        Set<Function> calledFunctions = function.getCalledFunctions(monitor);

        for (Function callee : calledFunctions) {
            Long calleeId = functionIdMap.get(callee.getName());
            if (calleeId == null) continue;

            // Find call sites to this function
            Reference[] callRefs = getReferencesTo(callee.getEntryPoint());

            for (Reference ref : callRefs) {
                Address refAddr = ref.getFromAddress();

                // Check if this reference is from our function
                if (function.getBody().contains(refAddr)) {
                    callStmt.setInt(1, executableId);
                    callStmt.setLong(2, functionId);
                    callStmt.setLong(3, calleeId);
                    callStmt.setLong(4, refAddr.getOffset());
                    callStmt.setString(5, getCallType(ref));
                    callStmt.setString(6, ref.getReferenceType().getName());

                    try {
                        callStmt.executeUpdate();
                        callCount++;
                    } catch (SQLException e) {
                        // Ignore duplicate key errors
                        if (!e.getMessage().contains("duplicate key")) {
                            throw e;
                        }
                    }
                }
            }
        }

        return callCount;
    }

    private int processDataReferences(PreparedStatement dataRefStmt, Program program, Function function,
                                    long functionId, int executableId) throws SQLException {

        int dataRefCount = 0;

        // Iterate through function body to find data references
        AddressSetView body = function.getBody();
        InstructionIterator instructions = program.getListing().getInstructions(body, true);

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            Reference[] refs = instr.getReferencesFrom();

            for (Reference ref : refs) {
                if (ref.getReferenceType().isData()) {
                    dataRefStmt.setInt(1, executableId);
                    dataRefStmt.setLong(2, functionId);
                    dataRefStmt.setLong(3, ref.getToAddress().getOffset());
                    dataRefStmt.setLong(4, ref.getFromAddress().getOffset());
                    dataRefStmt.setString(5, getDataReferenceType(ref));
                    dataRefStmt.setString(6, getDataType(program, ref.getToAddress()));

                    try {
                        dataRefStmt.executeUpdate();
                        dataRefCount++;
                    } catch (SQLException e) {
                        // Ignore duplicate key errors
                        if (!e.getMessage().contains("duplicate key")) {
                            throw e;
                        }
                    }
                }
            }
        }

        return dataRefCount;
    }

    private void insertFunctionMetrics(PreparedStatement metricsStmt, Function function,
                                     long functionId, int outgoingCalls, int dataRefs) throws SQLException {

        // Calculate incoming calls (will be updated later)
        boolean isLeaf = function.getCalledFunctions(monitor).isEmpty();
        boolean isEntryPoint = function.hasCustomVariableStorage() ||
                               function.getName().equals("main") ||
                               function.getName().startsWith("_");

        metricsStmt.setLong(1, functionId);
        metricsStmt.setInt(2, 0); // incoming_calls - will be updated
        metricsStmt.setInt(3, outgoingCalls);
        metricsStmt.setInt(4, dataRefs);
        metricsStmt.setBoolean(5, isLeaf);
        metricsStmt.setBoolean(6, isEntryPoint);

        metricsStmt.executeUpdate();
    }

    private void updateIncomingCallCounts(Connection conn) throws SQLException {
        println("Updating incoming call counts...");

        String updateSql = """
            UPDATE call_graph_metrics
            SET incoming_calls = (
                SELECT COUNT(*)
                FROM function_calls
                WHERE callee_function_id = call_graph_metrics.function_id
            )
            """;

        try (Statement stmt = conn.createStatement()) {
            int updated = stmt.executeUpdate(updateSql);
            println("Updated incoming call counts for " + updated + " functions");
        }
    }

    private String getCallType(Reference ref) {
        RefType refType = ref.getReferenceType();
        if (refType.isCall()) {
            return "direct";
        } else if (refType.isIndirect()) {
            return "indirect";
        } else if (refType.isConditional()) {
            return "conditional";
        } else if (refType.isUnConditional()) {
            return "unconditional";
        }
        return "unknown";
    }

    private String getDataReferenceType(Reference ref) {
        // Simplified data reference type detection
        RefType refType = ref.getReferenceType();
        if (refType.isRead()) {
            return "read";
        } else if (refType.isWrite()) {
            return "write";
        }
        return "read_write";
    }

    private String getDataType(Program program, Address addr) {
        // Simplified data type detection based on address characteristics
        if (program.getMemory().getBlock(addr) != null) {
            String blockName = program.getMemory().getBlock(addr).getName().toLowerCase();
            if (blockName.contains("data") || blockName.contains("bss")) {
                return "global";
            } else if (blockName.contains("stack")) {
                return "stack";
            } else if (blockName.contains("heap")) {
                return "heap";
            } else if (blockName.contains("rodata") || blockName.contains("string")) {
                return "string";
            }
        }
        return "unknown";
    }
}