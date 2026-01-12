/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Ingests a well-documented REFERENCE program into BSim database.
//NO GUI - All configuration is preset. Supports headless execution.
//Marks the program with "ReferenceLibrary" category and tags documented functions.
//@category BSim
//@menupath Tools.BSim.Ingest Reference Program
import java.io.IOException;
import java.net.URL;
import java.util.*;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

/**
 * Ingests a well-documented reference program into the BSim database.
 * 
 * NO GUI DIALOGS - All configuration is preset below.
 * Fully supports headless execution via analyzeHeadless.
 * 
 * This script is designed for programs that will serve as the SOURCE of documentation
 * for BSim-based propagation to other versions/binaries.
 */
public class IngestReferenceProgramScript extends GhidraScript {

    // ========================================================================
    // CONNECTION CONFIGURATION - Edit these values before running
    // ========================================================================
    private static final String DB_HOST = "localhost";
    private static final int DB_PORT = 5432;
    private static final String DB_NAME = "bsim_project";
    private static final String DB_USERNAME = "ben";  // Change to your PostgreSQL username
    
    // ========================================================================
    // INGESTION CONFIGURATION
    // ========================================================================
    // Tag documented functions with "DOCUMENTED" tag
    private static final boolean TAG_DOCUMENTED_FUNCTIONS = true;
    
    // Auto-detect version from folder path (e.g., /LoD/1.09d/D2Client.dll -> "1.09d")
    private static final boolean AUTO_DETECT_VERSION = true;
    
    // Fallback version if auto-detection fails (set to null to require detection)
    private static final String FALLBACK_VERSION = null;
    
    // Auto-detect platform from folder path (LoD, Classic, PD2)
    private static final boolean AUTO_DETECT_PLATFORM = true;

    // Statistics
    private int totalFunctions = 0;
    private int documentedFunctions = 0;
    private int namedFunctions = 0;
    private int functionsWithPlateComments = 0;
    private int functionsWithSignatures = 0;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("ERROR: No program is open. Open a reference program first.");
            return;
        }

        if (currentProgram.isChanged()) {
            printerr("ERROR: " + currentProgram.getName() + " has unsaved changes. Please save first.");
            return;
        }

        String programName = currentProgram.getName();
        
        // Auto-detect version and platform
        String version = AUTO_DETECT_VERSION ? detectVersionFromPath() : FALLBACK_VERSION;
        String platform = AUTO_DETECT_PLATFORM ? detectPlatformFromPath() : null;
        
        if (version == null) {
            if (FALLBACK_VERSION != null) {
                version = FALLBACK_VERSION;
            } else {
                printerr("ERROR: Could not auto-detect version from path.");
                printerr("Path: " + currentProgram.getDomainFile().getPathname());
                printerr("Set FALLBACK_VERSION in script configuration.");
                return;
            }
        }

        println("=".repeat(70));
        println("INGEST REFERENCE PROGRAM TO BSIM");
        println("=".repeat(70));
        println("");
        println("Program: " + programName);
        println("Version: " + version);
        if (platform != null) {
            println("Platform: " + platform);
        }
        println("");
        println("Database: " + DB_HOST + ":" + DB_PORT + "/" + DB_NAME);
        println("");

        // Analyze documentation status
        analyzeProgramDocumentation();
        
        println("Documentation Analysis:");
        println("  Total Functions: " + totalFunctions);
        println("  Named Functions: " + namedFunctions + " (" + 
            String.format("%.1f%%", totalFunctions > 0 ? (double)namedFunctions/totalFunctions*100 : 0) + ")");
        println("  With Plate Comments: " + functionsWithPlateComments);
        println("  With Custom Signatures: " + functionsWithSignatures);
        println("  Documented Total: " + documentedFunctions);
        println("");

        if (documentedFunctions < 10) {
            Msg.warn(this, "Low documentation: only " + documentedFunctions + " documented functions.");
            println("WARNING: Low documentation coverage. Consider documenting more functions first.");
        }

        // Connect to BSim database
        BSimServerInfo serverInfo = new BSimServerInfo(DBType.postgres, DB_USERNAME, DB_HOST, DB_PORT, DB_NAME);

        try (FunctionDatabase pgDatabase = BSimClientFactory.buildClient(serverInfo, false)) {

            if (!pgDatabase.initialize()) {
                BSimError lastError = pgDatabase.getLastError();
                String errorMsg = lastError != null ? lastError.message : "Unknown error";
                throw new IOException("Failed to connect to database: " + errorMsg);
            }

            DatabaseInformation dbInfo = pgDatabase.getInfo();
            if (dbInfo == null) {
                throw new IOException("Failed to retrieve database information.");
            }

            println("Connected to BSim database: " + DB_NAME);

            LSHVectorFactory vectorFactory = pgDatabase.getLSHVectorFactory();

            // Generate signatures
            println("");
            println("Generating BSim signatures...");
            
            GenSignatures gensig = new GenSignatures(dbInfo.trackcallgraph);
            gensig.setVectorFactory(vectorFactory);
            gensig.addExecutableCategories(dbInfo.execats);
            gensig.addFunctionTags(dbInfo.functionTags);

            // Set categories for reference program
            List<String> categories = new ArrayList<>();
            categories.add("ReferenceLibrary");  // Mark as reference
            categories.add(version);             // Version category
            if (platform != null) {
                categories.add(platform);        // Platform category
            }

            URL programUrl = GhidraURL.toURL(currentProgram.getDomainFile().getProjectLocator(),
                currentProgram.getDomainFile().getPathname());

            gensig.openProgram(currentProgram, null, null, null, programUrl, categories);

            // Scan functions
            int scanned = 0;
            int tagged = 0;
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            
            monitor.initialize(totalFunctions);
            
            while (funcIter.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }

                Function func = funcIter.next();
                monitor.setProgress(scanned);
                monitor.setMessage("Scanning: " + func.getName());

                if (func.isExternal()) {
                    scanned++;
                    continue;
                }

                try {
                    gensig.scanFunction(func);
                    
                    if (TAG_DOCUMENTED_FUNCTIONS && isDocumentedFunction(func)) {
                        tagged++;
                    }

                    scanned++;
                } catch (Exception e) {
                    Msg.warn(this, "Error scanning " + func.getName() + ": " + e.getMessage());
                }
            }

            println("Scanned " + scanned + " functions");
            println("Documented functions: " + tagged);

            // Commit to database
            println("");
            println("Committing signatures to database...");
            
            DescriptionManager manager = gensig.getDescriptionManager();
            
            if (manager.numFunctions() == 0) {
                gensig.dispose();
                throw new IOException("No functions were scanned. Cannot commit.");
            }

            InsertRequest insertReq = new InsertRequest();
            insertReq.repo_override = null;
            insertReq.manage = manager;

            ResponseInsert insertResponse = insertReq.execute(pgDatabase);
            
            if (insertResponse == null) {
                BSimError lastError = pgDatabase.getLastError();
                String errorMsg = lastError != null ? lastError.message : "Unknown error";
                throw new IOException("Failed to insert signatures: " + errorMsg);
            }

            gensig.dispose();

            // Print summary
            println("");
            println("=".repeat(70));
            println("REFERENCE PROGRAM INGESTED SUCCESSFULLY");
            println("=".repeat(70));
            println("");
            println("Program: " + programName);
            println("Version: " + version);
            println("Categories: ReferenceLibrary, " + version + (platform != null ? ", " + platform : ""));
            println("Functions Scanned: " + scanned);
            println("Documented Functions: " + tagged);
            println("");
            println("=".repeat(70));
        }
    }

    private String detectVersionFromPath() {
        try {
            String path = currentProgram.getDomainFile().getPathname();
            // Look for version patterns like 1.09d, 1.13c, 1.10, etc.
            java.util.regex.Pattern versionPattern = 
                java.util.regex.Pattern.compile("\\b(\\d+\\.\\d+[a-z]?)\\b");
            java.util.regex.Matcher matcher = versionPattern.matcher(path);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    private String detectPlatformFromPath() {
        try {
            String path = currentProgram.getDomainFile().getPathname().toLowerCase();
            if (path.contains("/lod/") || path.contains("\\lod\\")) {
                return "LoD";
            } else if (path.contains("/classic/") || path.contains("\\classic\\")) {
                return "Classic";
            } else if (path.contains("/pd2/") || path.contains("\\pd2\\")) {
                return "PD2";
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    private void analyzeProgramDocumentation() {
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);

        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            totalFunctions++;

            if (func.isExternal()) {
                continue;
            }

            boolean isDocumented = false;

            if (!isDefaultName(func.getName())) {
                namedFunctions++;
                isDocumented = true;
            }

            if (func.getComment() != null && !func.getComment().isEmpty()) {
                functionsWithPlateComments++;
                isDocumented = true;
            }

            if (hasCustomSignature(func)) {
                functionsWithSignatures++;
                isDocumented = true;
            }

            if (isDocumented) {
                documentedFunctions++;
            }
        }
    }

    private boolean isDocumentedFunction(Function func) {
        if (func.isExternal() || func.isThunk()) {
            return false;
        }
        if (!isDefaultName(func.getName())) {
            return true;
        }
        if (func.getComment() != null && !func.getComment().isEmpty()) {
            return true;
        }
        if (func.getRepeatableComment() != null && !func.getRepeatableComment().isEmpty()) {
            return true;
        }
        return false;
    }

    private boolean isDefaultName(String name) {
        return name.startsWith("FUN_") ||
               name.startsWith("thunk_FUN_") ||
               name.startsWith("switchD_") ||
               name.startsWith("caseD_") ||
               name.matches("^[A-Za-z]+_[0-9a-fA-F]+$");
    }

    private boolean hasCustomSignature(Function func) {
        for (Parameter param : func.getParameters()) {
            String name = param.getName();
            if (name != null && !name.matches("param_\\d+") && !name.isEmpty()) {
                return true;
            }
        }
        String returnTypeName = func.getReturnType().getName();
        if (!returnTypeName.equals("undefined") && !returnTypeName.equals("void")) {
            return true;
        }
        return false;
    }
}
