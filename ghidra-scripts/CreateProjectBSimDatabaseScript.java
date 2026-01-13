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
//Creates or verifies a preconfigured BSim database on PostgreSQL for documentation propagation.
//IDEMPOTENT - Safe to run multiple times. Will create if missing, verify if exists.
//NO GUI - All configuration is preset. Supports headless execution.
//Pre-defines function tags: DOCUMENTED, PROPAGATED, NEEDS_REVIEW, LIBRARY, VERIFIED
//Pre-defines executable categories: Version, ReferenceLibrary, Target, Vendor, Platform
//@category BSim
//@menupath Tools.BSim.Create Project BSim Database
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.Msg;

/**
 * Creates or verifies a preconfigured BSim database optimized for cross-version 
 * function documentation propagation workflows.
 * 
 * IDEMPOTENT OPERATION:
 * - If database schema doesn't exist: Creates it with the specified template
 * - If database schema exists: Verifies configuration and adds any missing tags/categories
 * - Safe to run multiple times without side effects
 * 
 * NO GUI DIALOGS - All configuration is preset below.
 * Fully supports headless execution via analyzeHeadless.
 */
public class CreateProjectBSimDatabaseScript extends GhidraScript {

    // ========================================================================
    // CONNECTION CONFIGURATION - Edit these values before running
    // ========================================================================
    private static final String DB_HOST = "***REMOVED***";
    private static final int DB_PORT = 5432;
    private static final String DB_NAME = "bsim";
    private static final String DB_USERNAME = "ben";
    private static final String DB_PASSWORD = "***REMOVED***";  // Required for DROP operation
    
    // If true, drops and recreates DB when it exists but has no valid BSim schema
    private static final boolean DROP_IF_INVALID = true;
    
    // ========================================================================
    // DATABASE CONFIGURATION
    // ========================================================================
    // Template options: "medium_32", "medium_64", "medium_nosize", "medium_cpool"
    // - medium_32: Best for 32-bit x86 binaries (recommended for game reversing)
    // - medium_64: For 64-bit x86-64 binaries
    // - medium_nosize: Cross-architecture matching (ignores operand sizes)
    private static final String DB_TEMPLATE = "medium_32";
    private static final boolean TRACK_CALL_GRAPH = true;
    
    // ========================================================================
    // FUNCTION TAGS - Pre-installed for documentation workflow
    // ========================================================================
    private static final String[] FUNCTION_TAGS = {
        "DOCUMENTED",     // Source functions with complete documentation
        "PROPAGATED",     // Functions that received propagated documentation
        "NEEDS_REVIEW",   // Flagged for manual review (70-85% similarity)
        "LIBRARY",        // Known library/CRT functions
        "VERIFIED",       // Human-verified after propagation
        "THUNK",          // Thunk/stub functions
        "CUSTOM_CALLING"  // Functions with non-standard calling conventions
    };
    
    // ========================================================================
    // EXECUTABLE CATEGORIES - Pre-installed for organization
    // ========================================================================
    private static final String[] EXECUTABLE_CATEGORIES = {
        "Version",          // Game/software version (1.09d, 1.10, 1.13c)
        "ReferenceLibrary", // Well-documented source programs
        "Target",           // Programs receiving propagation
        "Vendor",           // Publisher/developer
        "Platform"          // Platform identifier (LoD, Classic, PD2)
    };

    @Override
    protected void run() throws Exception {
        println("=".repeat(70));
        println("CREATE/VERIFY PROJECT BSIM DATABASE");
        println("=".repeat(70));
        println("");
        println("Configuration:");
        println("  Host: " + DB_HOST);
        println("  Port: " + DB_PORT);
        println("  Database: " + DB_NAME);
        println("  Username: " + DB_USERNAME);
        println("  Template: " + DB_TEMPLATE);
        println("  Track Call Graph: " + TRACK_CALL_GRAPH);
        println("");

        BSimServerInfo serverInfo = new BSimServerInfo(DBType.postgres, DB_USERNAME, DB_HOST, DB_PORT, DB_NAME);

        try (FunctionDatabase pgDatabase = BSimClientFactory.buildClient(serverInfo, false)) {

            boolean databaseExists = false;
            DatabaseInformation existingInfo = null;
            Set<String> existingTags = new HashSet<>();
            Set<String> existingCategories = new HashSet<>();

            // ================================================================
            // STEP 1: Check if database schema already exists
            // ================================================================
            println("Checking database status...");
            QueryInfo queryInfo = new QueryInfo();
            ResponseInfo infoResponse = queryInfo.execute(pgDatabase);
            
            if (infoResponse != null && infoResponse.info != null) {
                databaseExists = true;
                existingInfo = infoResponse.info;
                println("  ✓ Database schema exists");
                println("    Name: " + existingInfo.databasename);
                println("    LSH settings: 0x" + Integer.toHexString(existingInfo.settings));
                println("    Track call graph: " + existingInfo.trackcallgraph);
                
                // Collect existing tags
                List<String> tagList = existingInfo.functionTags;
                if (tagList != null) {
                    for (String tag : tagList) {
                        existingTags.add(tag);
                    }
                }
                println("    Existing tags: " + existingTags.size());
                
                // Collect existing categories (field is 'execats')
                List<String> catList = existingInfo.execats;
                if (catList != null) {
                    for (String cat : catList) {
                        existingCategories.add(cat);
                    }
                }
                println("    Existing categories: " + existingCategories.size());
            } else {
                println("  Database schema not found - will create");
            }

            // ================================================================
            // STEP 2: Create database schema if it doesn't exist
            // ================================================================
            if (!databaseExists) {
                println("");
                println("Creating database structure...");
                
                CreateDatabase command = new CreateDatabase();
                command.info = new DatabaseInformation();
                command.info.databasename = DB_NAME;
                command.config_template = DB_TEMPLATE;
                command.info.trackcallgraph = TRACK_CALL_GRAPH;

                ResponseInfo response = command.execute(pgDatabase);
                if (response == null) {
                    BSimError lastError = pgDatabase.getLastError();
                    String errorMsg = lastError != null ? lastError.message : "Unknown error";
                    
                    // Check if this is just "database already exists" error
                    // This happens when PostgreSQL DB exists but BSim schema is missing
                    if (errorMsg != null && errorMsg.contains("already exists")) {
                        println("  ⚠ PostgreSQL database exists - checking if BSim schema needs initialization...");
                        
                        // Try to query again after the create attempt - Ghidra may have initialized schema
                        QueryInfo retryQuery = new QueryInfo();
                        ResponseInfo retryResponse = retryQuery.execute(pgDatabase);
                        if (retryResponse != null && retryResponse.info != null) {
                            println("  ✓ BSim schema is now accessible");
                            databaseExists = true;
                            existingInfo = retryResponse.info;
                        } else {
                            // Database exists but BSim schema could not be created
                            println("  ✗ BSim schema could not be initialized in existing database");
                            
                            if (DROP_IF_INVALID) {
                                println("");
                                println("DROP_IF_INVALID is enabled - dropping and recreating database...");
                                
                                // Close the current connection before dropping
                                pgDatabase.close();
                                
                                // Drop the database using JDBC
                                if (dropDatabase()) {
                                    println("  ✓ Database dropped successfully");
                                    println("");
                                    println("Restarting script with fresh database...");
                                    println("");
                                    // Recursively call run() to start fresh
                                    run();
                                    return;  // Exit this invocation
                                } else {
                                    throw new IOException("Failed to drop database. Check credentials and permissions.");
                                }
                            } else {
                                println("");
                                println("MANUAL ACTION REQUIRED:");
                                println("  The PostgreSQL database '" + DB_NAME + "' exists but has no BSim schema.");
                                println("  Options:");
                                println("  1. Set DROP_IF_INVALID = true in the script configuration");
                                println("  2. Manually drop: psql -h " + DB_HOST + " -U " + DB_USERNAME + " -c \"DROP DATABASE " + DB_NAME + " WITH (FORCE);\"");
                                println("");
                                throw new IOException("Database exists without BSim schema. See instructions above.");
                            }
                        }
                    } else {
                        throw new IOException("Failed to create database: " + errorMsg);
                    }
                } else {
                    println("  ✓ Database schema created successfully");
                }
            }

            // ================================================================
            // STEP 3: Install/verify function tags (idempotent)
            // ================================================================
            println("");
            println("Verifying function tags...");
            int tagsExisted = 0;
            int tagsAdded = 0;
            int tagsFailed = 0;
            
            for (String tag : FUNCTION_TAGS) {
                if (existingTags.contains(tag)) {
                    println("  ✓ " + tag + " (exists)");
                    tagsExisted++;
                } else {
                    InstallTagRequest req = new InstallTagRequest();
                    req.tag_name = tag;
                    ResponseInfo resp = req.execute(pgDatabase);
                    if (resp == null) {
                        BSimError lastError = pgDatabase.getLastError();
                        // Check if it's just a "already exists" error
                        if (lastError != null && lastError.category == ErrorCategory.Nodatabase) {
                            println("  ✓ " + tag + " (exists)");
                            tagsExisted++;
                        } else {
                            println("  ✗ " + tag + " (FAILED: " + 
                                (lastError != null ? lastError.message : "Unknown error") + ")");
                            tagsFailed++;
                        }
                    } else {
                        println("  + " + tag + " (added)");
                        tagsAdded++;
                    }
                }
            }
            println("  Tags: " + tagsExisted + " existed, " + tagsAdded + " added, " + tagsFailed + " failed");

            // ================================================================
            // STEP 4: Install/verify executable categories (idempotent)
            // ================================================================
            println("");
            println("Verifying executable categories...");
            int catsExisted = 0;
            int catsAdded = 0;
            int catsFailed = 0;
            
            for (String cat : EXECUTABLE_CATEGORIES) {
                if (existingCategories.contains(cat)) {
                    println("  ✓ " + cat + " (exists)");
                    catsExisted++;
                } else {
                    InstallCategoryRequest req = new InstallCategoryRequest();
                    req.type_name = cat;
                    ResponseInfo resp = req.execute(pgDatabase);
                    if (resp == null) {
                        BSimError lastError = pgDatabase.getLastError();
                        // Check if it's just a "already exists" error
                        if (lastError != null && lastError.category == ErrorCategory.Nodatabase) {
                            println("  ✓ " + cat + " (exists)");
                            catsExisted++;
                        } else {
                            println("  ✗ " + cat + " (FAILED: " + 
                                (lastError != null ? lastError.message : "Unknown error") + ")");
                            catsFailed++;
                        }
                    } else {
                        println("  + " + cat + " (added)");
                        catsAdded++;
                    }
                }
            }
            println("  Categories: " + catsExisted + " existed, " + catsAdded + " added, " + catsFailed + " failed");

            // ================================================================
            // STEP 5: Final verification and summary
            // ================================================================
            println("");
            println("Performing final verification...");
            
            QueryInfo verifyQuery = new QueryInfo();
            ResponseInfo verifyResponse = verifyQuery.execute(pgDatabase);
            
            int finalTagCount = 0;
            int finalCatCount = 0;
            String templateUsed = "unknown";
            boolean trackCallGraph = false;
            
            if (verifyResponse != null && verifyResponse.info != null) {
                DatabaseInformation info = verifyResponse.info;
                if (info.functionTags != null) {
                    finalTagCount = info.functionTags.size();
                }
                if (info.execats != null) {
                    finalCatCount = info.execats.size();
                }
                templateUsed = "0x" + Integer.toHexString(info.settings);
                trackCallGraph = info.trackcallgraph;
                println("  ✓ Verification successful");
            } else {
                println("  ⚠ Could not verify database state");
            }

            // Print summary
            println("");
            println("=".repeat(70));
            if (databaseExists) {
                println("DATABASE VERIFIED SUCCESSFULLY");
            } else {
                println("DATABASE CREATED SUCCESSFULLY");
            }
            println("=".repeat(70));
            println("");
            println("Database: " + DB_NAME + " @ " + DB_HOST + ":" + DB_PORT);
            println("Template/Settings: " + templateUsed);
            println("Track Call Graph: " + trackCallGraph);
            println("");
            println("Function Tags: " + finalTagCount + " total");
            println("  - Pre-existing: " + tagsExisted);
            println("  - Added: " + tagsAdded);
            if (tagsFailed > 0) {
                println("  - FAILED: " + tagsFailed + " (check logs)");
            }
            println("");
            println("Executable Categories: " + finalCatCount + " total");
            println("  - Pre-existing: " + catsExisted);
            println("  - Added: " + catsAdded);
            if (catsFailed > 0) {
                println("  - FAILED: " + catsFailed + " (check logs)");
            }
            println("");
            
            // Validation status
            boolean allTagsOk = (tagsExisted + tagsAdded) == FUNCTION_TAGS.length;
            boolean allCatsOk = (catsExisted + catsAdded) == EXECUTABLE_CATEGORIES.length;
            
            if (allTagsOk && allCatsOk) {
                println("Status: ✓ ALL REQUIRED COMPONENTS VERIFIED");
            } else {
                println("Status: ⚠ SOME COMPONENTS MISSING");
                if (!allTagsOk) {
                    println("  - Missing " + (FUNCTION_TAGS.length - tagsExisted - tagsAdded) + " function tags");
                }
                if (!allCatsOk) {
                    println("  - Missing " + (EXECUTABLE_CATEGORIES.length - catsExisted - catsAdded) + " categories");
                }
            }
            
            println("");
            println("Next Steps:");
            println("1. Run 'IngestReferenceProgramScript' on well-documented programs");
            println("2. Run 'AddProgramToPostgresBSimDatabaseScript' on target programs");
            println("3. Run 'PropagateFullDocumentationScript' to propagate documentation");
            println("");
            println("=".repeat(70));
        }
    }
    
    /**
     * Drops the BSim database using direct JDBC connection.
     * Uses DROP DATABASE WITH (FORCE) to terminate any active connections.
     * 
     * @return true if database was dropped successfully, false otherwise
     */
    private boolean dropDatabase() {
        String jdbcUrl = "jdbc:postgresql://" + DB_HOST + ":" + DB_PORT + "/postgres";
        
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            println("  ERROR: PostgreSQL JDBC driver not found: " + e.getMessage());
            return false;
        }
        
        try (Connection conn = DriverManager.getConnection(jdbcUrl, DB_USERNAME, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            // Use WITH (FORCE) to terminate any active connections
            String dropSql = "DROP DATABASE IF EXISTS " + DB_NAME + " WITH (FORCE)";
            stmt.execute(dropSql);
            return true;
            
        } catch (Exception e) {
            println("  ERROR dropping database: " + e.getMessage());
            return false;
        }
    }
}
