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
//Creates a preconfigured BSim database on PostgreSQL optimized for documentation propagation.
//NO GUI - All configuration is preset. Supports headless execution.
//Pre-defines function tags: DOCUMENTED, PROPAGATED, NEEDS_REVIEW, LIBRARY, VERIFIED
//Pre-defines executable categories: Version, ReferenceLibrary, Target, Vendor, Platform
//@category BSim
//@menupath Tools.BSim.Create Project BSim Database
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.Msg;

/**
 * Creates a preconfigured BSim database optimized for cross-version function
 * documentation propagation workflows.
 * 
 * NO GUI DIALOGS - All configuration is preset below.
 * Fully supports headless execution via analyzeHeadless.
 */
public class CreateProjectBSimDatabaseScript extends GhidraScript {

    // ========================================================================
    // CONNECTION CONFIGURATION - Edit these values before running
    // ========================================================================
    private static final String DB_HOST = "localhost";
    private static final int DB_PORT = 5432;
    private static final String DB_NAME = "bsim_project";
    private static final String DB_USERNAME = "ben";  // Change to your PostgreSQL username
    
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
        println("CREATE PROJECT BSIM DATABASE");
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

            // Create the database
            CreateDatabase command = new CreateDatabase();
            command.info = new DatabaseInformation();
            command.info.databasename = DB_NAME;
            command.config_template = DB_TEMPLATE;
            command.info.trackcallgraph = TRACK_CALL_GRAPH;

            println("Creating database structure...");
            ResponseInfo response = command.execute(pgDatabase);
            if (response == null) {
                BSimError lastError = pgDatabase.getLastError();
                String errorMsg = lastError != null ? lastError.message : "Unknown error";
                throw new IOException("Failed to create database: " + errorMsg);
            }
            println("  ✓ Database created successfully");

            // Install function tags
            println("");
            println("Installing function tags...");
            int tagCount = 0;
            for (String tag : FUNCTION_TAGS) {
                InstallTagRequest req = new InstallTagRequest();
                req.tag_name = tag;
                ResponseInfo resp = req.execute(pgDatabase);
                if (resp == null) {
                    BSimError lastError = pgDatabase.getLastError();
                    Msg.warn(this, "Failed to install tag '" + tag + "': " + 
                        (lastError != null ? lastError.message : "Unknown error"));
                } else {
                    println("  ✓ " + tag);
                    tagCount++;
                }
            }
            println("  Installed " + tagCount + "/" + FUNCTION_TAGS.length + " function tags");

            // Install executable categories
            println("");
            println("Installing executable categories...");
            int catCount = 0;
            for (String cat : EXECUTABLE_CATEGORIES) {
                InstallCategoryRequest req = new InstallCategoryRequest();
                req.type_name = cat;
                ResponseInfo resp = req.execute(pgDatabase);
                if (resp == null) {
                    BSimError lastError = pgDatabase.getLastError();
                    Msg.warn(this, "Failed to install category '" + cat + "': " + 
                        (lastError != null ? lastError.message : "Unknown error"));
                } else {
                    println("  ✓ " + cat);
                    catCount++;
                }
            }
            println("  Installed " + catCount + "/" + EXECUTABLE_CATEGORIES.length + " executable categories");

            // Print summary
            println("");
            println("=".repeat(70));
            println("DATABASE CREATED SUCCESSFULLY");
            println("=".repeat(70));
            println("");
            println("Database: " + DB_NAME);
            println("Template: " + DB_TEMPLATE);
            println("Function Tags: " + tagCount);
            println("Executable Categories: " + catCount);
            println("");
            println("Next Steps:");
            println("1. Run 'IngestReferenceProgramScript' on well-documented programs");
            println("2. Run 'AddProgramToPostgresBSimDatabaseScript' on target programs");
            println("3. Run 'PropagateFullDocumentationScript' to propagate documentation");
            println("");
            println("=".repeat(70));
        }
    }
}
