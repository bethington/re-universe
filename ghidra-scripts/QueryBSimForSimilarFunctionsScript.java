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
//Queries a PostgreSQL BSim database to find similar functions across all indexed programs.
//Useful for matching functions across different versions of the same software.
//NO GUI - All configuration is preset below. Edit the constants before running.
//@category BSim
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.Msg;

public class QueryBSimForSimilarFunctionsScript extends GhidraScript {

    // ========================================================================
    // CONNECTION CONFIGURATION
    // Values are read from environment variables with fallback defaults.
    // Set these in your environment or .env file before running:
    //   BSIM_DB_HOST, BSIM_DB_PORT, BSIM_DB_NAME, BSIM_DB_USER
    // ========================================================================
    // NOTE: PostgreSQL must be configured with 'trust' authentication for this user
    //       OR you must have a .pgpass file in your home directory:
    //       Windows: %APPDATA%\postgresql\pgpass.conf
    //       Linux/Mac: ~/.pgpass
    //       Format: hostname:port:database:username:password
    //       Example: localhost:5432:bsim:bsim_user:yourpassword
    // ========================================================================
    private static final String DB_HOST = getEnvOrDefault("BSIM_DB_HOST", "localhost");
    private static final int DB_PORT = Integer.parseInt(getEnvOrDefault("BSIM_DB_PORT", "5432"));
    private static final String DB_NAME = getEnvOrDefault("BSIM_DB_NAME", "bsim");
    private static final String DB_USERNAME = getEnvOrDefault("BSIM_DB_USER", "bsim_user");

    private static String getEnvOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
    
    // ========================================================================
    // QUERY CONFIGURATION
    // ========================================================================
    // Similarity: 0.0-1.0, higher = stricter matching
    //   0.9+ = near-identical (same compiler, minor changes)
    //   0.7-0.9 = same function with moderate changes
    //   0.5-0.7 = similar algorithms, significant differences
    private static final double SIMILARITY_THRESHOLD = 0.7;
    
    // Confidence: statistical significance of match
    //   10.0+ = very high confidence (complex, unique functions)
    //   5.0-10.0 = good confidence
    //   1.0-5.0 = moderate, review manually
    //   <1.0 = low confidence, likely coincidental
    private static final double CONFIDENCE_THRESHOLD = 10.0;
    
    // Maximum results per queried function
    private static final int MAX_RESULTS = 100;
    
    // Query all functions in program (true) or just the one at cursor (false)
    private static final boolean QUERY_ALL_FUNCTIONS = false;
    
    // Export results to CSV file in user's home directory
    private static final boolean EXPORT_CSV = true;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("ERROR: This script requires an open program to query against.");
            return;
        }

        println("=".repeat(70));
        println("BSIM CROSS-VERSION FUNCTION QUERY");
        println("=".repeat(70));
        println("");
        println("Configuration:");
        println("  Database: " + DB_HOST + ":" + DB_PORT + "/" + DB_NAME);
        println("  Username: " + DB_USERNAME);
        println("  Similarity Threshold: " + SIMILARITY_THRESHOLD);
        println("  Confidence Threshold: " + CONFIDENCE_THRESHOLD);
        println("  Query All Functions: " + QUERY_ALL_FUNCTIONS);
        println("");
        
        BSimServerInfo serverInfo = new BSimServerInfo(DBType.postgres, DB_USERNAME, DB_HOST, DB_PORT, DB_NAME);
        
        println("Connecting to BSim database...");
        println("  (If this hangs, check PostgreSQL authentication settings)");
        println("  (You may need a .pgpass file - see script comments for details)");

        try (FunctionDatabase pgDatabase = BSimClientFactory.buildClient(serverInfo, false)) {

            if (!pgDatabase.initialize()) {
                BSimError lastError = pgDatabase.getLastError();
                String errorMsg = lastError != null ? lastError.message : "Unknown error";
                printerr("ERROR: Failed to connect to database: " + errorMsg);
                printerr("");
                printerr("TROUBLESHOOTING:");
                printerr("1. Verify PostgreSQL is running: docker ps | grep bsim");
                printerr("2. Test connection: psql -h " + DB_HOST + " -p " + DB_PORT + " -U " + DB_USERNAME + " -d " + DB_NAME);
                printerr("3. Check pg_hba.conf allows your connection");
                printerr("4. Create .pgpass file with credentials (see script comments)");
                return;
            }
            
            println("  Connected successfully!");

            DatabaseInformation dbInfo = pgDatabase.getInfo();
            if (dbInfo == null) {
                printerr("ERROR: Failed to retrieve database information.");
                return;
            }
            
            println("  Database: " + dbInfo.databasename);
            println("  Functions indexed: querying...");

            LSHVectorFactory vectorFactory = pgDatabase.getLSHVectorFactory();

            // Collect functions to query
            List<Function> functionsToQuery = new ArrayList<>();
            if (QUERY_ALL_FUNCTIONS) {
                FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
                while (funcIter.hasNext()) {
                    Function func = funcIter.next();
                    // Skip thunks and external functions
                    if (!func.isThunk() && !func.isExternal() && func.getBody().getNumAddresses() > 0) {
                        functionsToQuery.add(func);
                    }
                }
            } else {
                // Query only the function at the current cursor location
                Function func = getFunctionContaining(currentAddress);
                if (func != null) {
                    functionsToQuery.add(func);
                    println("");
                    println("Querying single function: " + func.getName() + " @ " + func.getEntryPoint());
                } else {
                    printerr("ERROR: No function at current cursor location. Place cursor inside a function.");
                    return;
                }
            }

            if (functionsToQuery.isEmpty()) {
                printerr("ERROR: No functions found to query.");
                return;
            }

            println("");
            println("Querying " + functionsToQuery.size() + " function(s) against BSim database...");
            monitor.initialize(functionsToQuery.size());
            monitor.setMessage("Generating signatures and querying...");

            // Generate signatures for query functions
            GenSignatures gensig = new GenSignatures(dbInfo.trackcallgraph);
            gensig.setVectorFactory(vectorFactory);
            gensig.addExecutableCategories(dbInfo.execats);
            gensig.addFunctionTags(dbInfo.functionTags);

            gensig.openProgram(currentProgram, null, null, null, null, null);

            // Results storage
            Map<Function, List<SimilarityResult>> allResults = new LinkedHashMap<>();
            int processedCount = 0;

            for (Function func : functionsToQuery) {
                if (monitor.isCancelled()) {
                    break;
                }
                monitor.setProgress(processedCount++);
                monitor.setMessage("Querying: " + func.getName());

                try {
                    // Scan function and get description manager
                    gensig.scanFunction(func);
                    DescriptionManager manager = gensig.getDescriptionManager();

                    if (manager.numFunctions() == 0) {
                        continue;
                    }

                    // Build query
                    QueryNearest queryNearest = new QueryNearest();
                    queryNearest.manage = manager;
                    queryNearest.max = MAX_RESULTS;
                    queryNearest.thresh = SIMILARITY_THRESHOLD;
                    queryNearest.signifthresh = CONFIDENCE_THRESHOLD;

                    ResponseNearest response = queryNearest.execute(pgDatabase);
                    if (response == null) {
                        Msg.warn(this, "Query failed for " + func.getName());
                        continue;
                    }

                    List<SimilarityResult> results = new ArrayList<>();
                    // Iterate over each SimilarityResult, then over each SimilarityNote within
                    for (ghidra.features.bsim.query.protocol.SimilarityResult simResult : response.result) {
                        for (SimilarityNote note : simResult) {
                            FunctionDescription matchFunc = note.getFunctionDescription();
                            ExecutableRecord matchExe = matchFunc.getExecutableRecord();

                            // Skip self-matches (same program)
                            String matchExeName = matchExe.getNameExec();
                            if (matchExeName.equals(currentProgram.getName())) {
                                continue;
                            }

                            SimilarityResult result = new SimilarityResult();
                            result.matchedFunctionName = matchFunc.getFunctionName();
                            result.matchedFunctionAddress = "0x" + Long.toHexString(matchFunc.getAddress());
                            result.matchedExecutable = matchExeName;
                            result.similarity = note.getSimilarity();
                            result.confidence = note.getSignificance();
                            results.add(result);
                        }
                    }

                    if (!results.isEmpty()) {
                        allResults.put(func, results);
                    }

                } catch (Exception e) {
                    Msg.warn(this, "Error querying function " + func.getName() + ": " + e.getMessage());
                }
            }

            gensig.dispose();

            // Display results
            displayResults(allResults);
        }
    }

    private void displayResults(Map<Function, List<SimilarityResult>> allResults) throws Exception {

        if (allResults.isEmpty()) {
            println("");
            println("No similar functions found above thresholds:");
            println("  Similarity >= " + SIMILARITY_THRESHOLD);
            println("  Confidence >= " + CONFIDENCE_THRESHOLD);
            return;
        }

        StringBuilder report = new StringBuilder();
        report.append("\n");
        report.append("=".repeat(70)).append("\n");
        report.append("BSim Cross-Version Function Matching Results\n");
        report.append("=".repeat(70)).append("\n");
        report.append("Source Program: ").append(currentProgram.getName()).append("\n");
        report.append("Similarity Threshold: ").append(SIMILARITY_THRESHOLD).append("\n");
        report.append("Confidence Threshold: ").append(CONFIDENCE_THRESHOLD).append("\n");
        report.append("Functions with matches: ").append(allResults.size()).append("\n\n");

        // Group by matched executable for summary
        Map<String, Integer> matchCountByExe = new HashMap<>();
        int totalMatches = 0;

        for (Map.Entry<Function, List<SimilarityResult>> entry : allResults.entrySet()) {
            for (SimilarityResult result : entry.getValue()) {
                matchCountByExe.merge(result.matchedExecutable, 1, Integer::sum);
                totalMatches++;
            }
        }

        report.append("Summary by Executable:\n");
        report.append("-".repeat(40)).append("\n");
        for (Map.Entry<String, Integer> entry : matchCountByExe.entrySet()) {
            report.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append(" matches\n");
        }
        report.append("\nTotal matches: ").append(totalMatches).append("\n\n");

        report.append("Detailed Results:\n");
        report.append("-".repeat(40)).append("\n\n");

        for (Map.Entry<Function, List<SimilarityResult>> entry : allResults.entrySet()) {
            Function func = entry.getKey();
            List<SimilarityResult> results = entry.getValue();

            report.append("Function: ").append(func.getName());
            report.append(" @ 0x").append(func.getEntryPoint().toString()).append("\n");

            for (SimilarityResult result : results) {
                report.append(String.format("  -> %s @ %s in [%s] (sim=%.4f, conf=%.4f)\n",
                    result.matchedFunctionName,
                    result.matchedFunctionAddress,
                    result.matchedExecutable,
                    result.similarity,
                    result.confidence));
            }
            report.append("\n");
        }

        // Export to CSV if requested
        if (EXPORT_CSV) {
            String csvPath = System.getProperty("user.home") + "/bsim_results_" +
                currentProgram.getName().replaceAll("[^a-zA-Z0-9.-]", "_") + 
                "_" + System.currentTimeMillis() + ".csv";
            try (PrintWriter pw = new PrintWriter(new FileWriter(csvPath))) {
                pw.println("Source Function,Source Address,Matched Function,Matched Address,Matched Executable,Similarity,Confidence");
                for (Map.Entry<Function, List<SimilarityResult>> entry : allResults.entrySet()) {
                    Function func = entry.getKey();
                    for (SimilarityResult result : entry.getValue()) {
                        pw.printf("\"%s\",\"0x%s\",\"%s\",\"%s\",\"%s\",%.4f,%.4f%n",
                            func.getName(),
                            func.getEntryPoint().toString(),
                            result.matchedFunctionName,
                            result.matchedFunctionAddress,
                            result.matchedExecutable,
                            result.similarity,
                            result.confidence);
                    }
                }
            }
            report.append("\nResults exported to: ").append(csvPath).append("\n");
        }

        // Show in console
        println(report.toString());
        
        println("=".repeat(70));
        println("QUERY COMPLETE");
        println("=".repeat(70));
        println("Found " + allResults.size() + " functions with " + totalMatches +
            " total matches across " + matchCountByExe.size() + " executables.");
        if (EXPORT_CSV) {
            println("Results exported to CSV in your home directory.");
        }
    }

    private static class SimilarityResult {
        String matchedFunctionName;
        String matchedFunctionAddress;
        String matchedExecutable;
        double similarity;
        double confidence;
    }
}
