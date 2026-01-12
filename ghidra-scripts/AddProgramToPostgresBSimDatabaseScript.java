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
//Generates and commits the BSim signatures for programs to a PostgreSQL BSim database.
//Can process the current program or all programs in the project.
//@category BSim
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class AddProgramToPostgresBSimDatabaseScript extends GhidraScript {

	private static final String HOST = "Host";
	private static final String PORT = "Port";
	private static final String DATABASE_NAME = "Database Name";
	private static final String USERNAME = "Username";
	private static final String PROCESS_ALL = "Process All Programs in Project";
	private static final String USE_FOLDER_AS_VERSION = "Use Parent Folder as Version";

	private static final int DEFAULT_POSTGRES_PORT = 5432;

	// Configuration
	private boolean useFolderAsVersion = true;

	private int successCount = 0;
	private int skipCount = 0;
	private int errorCount = 0;
	private List<String> processedPrograms = new ArrayList<>();
	private List<String> skippedPrograms = new ArrayList<>();
	private List<String> errorPrograms = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("Use the \"bsim\" command-line tool to add programs to a database headlessly");
			return;
		}

		// Reset counters
		successCount = 0;
		skipCount = 0;
		errorCount = 0;
		processedPrograms.clear();
		skippedPrograms.clear();
		errorPrograms.clear();

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(HOST, "localhost");
		values.defineInt(PORT, DEFAULT_POSTGRES_PORT);
		values.defineString(DATABASE_NAME, "bsim");
		values.defineString(USERNAME, System.getProperty("user.name"));
		values.defineBoolean(PROCESS_ALL, false);
		values.defineBoolean(USE_FOLDER_AS_VERSION, true);

		values.setValidator((valueMap, status) -> {
			String host = valueMap.getString(HOST);
			if (StringUtils.isBlank(host)) {
				status.setStatusText("Host cannot be empty!", MessageType.ERROR);
				return false;
			}
			int port = valueMap.getInt(PORT);
			if (port <= 0 || port > 65535) {
				status.setStatusText("Port must be between 1 and 65535!", MessageType.ERROR);
				return false;
			}
			String dbName = valueMap.getString(DATABASE_NAME);
			if (StringUtils.isBlank(dbName)) {
				status.setStatusText("Database Name cannot be empty!", MessageType.ERROR);
				return false;
			}
			String username = valueMap.getString(USERNAME);
			if (StringUtils.isBlank(username)) {
				status.setStatusText("Username cannot be empty!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		askValues("PostgreSQL BSim Database Connection", null, values);

		String host = values.getString(HOST);
		int port = values.getInt(PORT);
		String dbName = values.getString(DATABASE_NAME);
		String username = values.getString(USERNAME);
		boolean processAll = values.getBoolean(PROCESS_ALL);
		useFolderAsVersion = values.getBoolean(USE_FOLDER_AS_VERSION);

		// Validate based on mode
		if (!processAll) {
			if (currentProgram == null) {
				popup("This script requires that a program be open in the tool, " +
						"or enable 'Process All Programs in Project' option.");
				return;
			}
			if (currentProgram.isChanged()) {
				popup(currentProgram.getName() + " has unsaved changes. Please save the program" +
						" before adding it to a BSim database.");
				return;
			}
		}

		BSimServerInfo serverInfo = new BSimServerInfo(DBType.postgres, username, host, port, dbName);

		try (FunctionDatabase pgDatabase = BSimClientFactory.buildClient(serverInfo, false)) {

			if (!pgDatabase.initialize()) {
				BSimError lastError = pgDatabase.getLastError();
				String errorMsg = lastError != null ? lastError.message : "Unknown error";
				popup("Failed to connect to database: " + errorMsg);
				return;
			}

			DatabaseInformation dbInfo = pgDatabase.getInfo();
			if (dbInfo == null) {
				popup("Failed to retrieve database information. Is this a valid BSim database?");
				return;
			}

			if (processAll) {
				processAllPrograms(pgDatabase, dbInfo);
			} else {
				processSingleProgram(currentProgram, pgDatabase, dbInfo, true);
			}

			// Show final status
			StringBuilder status = new StringBuilder();
			if (processAll) {
				status.append("Batch Processing Complete\n");
				status.append("========================\n\n");
				status.append("Successfully added: ").append(successCount).append(" programs\n");
				status.append("Skipped: ").append(skipCount).append(" programs\n");
				status.append("Errors: ").append(errorCount).append(" programs\n\n");

				if (!processedPrograms.isEmpty()) {
					status.append("Added:\n");
					for (String name : processedPrograms) {
						status.append("  - ").append(name).append("\n");
					}
					status.append("\n");
				}
				if (!skippedPrograms.isEmpty()) {
					status.append("Skipped:\n");
					for (String name : skippedPrograms) {
						status.append("  - ").append(name).append("\n");
					}
					status.append("\n");
				}
				if (!errorPrograms.isEmpty()) {
					status.append("Errors:\n");
					for (String name : errorPrograms) {
						status.append("  - ").append(name).append("\n");
					}
					status.append("\n");
				}
			}

			QueryExeCount exeCount = new QueryExeCount();
			ResponseExe countResponse = exeCount.execute(pgDatabase);
			if (countResponse != null) {
				status.append(dbInfo.databasename);
				status.append(" now contains ");
				status.append(countResponse.recordCount);
				status.append(" executables.");
			}
			popup(status.toString());
		}
	}

	/**
	 * Process all programs in the current project
	 */
	private void processAllPrograms(FunctionDatabase pgDatabase, DatabaseInformation dbInfo) throws Exception {
		Project project = state.getProject();
		if (project == null) {
			popup("No project is currently open.");
			return;
		}

		List<DomainFile> programFiles = new ArrayList<>();
		collectProgramFiles(project.getProjectData().getRootFolder(), programFiles);

		if (programFiles.isEmpty()) {
			popup("No programs found in the project.");
			return;
		}

		monitor.initialize(programFiles.size());
		monitor.setMessage("Processing " + programFiles.size() + " programs...");

		for (int i = 0; i < programFiles.size(); i++) {
			if (monitor.isCancelled()) {
				Msg.info(this, "Batch processing cancelled by user");
				break;
			}

			DomainFile dFile = programFiles.get(i);
			monitor.setProgress(i);
			monitor.setMessage("Processing (" + (i + 1) + "/" + programFiles.size() + "): " + dFile.getName());

			Program program = null;
			try {
				// Open the program read-only
				program = (Program) dFile.getDomainObject(this, false, false, monitor);
				processSingleProgram(program, pgDatabase, dbInfo, false);
			} catch (Exception e) {
				errorCount++;
				errorPrograms.add(dFile.getName() + ": " + e.getMessage());
				Msg.error(this, "Error processing " + dFile.getName() + ": " + e.getMessage(), e);
			} finally {
				if (program != null) {
					program.release(this);
				}
			}
		}
	}

	/**
	 * Recursively collect all program files from a folder
	 */
	private void collectProgramFiles(DomainFolder folder, List<DomainFile> programFiles) {
		// Get all files in this folder
		for (DomainFile file : folder.getFiles()) {
			if (file.getContentType().equals("Program")) {
				programFiles.add(file);
			}
		}

		// Recursively process subfolders
		for (DomainFolder subfolder : folder.getFolders()) {
			collectProgramFiles(subfolder, programFiles);
		}
	}

	/**
	 * Process a single program and add it to the BSim database
	 */
	private void processSingleProgram(Program program, FunctionDatabase pgDatabase,
			DatabaseInformation dbInfo, boolean showIndividualPopups) throws Exception {

		LSHVectorFactory vectorFactory = pgDatabase.getLSHVectorFactory();
		GenSignatures gensig = null;
		try {
			gensig = new GenSignatures(dbInfo.trackcallgraph);
			gensig.setVectorFactory(vectorFactory);
			gensig.addExecutableCategories(dbInfo.execats);
			gensig.addFunctionTags(dbInfo.functionTags);
			gensig.addDateColumnName(dbInfo.dateColumnName);

			DomainFile dFile = program.getDomainFile();
			URL fileURL = dFile.getSharedProjectURL(null);
			if (fileURL == null) {
				fileURL = dFile.getLocalProjectURL(null);
			}
			if (fileURL == null) {
				skipCount++;
				skippedPrograms.add(program.getName() + ": never been saved");
				if (showIndividualPopups) {
					popup("Cannot add signatures for program which has never been saved");
				}
				return;
			}

			String path = GhidraURL.getProjectPathname(fileURL);
			int lastSlash = path.lastIndexOf('/');
			path = lastSlash == 0 ? "/" : path.substring(0, lastSlash);

			// Extract version from parent folder name if enabled
			String version = null;
			if (useFolderAsVersion && path != null && !path.equals("/")) {
				// Path is like "/1.0.0" or "/folder/1.0.0" - extract the last folder name
				String folderPath = path;
				if (folderPath.endsWith("/")) {
					folderPath = folderPath.substring(0, folderPath.length() - 1);
				}
				int lastFolderSlash = folderPath.lastIndexOf('/');
				version = lastFolderSlash >= 0 ? folderPath.substring(lastFolderSlash + 1) : folderPath;
				Msg.info(this, "Using version '" + version + "' from folder path for " + program.getName());
			}

			URL normalizedProjectURL = GhidraURL.getProjectURL(fileURL);
			String repo = normalizedProjectURL.toExternalForm();

			// Pass version as the first executable category (3rd parameter)
			gensig.openProgram(program, null, version, null, repo, path);
			final FunctionManager fman = program.getFunctionManager();
			final Iterator<Function> iter = fman.getFunctions(true);
			gensig.scanFunctions(iter, fman.getFunctionCount(), monitor);
			final DescriptionManager manager = gensig.getDescriptionManager();
			if (manager.numFunctions() == 0) {
				skipCount++;
				skippedPrograms.add(program.getName() + ": no functions with bodies");
				if (showIndividualPopups) {
					Msg.showWarn(this, null, "Skipping Insert",
						program.getName() + " contains no functions with bodies");
				}
				return;
			}

			manager.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());

			InsertRequest insertreq = new InsertRequest();
			insertreq.manage = manager;
			if (insertreq.execute(pgDatabase) == null) {
				BSimError lastError = pgDatabase.getLastError();
				if ((lastError.category == ErrorCategory.Format) ||
					(lastError.category == ErrorCategory.Nonfatal)) {
					skipCount++;
					skippedPrograms.add(program.getName() + ": " + lastError.message);
					if (showIndividualPopups) {
						Msg.showWarn(this, null, "Skipping Insert",
							program.getName() + ": " + lastError.message);
					}
					return;
				}
				throw new IOException(program.getName() + ": " + lastError.message);
			}

			successCount++;
			String displayName = program.getName();
			if (version != null) {
				displayName += " (Version: " + version + ")";
			}
			processedPrograms.add(displayName);

			if (showIndividualPopups) {
				StringBuilder status = new StringBuilder(program.getName());
				if (version != null) {
					status.append(" [Version: ").append(version).append("]");
				}
				status.append(" added to database ");
				status.append(dbInfo.databasename);
				popup(status.toString());
			}
		}
		finally {
			if (gensig != null) {
				gensig.dispose();
			}
		}
	}
}
