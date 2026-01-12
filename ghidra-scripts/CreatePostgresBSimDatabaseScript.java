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
//Creates a new BSim database on a PostgreSQL server
//@category BSim
import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.MessageType;

public class CreatePostgresBSimDatabaseScript extends GhidraScript {

	private static final String HOST = "Host";
	private static final String PORT = "Port";
	private static final String DATABASE_NAME = "Database Name";
	private static final String USERNAME = "Username";
	private static final String DATABASE_TEMPLATE = "Database Template";
	private static final String FUNCTION_TAGS = "Function Tags (CSV)";
	private static final String EXECUTABLE_CATEGORIES = "Executable Categories (CSV)";
	private static final String TRACK_CALL_GRAPH = "Track Call Graph";

	// Default category for version tracking
	private static final String DEFAULT_VERSION_CATEGORY = "Version";

	private static final int DEFAULT_POSTGRES_PORT = 5432;

	private static final String[] templates =
		{ "medium_nosize", "medium_32", "medium_64", "medium_cpool" };

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("Use \"bsim createdatabase\" to create a PostgreSQL BSim database from the command line");
			return;
		}

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(HOST, "localhost");
		values.defineInt(PORT, DEFAULT_POSTGRES_PORT);
		values.defineString(DATABASE_NAME, "bsim");
		values.defineString(USERNAME, System.getProperty("user.name"));
		values.defineChoice(DATABASE_TEMPLATE, "medium_nosize", templates);
		values.defineString(FUNCTION_TAGS);
		values.defineString(EXECUTABLE_CATEGORIES, DEFAULT_VERSION_CATEGORY);
		values.defineBoolean(TRACK_CALL_GRAPH, true);

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
			if (dbName.contains("/") || dbName.contains("\\") || dbName.contains(" ")) {
				status.setStatusText("Database Name contains invalid characters!", MessageType.ERROR);
				return false;
			}
			String username = valueMap.getString(USERNAME);
			if (StringUtils.isBlank(username)) {
				status.setStatusText("Username cannot be empty!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		askValues("Create PostgreSQL BSim Database",
			"Enter values required to create a new BSim database on PostgreSQL.", values);

		String host = values.getString(HOST);
		int port = values.getInt(PORT);
		String dbName = values.getString(DATABASE_NAME);
		String username = values.getString(USERNAME);
		String template = values.getChoice(DATABASE_TEMPLATE);
		boolean trackCallGraph = values.getBoolean(TRACK_CALL_GRAPH);

		String functionTagsCSV = values.getString(FUNCTION_TAGS);
		List<String> tags = parseCSV(functionTagsCSV);

		String exeCatCSV = values.getString(EXECUTABLE_CATEGORIES);
		List<String> cats = parseCSV(exeCatCSV);

		BSimServerInfo serverInfo = new BSimServerInfo(DBType.postgres, username, host, port, dbName);

		try (FunctionDatabase pgDatabase = BSimClientFactory.buildClient(serverInfo, false)) {

			CreateDatabase command = new CreateDatabase();
			command.info = new DatabaseInformation();
			command.info.databasename = dbName;
			command.config_template = template;
			command.info.trackcallgraph = trackCallGraph;

			ResponseInfo response = command.execute(pgDatabase);
			if (response == null) {
				BSimError lastError = pgDatabase.getLastError();
				String errorMsg = lastError != null ? lastError.message : "Unknown error";
				throw new IOException("Failed to create database: " + errorMsg);
			}

			// Install function tags
			for (String tag : tags) {
				InstallTagRequest req = new InstallTagRequest();
				req.tag_name = tag;
				ResponseInfo resp = req.execute(pgDatabase);
				if (resp == null) {
					BSimError lastError = pgDatabase.getLastError();
					throw new LSHException("Failed to install tag '" + tag + "': " + lastError.message);
				}
			}

			// Install executable categories
			for (String cat : cats) {
				InstallCategoryRequest req = new InstallCategoryRequest();
				req.type_name = cat;
				ResponseInfo resp = req.execute(pgDatabase);
				if (resp == null) {
					BSimError lastError = pgDatabase.getLastError();
					throw new LSHException("Failed to install category '" + cat + "': " + lastError.message);
				}
			}

			StringBuilder successMsg = new StringBuilder();
			successMsg.append("Database '").append(dbName).append("' created successfully!\n\n");
			successMsg.append("Server: ").append(host).append(":").append(port).append("\n");
			successMsg.append("Template: ").append(template).append("\n");
			successMsg.append("Track Call Graph: ").append(trackCallGraph).append("\n");
			if (!tags.isEmpty()) {
				successMsg.append("Function Tags: ").append(String.join(", ", tags)).append("\n");
			}
			if (!cats.isEmpty()) {
				successMsg.append("Executable Categories: ").append(String.join(", ", cats)).append("\n");
			}
			popup(successMsg.toString());
		}
	}

	/**
	 * Parse a comma-separated string into a de-duplicated, sorted list
	 */
	private List<String> parseCSV(String csv) {
		Set<String> parsed = new HashSet<>();
		if (StringUtils.isEmpty(csv)) {
			return new ArrayList<String>();
		}
		String[] parts = csv.split(",");
		for (String p : parts) {
			if (!StringUtils.isBlank(p)) {
				parsed.add(p.trim());
			}
		}
		List<String> res = new ArrayList<>(parsed);
		res.sort(String::compareTo);
		return res;
	}
}
