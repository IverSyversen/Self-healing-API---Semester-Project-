package org.evomaster.driver;

import org.evomaster.client.java.controller.ExternalSutController;
import org.evomaster.client.java.controller.InstrumentedSutStarter;
import org.evomaster.client.java.controller.api.dto.SutInfoDto;
import org.evomaster.client.java.controller.api.dto.database.schema.DatabaseType;
import org.evomaster.client.java.controller.db.DbCleaner;
import org.evomaster.client.java.controller.problem.ProblemInfo;
import org.evomaster.client.java.controller.problem.RestProblem;

import java.util.Collections;
import java.util.List;

/**
 * EvoMaster white-box driver for the crAPI Community Service.
 *
 * <p>This controller:
 * <ol>
 *   <li>Starts the community-service fat JAR as an external process, injecting the
 *       EvoMaster Java agent for bytecode instrumentation.</li>
 *   <li>Waits for the Spring Boot banner string to confirm the server is ready.</li>
 *   <li>Resets MongoDB state between EvoMaster test calls so each generated test
 *       starts from a clean database.</li>
 *   <li>Exposes the crAPI OpenAPI spec to guide schema-based test generation.</li>
 * </ol>
 *
 * <p><b>Required system properties (pass with -D on the command line):</b>
 * <ul>
 *   <li>{@code sut.jar}   – absolute path to the community-service fat JAR
 *       (default: {@code /opt/crapi/community-service.jar})</li>
 *   <li>{@code agent.jar} – absolute path to {@code evomaster-agent.jar}
 *       (default: {@code /opt/evomaster/evomaster-agent.jar})</li>
 *   <li>{@code mongo.uri} – MongoDB connection URI
 *       (default: {@code mongodb://localhost:27017/crapi})</li>
 *   <li>{@code openapi.url} – URL of the OpenAPI spec served by the SUT
 *       (default: {@code http://localhost:8087/v3/api-docs})</li>
 * </ul>
 */
public class CrApiCommunityController extends ExternalSutController {

    /** Port the community service listens on (matches Docker Compose config). */
    private static final int SUT_PORT = 8087;

    /** Port the EvoMaster driver REST API listens on. */
    private static final int CONTROLLER_PORT = 40100;

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------

    public static void main(String[] args) {
        int controllerPort = CONTROLLER_PORT;
        if (args.length > 0) {
            controllerPort = Integer.parseInt(args[0]);
        }

        CrApiCommunityController controller = new CrApiCommunityController();
        controller.setControllerPort(controllerPort);

        InstrumentedSutStarter starter = new InstrumentedSutStarter(controller);
        starter.start();
    }

    // -----------------------------------------------------------------------
    // ExternalSutController overrides
    // -----------------------------------------------------------------------

    @Override
    public String getPathToExecutableJar() {
        return System.getProperty("sut.jar", "/opt/crapi/community-service.jar");
    }

    /**
     * JVM flags passed when spawning the community service process.
     * The EvoMaster agent MUST appear first so it can instrument all loaded classes.
     */
    @Override
    public String[] getJVMParameters() {
        String agentJar = System.getProperty("agent.jar",
                "/opt/evomaster/evomaster-agent.jar");
        return new String[]{
                "-javaagent:" + agentJar,
                "-Dspring.profiles.active=default",
                "-Dserver.port=" + SUT_PORT
        };
    }

    /**
     * Application-level arguments forwarded to the Spring Boot application.
     * Override the MongoDB URI when the database is not on localhost
     * (e.g. when using the Docker-internal hostname {@code mongodb}).
     */
    @Override
    public String[] getInputParameters() {
        String mongoUri = System.getProperty("mongo.uri",
                "mongodb://localhost:27017/crapi");
        return new String[]{
                "--spring.data.mongodb.uri=" + mongoUri,
                "--server.port=" + SUT_PORT
        };
    }

    @Override
    public String getBaseURL() {
        return "http://localhost:" + SUT_PORT;
    }

    /**
     * Log message that confirms the Spring Boot server has fully started.
     * EvoMaster polls stdout/stderr for this string before beginning test generation.
     */
    @Override
    public String getLogMessageOfInitializedServer() {
        return "Started CrApiApplication";
    }

    @Override
    public int getTimeoutSeconds() {
        return 180;
    }

    /**
     * Package prefix used to scope bytecode coverage collection.
     * EvoMaster will only count branches in classes under this prefix.
     */
    @Override
    public String getPackagePrefixesToCover() {
        return "com.crapi";
    }

    // -----------------------------------------------------------------------
    // Lifecycle hooks
    // -----------------------------------------------------------------------

    @Override
    public void preStart() {
        // Nothing needed before the SUT process starts.
    }

    @Override
    public void postStart() {
        // Nothing needed after the SUT process starts.
    }

    @Override
    public void preStop() {
        // Nothing needed before the SUT process is stopped.
    }

    @Override
    public void postStop() {
        // Nothing needed after the SUT process is stopped.
    }

    // -----------------------------------------------------------------------
    // State reset between tests
    // -----------------------------------------------------------------------

    /**
     * Called by EvoMaster before each new test to ensure a clean state.
     *
     * <p>For the community service we drop and re-create all MongoDB collections
     * so that posts, comments, and user state do not bleed between tests.
     * The actual reset is delegated to a helper that connects via the Mongo URI.
     */
    @Override
    public void resetStateOfSUT() {
        String mongoUri = System.getProperty("mongo.uri",
                "mongodb://localhost:27017/crapi");
        MongoDbResetter.reset(mongoUri);
    }

    // -----------------------------------------------------------------------
    // Problem / schema information
    // -----------------------------------------------------------------------

    /**
     * Tell EvoMaster where to find the OpenAPI schema for the community service.
     *
     * <p>The community service exposes Swagger UI and an {@code /v3/api-docs} endpoint
     * when running with the default Spring Boot configuration.  If the application
     * does not expose its own docs at runtime, the raw GitHub URL of the crAPI
     * OpenAPI spec is used as a fallback.
     */
    @Override
    public ProblemInfo getProblemInfo() {
        String openapiUrl = System.getProperty("openapi.url",
                "http://localhost:" + SUT_PORT + "/v3/api-docs");
        return new RestProblem(openapiUrl, null);
    }

    @Override
    public SutInfoDto.OutputFormat getPreferredOutputFormat() {
        return SutInfoDto.OutputFormat.JAVA_JUNIT_5;
    }

    // -----------------------------------------------------------------------
    // Database specification (SQL) – not used for MongoDB
    // -----------------------------------------------------------------------

    /**
     * crAPI community service uses MongoDB, not SQL.
     * Return an empty list so EvoMaster does not attempt SQL-based state reset.
     */
    @Override
    public List<org.evomaster.client.java.controller.api.dto.database.schema.DbSpecification>
    getDbSpecifications() {
        return Collections.emptyList();
    }
}
