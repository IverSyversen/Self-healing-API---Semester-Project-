package org.evomaster.driver;

import org.evomaster.client.java.controller.ExternalSutController;
import org.evomaster.client.java.controller.InstrumentedSutStarter;
import org.evomaster.client.java.controller.api.dto.SutInfoDto;
import org.evomaster.client.java.controller.problem.ProblemInfo;
import org.evomaster.client.java.controller.problem.RestProblem;
import org.evomaster.client.java.controller.api.dto.auth.AuthenticationDto;
import org.evomaster.client.java.sql.DbSpecification;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * EvoMaster white-box driver for the crAPI Identity Service.
 *
 * <p>The crAPI community service is written in Go and cannot be instrumented by
 * EvoMaster's Java agent.  The identity service (Java / Spring Boot) is used as
 * the white-box testing target instead.
 *
 * <p>This controller:
 * <ol>
 *   <li>Starts the identity-service fat JAR as an external process, injecting the
 *       EvoMaster Java agent for bytecode instrumentation.</li>
 *   <li>Waits for the Spring Boot banner string to confirm the server is ready.</li>
 *   <li>Resets PostgreSQL state between EvoMaster test calls so each generated test
 *       starts from a clean database.</li>
 *   <li>Exposes the crAPI OpenAPI spec to guide schema-based test generation.</li>
 * </ol>
 *
 * <p><b>Optional system properties (pass with -D on the command line):</b>
 * <ul>
 *   <li>{@code sut.jar}    – absolute path to the identity-service fat JAR
 *       (default: {@code /opt/crapi/identity-service.jar})</li>
 *   <li>{@code agent.jar}  – absolute path to {@code evomaster-agent.jar}
 *       (default: {@code /opt/evomaster/evomaster-agent.jar})</li>
 *   <li>{@code jwks.file}  – absolute path to the JWKS JSON file installed by the
 *       build script (default: {@code /opt/crapi/jwks.json})</li>
 *   <li>{@code db.host}    – PostgreSQL hostname (default: {@code localhost})</li>
 *   <li>{@code db.port}    – PostgreSQL port (default: {@code 5432})</li>
 *   <li>{@code db.name}    – PostgreSQL database name (default: {@code crapi})</li>
 *   <li>{@code db.user}    – PostgreSQL username (default: {@code admin})</li>
 *   <li>{@code db.password} – PostgreSQL password
 *       (default: {@code crapisecretpassword})</li>
 *   <li>{@code openapi.url} – URL of the OpenAPI spec served by the SUT
 *       (default: {@code http://localhost:8080/v3/api-docs})</li>
 * </ul>
 */
public class CrApiCommunityController extends ExternalSutController {

    /** Port the identity service listens on. */
    private static final int SUT_PORT = 8080;

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
        return System.getProperty("sut.jar", "/opt/crapi/identity-service.jar");
    }

    /**
     * JVM flags passed when spawning the identity service process.
     *
     * <p>The EvoMaster agent MUST appear first.  All remaining flags pass the
     * environment variables that the Spring Boot application.properties placeholders
     * (e.g. {@code ${DB_HOST}}) require, so the service can start without a
     * Docker-injected environment.
     *
     * <p>DB credentials are sourced from the same system properties used in
     * {@link #resetStateOfSUT()} so both the SUT and the reset logic always use
     * identical credentials.
     */
    @Override
    public String[] getJVMParameters() {
        String agentJar = System.getProperty("agent.jar",
                "/opt/evomaster/evomaster-agent.jar");
        return new String[]{
                "-javaagent:" + agentJar,
                // Server port (overridden via CLI arg in getInputParameters too)
                "-DSERVER_PORT=" + SUT_PORT,
                // PostgreSQL – sourced from same system properties as resetStateOfSUT()
                "-DDB_HOST=" + dbHost(),
                "-DDB_PORT=" + dbPort(),
                "-DDB_NAME=" + dbName(),
                "-DDB_USER=" + dbUser(),
                "-DDB_PASSWORD=" + dbPassword(),
                // MongoDB – present in the identity service application context
                // (used for cross-service calls); point to localhost where MongoDB
                // is exposed from Docker
                "-DMONGO_DB_HOST=localhost",
                "-DMONGO_DB_PORT=27017",
                "-DMONGO_DB_USER=",
                "-DMONGO_DB_PASSWORD=",
                "-DMONGO_DB_NAME=crapi",
                // JWT / security
                "-DSECRET_KEY=crapi-secret-key-evomaster",
                // E-mail (Mailhog, non-critical for test generation)
                "-DSMTP_AUTH=false",
                "-DSMTP_STARTTLS=false",
                "-DSMTP_FROM=no-reply@example.com",
                "-DSMTP_EMAIL=no-reply@example.com",
                "-DSMTP_PASS=",
                "-DSMTP_HOST=localhost",
                "-DSMTP_PORT=1025",
                "-DMAILHOG_HOST=localhost",
                "-DMAILHOG_PORT=1025",
                "-DMAILHOG_DOMAIN=example.com",
                // Misc application settings
                "-DENABLE_SHELL_INJECTION=false",
                "-DAPI_GATEWAY_URL=https://api.mypremiumdealership.com",
                "-DCOMMUNITY_SERVICE_URL=http://localhost:8087",
                // TLS disabled
                "-DTLS_ENABLED=false",
                "-DTLS_KEYSTORE_TYPE=PKCS12",
                "-DTLS_KEYSTORE=classpath:certs/server.p12",
                "-DTLS_KEYSTORE_PASSWORD=passw0rd",
                "-DTLS_KEY_PASSWORD=passw0rd",
                "-DTLS_KEY_ALIAS=identity",
                // JWT – JWKS must be base64-encoded content of jwks.json
                "-DJWKS=" + readJwksBase64()
        };
    }

    /**
     * Application-level arguments forwarded to the Spring Boot application.
     * The server port is set here (highest-priority override).
     */
    @Override
    public String[] getInputParameters() {
        return new String[]{
                "--server.port=" + SUT_PORT
        };
    }

    @Override
    public String getBaseURL() {
        return "http://localhost:" + SUT_PORT;
    }

    /**
     * Log message that confirms the Spring Boot identity service has fully started.
     * EvoMaster polls stdout/stderr for this string before beginning test generation.
     */
    @Override
    public String getLogMessageOfInitializedServer() {
        return "Started CRAPIBootApplication";
    }

    @Override
    public long getMaxAwaitForInitializationInSeconds() {
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
     * <p>Truncates every user-owned table in the {@code public} schema in a single
     * atomic statement so that data created by one generated test cannot affect the
     * next.  Migration history tables (Flyway / Liquibase) are preserved.
     */
    @Override
    public void resetStateOfSUT() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {

            List<String> tables = new ArrayList<>();
            try (ResultSet rs = conn.getMetaData()
                    .getTables(null, "public", "%", new String[]{"TABLE"})) {
                while (rs.next()) {
                    String name = rs.getString("TABLE_NAME");
                    if (!name.startsWith("flyway_")
                            && !name.equals("databasechangelog")
                            && !name.equals("databasechangeloglock")) {
                        tables.add(name);
                    }
                }
            }

            if (tables.isEmpty()) {
                return;
            }

            // Build a single TRUNCATE listing all tables; this is atomic and
            // much faster than N individual statements for frequent EvoMaster resets.
            String tableList = tables.stream()
                    .map(t -> "public.\"" + t.replace("\"", "\"\"") + "\"")
                    .collect(Collectors.joining(", "));

            conn.setAutoCommit(false);
            try (Statement st = conn.createStatement()) {
                // Disable FK checks so tables can be truncated regardless of order.
                st.execute("SET session_replication_role = 'replica'");
                st.execute("TRUNCATE TABLE " + tableList + " RESTART IDENTITY CASCADE");
                st.execute("SET session_replication_role = 'origin'");
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }

        } catch (Exception e) {
            throw new RuntimeException("PostgreSQL state reset failed", e);
        }
    }

    // -----------------------------------------------------------------------
    // Problem / schema information
    // -----------------------------------------------------------------------

    /**
     * Tell EvoMaster where to find the OpenAPI schema for the identity service.
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
    // Database specification (SQL) – delegated to resetStateOfSUT above
    // -----------------------------------------------------------------------

    @Override
    public List<DbSpecification> getDbSpecifications() {
        return Collections.emptyList();
    }

    @Override
    public List<AuthenticationDto> getInfoForAuthentication() {
        return Collections.emptyList();
    }

    // -----------------------------------------------------------------------
    // Helpers – DB properties
    // -----------------------------------------------------------------------

    private String dbHost()     { return System.getProperty("db.host",     "localhost"); }
    private String dbPort()     { return System.getProperty("db.port",     "5432"); }
    private String dbName()     { return System.getProperty("db.name",     "crapi"); }
    private String dbUser()     { return System.getProperty("db.user",     "admin"); }
    private String dbPassword() { return System.getProperty("db.password", "crapisecretpassword"); }

    /** Constructs the JDBC URL from individual db.* properties. */
    private String dbJdbcUrl() {
        return "jdbc:postgresql://" + dbHost() + ":" + dbPort() + "/" + dbName();
    }

    /**
     * Reads the JWKS JSON file installed by {@code build-community-jar.sh} and
     * returns its base64-encoded content, which is what the identity service
     * expects via the {@code JWKS} environment variable / system property.
     */
    private String readJwksBase64() {
        String jwksPath = System.getProperty("jwks.file", "/opt/crapi/jwks.json");
        try {
            byte[] content = Files.readAllBytes(Paths.get(jwksPath));
            return Base64.getEncoder().encodeToString(content);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Cannot read JWKS file at " + jwksPath
                            + " – run scripts/build-community-jar.sh first", e);
        }
    }
}
