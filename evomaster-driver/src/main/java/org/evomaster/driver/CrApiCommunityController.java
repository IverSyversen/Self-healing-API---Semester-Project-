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
 *       (default: {@code /opt/crapi/community-service.jar})</li>
 *   <li>{@code agent.jar}  – absolute path to {@code evomaster-agent.jar}
 *       (default: {@code /opt/evomaster/evomaster-agent.jar})</li>
 *   <li>{@code jwks.file}  – absolute path to the JWKS JSON file installed by the
 *       build script (default: {@code /opt/crapi/jwks.json})</li>
 *   <li>{@code db.host}    – PostgreSQL hostname (default: {@code localhost})</li>
 *   <li>{@code db.url}     – full JDBC URL for state reset
 *       (default: {@code jdbc:postgresql://localhost:5432/crapi})</li>
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
        return System.getProperty("sut.jar", "/opt/crapi/community-service.jar");
    }

    /**
     * JVM flags passed when spawning the identity service process.
     *
     * <p>The EvoMaster agent MUST appear first.  All remaining flags pass the
     * environment variables that the Spring Boot application.properties placeholders
     * (e.g. {@code ${DB_HOST}}) require, so the service can start without a
     * Docker-injected environment.
     */
    @Override
    public String[] getJVMParameters() {
        String agentJar = System.getProperty("agent.jar",
                "/opt/evomaster/evomaster-agent.jar");
        String dbHost = System.getProperty("db.host", "localhost");
        return new String[]{
                "-javaagent:" + agentJar,
                // PostgreSQL
                "-DDB_HOST=" + dbHost,
                "-DDB_PORT=5432",
                "-DDB_NAME=crapi",
                "-DDB_USER=admin",
                "-DDB_PASSWORD=crapisecretpassword",
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
     * <p>Truncates every user-owned table in the {@code public} schema so that
     * data created by one generated test cannot affect the next.  Migration
     * history tables (Flyway / Liquibase) are preserved.
     */
    @Override
    public void resetStateOfSUT() {
        String pgUrl  = System.getProperty("db.url",      "jdbc:postgresql://localhost:5432/crapi");
        String pgUser = System.getProperty("db.user",     "admin");
        String pgPass = System.getProperty("db.password", "crapisecretpassword");

        try (Connection conn = DriverManager.getConnection(pgUrl, pgUser, pgPass)) {

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

            try (Statement st = conn.createStatement()) {
                // Disable FK checks so tables can be truncated in any order.
                st.execute("SET session_replication_role = 'replica'");
                for (String table : tables) {
                    st.execute("TRUNCATE TABLE public.\"" + table
                            + "\" RESTART IDENTITY CASCADE");
                }
                st.execute("SET session_replication_role = 'origin'");
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
    // Helpers
    // -----------------------------------------------------------------------

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
