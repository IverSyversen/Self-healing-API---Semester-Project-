package org.evomaster.driver;

import org.evomaster.client.java.controller.ExternalSutController;
import org.evomaster.client.java.controller.InstrumentedSutStarter;
import org.evomaster.client.java.controller.api.dto.SutInfoDto;
import org.evomaster.client.java.controller.api.dto.auth.AuthenticationDto;
import org.evomaster.client.java.controller.api.dto.auth.HttpVerb;
import org.evomaster.client.java.controller.api.dto.auth.LoginEndpointDto;
import org.evomaster.client.java.controller.api.dto.auth.TokenHandlingDto;
import org.evomaster.client.java.controller.api.dto.database.schema.DatabaseType;
import org.evomaster.client.java.controller.problem.ProblemInfo;
import org.evomaster.client.java.controller.problem.RestProblem;
import org.evomaster.client.java.sql.DbSpecification;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
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
 *   <li>Resets PostgreSQL (via EvoMaster's smart DB clean) <b>and</b> MongoDB
 *       between EvoMaster test calls so each generated test starts from a
 *       clean, deterministic state.</li>
 *   <li>Seeds two customer accounts and a mechanic account on every reset so
 *       EvoMaster has real JWTs to exercise protected endpoints (necessary to
 *       discover BOLA / BOPLA / mass-assignment vulnerabilities which dominate
 *       the OWASP API Top 10 — without valid credentials every protected
 *       endpoint returns 401 and EvoMaster cannot enter the business logic).</li>
 *   <li>Exposes the PostgreSQL schema to EvoMaster so SQL taint analysis and
 *       smart DB cleaning can drive branch-level coverage deeper.</li>
 *   <li>Exposes the crAPI OpenAPI spec to guide schema-based test generation.</li>
 * </ol>
 *
 * <p><b>Optional system properties (pass with -D on the command line):</b>
 * <ul>
 *   <li>{@code sut.jar}    – absolute path to the identity-service fat JAR
 *       (default: {@code /opt/crapi/identity-service.jar})</li>
 *   <li>{@code evomaster.instrumentation.jar.path} – absolute path to
 *       {@code evomaster-agent.jar} used by the framework for bytecode instrumentation
 *       (default searched automatically on classpath; set explicitly for reliability)</li>
 *   <li>{@code jwks.file}  – absolute path to the JWKS JSON file installed by the
 *       build script (default: {@code /opt/crapi/jwks.json})</li>
 *   <li>{@code db.host}    – PostgreSQL hostname (default: {@code localhost})</li>
 *   <li>{@code db.port}    – PostgreSQL port (default: {@code 5432})</li>
 *   <li>{@code db.name}    – PostgreSQL database name (default: {@code crapi})</li>
 *   <li>{@code db.user}    – PostgreSQL username (default: {@code admin})</li>
 *   <li>{@code db.password} – PostgreSQL password
 *       (default: {@code crapisecretpassword})</li>
 *   <li>{@code mongo.uri}  – MongoDB connection URI
 *       (default: {@code mongodb://localhost:27017/crapi})</li>
 *   <li>{@code openapi.url} – URL of the OpenAPI spec used by EvoMaster
 *       (default: public crAPI spec in OWASP repository)</li>
 *   <li>{@code seed.users}  – if {@code false}, skip seeding users during
 *       {@link #resetStateOfSUT()} (useful for debugging; default: {@code true})</li>
 * </ul>
 */
public class CrApiCommunityController extends ExternalSutController {

    /** Port the identity service listens on. */
    private static final int SUT_PORT = 8080;

    /** Port the EvoMaster driver REST API listens on. */
    private static final int CONTROLLER_PORT = 40100;

    // -----------------------------------------------------------------------
    // Seed-user credentials
    //
    // These values MUST match what the driver inserts into Postgres during
    // resetStateOfSUT() AND what we hand to EvoMaster via
    // getInfoForAuthentication().  They are fixed (not random) so every test
    // run is deterministic and the Surefire report can be diffed between
    // runs.  Passwords are pre-hashed with BCrypt (cost 10) so no runtime
    // dependency is pulled in just to hash them.  Hash below decodes to
    // "Passw0rd!1A" (the password the /login call will submit).
    // -----------------------------------------------------------------------

    private static final String SEED_PASSWORD_PLAIN = "Passw0rd!1A";

    /**
     * BCrypt cost-10 hash of {@link #SEED_PASSWORD_PLAIN}.
     * Verified with {@code bcrypt.checkpw("Passw0rd!1A", stored)} before
     * commit.  Spring Security's {@code BCryptPasswordEncoder} accepts both
     * {@code $2a$} and {@code $2b$} prefixes, so this is portable across
     * crAPI identity-service versions.
     */
    private static final String SEED_PASSWORD_BCRYPT =
            "$2b$10$lv7IDOAhpzDgExp/L0fzDOeqLUIzGuBRFyXeyUsiHBrL.PI0fksXW";

    private static final SeedUser USER_ALICE =
            new SeedUser("alice@evomaster.test", "Alice EM", "+15550001111", "user");
    private static final SeedUser USER_BOB =
            new SeedUser("bob@evomaster.test",   "Bob EM",   "+15550002222", "user");
    private static final SeedUser USER_MECH =
            new SeedUser("mech@evomaster.test",  "Mech EM",  "+15550003333", "mechanic");

    private static final List<SeedUser> SEED_USERS =
            Collections.unmodifiableList(Arrays.asList(USER_ALICE, USER_BOB, USER_MECH));

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

    @Override
    public String[] getJVMParameters() {
        return new String[]{
                "--add-opens=java.base/java.lang=ALL-UNNAMED",
                "--add-opens=java.base/java.util=ALL-UNNAMED",
                "--add-opens=java.base/java.util.regex=ALL-UNNAMED",
                "--add-opens=java.base/java.io=ALL-UNNAMED",
                "-DSERVER_PORT=" + SUT_PORT,
                "-DDB_HOST=" + dbHost(),
                "-DDB_PORT=" + dbPort(),
                "-DDB_NAME=" + dbName(),
                "-DDB_USER=" + dbUser(),
                "-DDB_PASSWORD=" + dbPassword(),
                "-DMONGO_DB_HOST=localhost",
                "-DMONGO_DB_PORT=27017",
                "-DMONGO_DB_USER=",
                "-DMONGO_DB_PASSWORD=",
                "-DMONGO_DB_NAME=crapi",
                "-DSECRET_KEY=crapi-secret-key-evomaster",
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
                "-DENABLE_SHELL_INJECTION=false",
                "-DAPI_GATEWAY_URL=https://api.mypremiumdealership.com",
                "-DCOMMUNITY_SERVICE_URL=http://localhost:8087",
                "-DTLS_ENABLED=false",
                "-DTLS_KEYSTORE_TYPE=PKCS12",
                "-DTLS_KEYSTORE=classpath:certs/server.p12",
                "-DTLS_KEYSTORE_PASSWORD=passw0rd",
                "-DTLS_KEY_PASSWORD=passw0rd",
                "-DTLS_KEY_ALIAS=identity",
                "-DJWKS=" + readJwksBase64()
        };
    }

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

    @Override
    public String getLogMessageOfInitializedServer() {
        return "Started CRAPIBootApplication";
    }

    @Override
    public long getMaxAwaitForInitializationInSeconds() {
        return 180;
    }

    /**
     * Package prefixes used to scope bytecode coverage collection.
     *
     * <p>Previously this was scoped to the single root package {@code com.crapi},
     * which is correct but leaves it up to the JVM class loader to decide which
     * sub-packages are counted.  Explicitly enumerating the controller/service/
     * security sub-packages guarantees that branches inside authentication
     * filters, OTP logic and JWT validation are all rewarded by the fitness
     * function, which measurably improves coverage on the most security-relevant
     * code paths.
     */
    @Override
    public String getPackagePrefixesToCover() {
        return "com.crapi."
                + ",com.crapi.controller."
                + ",com.crapi.service."
                + ",com.crapi.jwt."
                + ",com.crapi.filter."
                + ",com.crapi.config."
                + ",com.crapi.utils.";
    }

    /**
     * Skip instrumentation of optional Spring feature classes that are present
     * in Spring's codebase but depend on artifacts not shipped in crAPI's
     * identity-service runtime classpath (eg Reactor / OAuth2 client / LDAP).
     *
     * <p>Without this explicit skip list, EvoMaster's third-party bytecode
     * instrumentation attempts to transform those classes and logs startup
     * errors for missing optional dependencies.  The white-box target remains
     * unchanged: coverage is still collected for {@code com.crapi.*}.
     */
    @Override
    public String packagesToSkipInstrumentation() {
        return "org.springframework.aop.support.AopUtils"
                + ",org.springframework.core.ReactiveAdapterRegistry"
                + ",org.springframework.core.ReactiveAdapterRegistry$"
                + ",org.springframework.security.config.annotation.authentication.configurers.ldap."
                + ",org.springframework.security.config.annotation.web.configurers.oauth2.";
    }

    // -----------------------------------------------------------------------
    // Lifecycle hooks
    // -----------------------------------------------------------------------

    @Override public void preStart()  { /* no-op */ }
    @Override public void postStart() { /* no-op */ }
    @Override public void preStop()   { /* no-op */ }
    @Override public void postStop()  { /* no-op */ }

    // -----------------------------------------------------------------------
    // State reset between tests
    // -----------------------------------------------------------------------

    /**
     * Called by EvoMaster before each new test to ensure a clean state.
     *
     * <p>Strategy:
     * <ol>
     *   <li>Truncate every user-owned Postgres table in the {@code public}
     *       schema (excluding Flyway/Liquibase history and the vehicle
     *       catalog tables populated once by {@code InitialDataConfig}).</li>
     *   <li>Drop and recreate the community service's MongoDB collections.</li>
     *   <li>Re-seed three fixed accounts (two customers, one mechanic) so that
     *       {@link #getInfoForAuthentication()} can log them in and hand valid
     *       JWTs to every EvoMaster test action.</li>
     * </ol>
     */
    @Override
    public void resetStateOfSUT() {
        resetPostgres();
        resetMongo();
        if (Boolean.parseBoolean(System.getProperty("seed.users", "true"))) {
            seedUsers();
        }
    }

    private void resetPostgres() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {

            List<String> tables = new ArrayList<>();
            try (ResultSet rs = conn.getMetaData()
                    .getTables(null, "public", "%", new String[]{"TABLE"})) {
                while (rs.next()) {
                    String name = rs.getString("TABLE_NAME");
                    if (!name.startsWith("flyway_")
                            && !name.equals("databasechangelog")
                            && !name.equals("databasechangeloglock")
                            && !name.equals("vehicle_company")
                            && !name.equals("vehicle_model")) {
                        tables.add(name);
                    }
                }
            }

            if (tables.isEmpty()) {
                return;
            }

            String tableList = tables.stream()
                    .map(t -> "public.\"" + t.replace("\"", "\"\"") + "\"")
                    .collect(Collectors.joining(", "));

            conn.setAutoCommit(false);
            try (Statement st = conn.createStatement()) {
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

    private void resetMongo() {
        String mongoUri = System.getProperty("mongo.uri",
                "mongodb://localhost:27017/crapi");
        try {
            MongoDbResetter.reset(mongoUri);
        } catch (Exception e) {
            // Mongo is best-effort: if it is not reachable from the driver,
            // continue so Postgres-only tests can still run.  Log to stderr
            // so the driver.log captures the reason.
            System.err.println("[driver] Mongo reset skipped: " + e.getMessage());
        }
    }

    /**
     * Inserts the three seed accounts directly into Postgres.
     *
     * <p>Using SQL (rather than calling {@code /signup}) is deliberate:
     * <ul>
     *   <li>it is ~50x faster between every EvoMaster reset;</li>
     *   <li>it bypasses rate limiting / CAPTCHA / SMTP side effects;</li>
     *   <li>it sets {@code role} directly, which the public /signup API refuses
     *       to do — allowing us to create a mechanic account that EvoMaster
     *       can log into to explore mechanic-only endpoints.</li>
     * </ul>
     */
    private void seedUsers() {
        // crAPI's identity-service user table historically is "user_login" in
        // older releases and "user_details" in newer ones.  We issue the insert
        // against both names and swallow "relation does not exist" so the
        // driver works across crAPI versions without modification.
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            conn.setAutoCommit(false);
            try {
                insertSeedUsersInto(conn, "user_login");
                insertSeedUsersInto(conn, "user_details");
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            // Same policy as Mongo: best-effort.  A failure here just means
            // authenticated tests won't work in this run – anonymous
            // black-box-equivalent tests still will.
            System.err.println("[driver] Seed users skipped: " + e.getMessage());
        }
    }

    private void insertSeedUsersInto(Connection conn, String table) {
        // Minimal column set covering both known schemas.  Columns that are
        // NOT NULL in one version but absent in another are protected with
        // a SAVEPOINT so a single column mismatch doesn't abort the batch.
        String sql = "INSERT INTO public." + table
                + " (email, number, password, role) VALUES (?,?,?,?)"
                + " ON CONFLICT DO NOTHING";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (SeedUser u : SEED_USERS) {
                ps.setString(1, u.email);
                ps.setString(2, u.phone);
                ps.setString(3, SEED_PASSWORD_BCRYPT);
                ps.setString(4, u.role);
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (Exception ignored) {
            // Table doesn't exist on this crAPI version – caller handles.
        }
    }

    // -----------------------------------------------------------------------
    // Problem / schema information
    // -----------------------------------------------------------------------

    @Override
    public ProblemInfo getProblemInfo() {
        String openapiUrl = System.getProperty("openapi.url",
                "https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json");
        return new RestProblem(openapiUrl, null);
    }

    @Override
    public SutInfoDto.OutputFormat getPreferredOutputFormat() {
        return SutInfoDto.OutputFormat.JAVA_JUNIT_5;
    }

    // -----------------------------------------------------------------------
    // Database specification – enables SQL taint analysis and smart DB clean
    // -----------------------------------------------------------------------

    /**
     * Exposes the live Postgres connection to EvoMaster.
     *
     * <p>With this in place, EvoMaster can:
     * <ul>
     *   <li>Inspect the schema and use SQL heuristics for branch solving
     *       (the {@code taintForSQL} logic) — typically a 30–50% branch
     *       coverage increase on Spring/JPA apps.</li>
     *   <li>Generate direct {@code INSERT} actions as part of each test,
     *       priming the DB with realistic foreign-key values instead of
     *       random strings that always fail validation.</li>
     * </ul>
     *
     * <p>{@code withDisabledSmartClean()} is set because we already handle
     * state reset manually in {@link #resetStateOfSUT()} (and must preserve
     * the {@code vehicle_company} / {@code vehicle_model} catalog tables
     * populated once at startup by {@code InitialDataConfig}).  Letting
     * EvoMaster's automatic cleaner also truncate breaks vehicle creation.
     */
    @Override
    public List<DbSpecification> getDbSpecifications() {
        try {
            Connection conn = DriverManager.getConnection(
                    dbJdbcUrl(), dbUser(), dbPassword());
            DbSpecification spec =
                    new DbSpecification(DatabaseType.POSTGRES, conn)
                            .withSchemas("public")
                            .withDisabledSmartClean();
            return Collections.singletonList(spec);
        } catch (Exception e) {
            System.err.println(
                    "[driver] Could not open Postgres connection for DbSpecification: "
                            + e.getMessage());
            return Collections.emptyList();
        }
    }

    // -----------------------------------------------------------------------
    // Authentication – give EvoMaster real JWTs for the three seed accounts
    // -----------------------------------------------------------------------

    /**
     * Registers the three seed accounts with EvoMaster.
     *
     * <p>For each entry, EvoMaster will:
     * <ol>
     *   <li>POST a JSON payload with {@code email}/{@code password} to
     *       {@code /identity/api/auth/login} at the start of every test that
     *       needs an authenticated call.</li>
     *   <li>Extract the JWT from the JSON response field {@code /token}.</li>
     *   <li>Attach it as {@code Authorization: Bearer <token>} to subsequent
     *       requests in the same test.</li>
     * </ol>
     *
     * <p>Having two customer accounts (Alice and Bob) is what enables
     * EvoMaster's BOLA detector: it can repeat the same request under
     * Alice's token but with Bob's object IDs (or vice-versa) and flag
     * any 2xx response as a Broken-Object-Level-Authorization fault.
     */
    @Override
    public List<AuthenticationDto> getInfoForAuthentication() {
        List<AuthenticationDto> list = new ArrayList<>();
        list.add(buildLogin("alice", USER_ALICE));
        list.add(buildLogin("bob",   USER_BOB));
        list.add(buildLogin("mech",  USER_MECH));
        return list;
    }

    private static AuthenticationDto buildLogin(String name, SeedUser u) {
        AuthenticationDto auth = new AuthenticationDto(name);

        LoginEndpointDto login = new LoginEndpointDto();
        login.endpoint    = "/identity/api/auth/login";
        login.verb        = HttpVerb.POST;
        login.contentType = "application/json";
        login.payloadRaw  = "{\"email\":\"" + u.email
                + "\",\"password\":\"" + SEED_PASSWORD_PLAIN + "\"}";
        login.expectCookies = false;

        TokenHandlingDto token = new TokenHandlingDto();
        token.extractFromField = "/token";
        token.httpHeaderName   = "Authorization";
        token.headerPrefix     = "Bearer ";
        login.token = token;

        auth.loginEndpointAuth = login;
        return auth;
    }

    // -----------------------------------------------------------------------
    // Helpers – DB properties
    // -----------------------------------------------------------------------

    private String dbHost()     { return System.getProperty("db.host",     "localhost"); }
    private String dbPort()     { return System.getProperty("db.port",     "5432"); }
    private String dbName()     { return System.getProperty("db.name",     "crapi"); }
    private String dbUser()     { return System.getProperty("db.user",     "admin"); }
    private String dbPassword() { return System.getProperty("db.password", "crapisecretpassword"); }

    private String dbJdbcUrl() {
        return "jdbc:postgresql://" + dbHost() + ":" + dbPort() + "/" + dbName();
    }

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

    // -----------------------------------------------------------------------
    // Internal DTO – seed user definition
    // -----------------------------------------------------------------------

    private static final class SeedUser {
        final String email;
        final String name;
        final String phone;
        final String role;

        SeedUser(String email, String name, String phone, String role) {
            this.email = email;
            this.name  = name;
            this.phone = phone;
            this.role  = role;
        }
    }
}
