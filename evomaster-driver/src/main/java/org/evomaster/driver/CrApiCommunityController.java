package org.evomaster.driver;

import org.evomaster.client.java.controller.ExternalSutController;
import org.evomaster.client.java.controller.InstrumentedSutStarter;
import org.evomaster.client.java.controller.api.dto.SutInfoDto;
import org.evomaster.client.java.controller.api.dto.auth.AuthenticationDto;
import org.evomaster.client.java.controller.api.dto.database.schema.DatabaseType;
import org.evomaster.client.java.controller.problem.ProblemInfo;
import org.evomaster.client.java.controller.problem.RestProblem;
import org.evomaster.client.java.sql.DbSpecification;
import com.webfuzzing.commons.auth.Header;
import com.webfuzzing.commons.auth.LoginEndpoint;
import com.webfuzzing.commons.auth.TokenHandling;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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

    /**
     * Fixed OTP used for password-reset and verify-email flows.
     * A known value lets EvoMaster submit the correct OTP when it discovers
     * the verify endpoint, turning a dead-end 400 into an explorable success path.
     */
    private static final String SEED_OTP = "000000";

    /**
     * Fixed email-change token seeded in {@code otp_token}.
     * Allows EvoMaster to exercise the verify-email-change endpoint without
     * needing to intercept a live email.
     */
    private static final String SEED_EMAIL_TOKEN = "evomaster-email-token";

    /**
     * Fixed OTP used for the phone-number-change confirmation flow.
     */
    private static final String SEED_PHONE_OTP = "111111";

    private static final SeedUser USER_ALICE =
            new SeedUser("alice@evomaster.test", "Alice EM", "+15550001111", "user",  "alice-apikey-evomaster");
    private static final SeedUser USER_BOB =
            new SeedUser("bob@evomaster.test",   "Bob EM",   "+15550002222", "user",  "bob-apikey-evomaster");
    private static final SeedUser USER_MECH =
            new SeedUser("mech@evomaster.test",  "Mech EM",  "+15550003333", "mechanic", "mech-apikey-evomaster");
    /**
     * Admin account (ERole ordinal 3 = ROLE_ADMIN).
     * Needed to exercise the {@code /identity/management/admin/**} endpoints
     * that Spring Security restricts to ADMIN role.
     */
    private static final SeedUser USER_ADMIN =
            new SeedUser("admin@evomaster.test", "Admin EM", "+15550004444", "admin", "admin-apikey-evomaster");

    private static final List<SeedUser> SEED_USERS =
            Collections.unmodifiableList(Arrays.asList(USER_ALICE, USER_BOB, USER_MECH, USER_ADMIN));

    private final String sutJarPath;

    public CrApiCommunityController() {
        this.sutJarPath = System.getProperty("sut.jar", "/opt/crapi/identity-service.jar");
    }

    public CrApiCommunityController(String sutJarPath) {
        this.sutJarPath = (sutJarPath == null || sutJarPath.isBlank())
                ? System.getProperty("sut.jar", "/opt/crapi/identity-service.jar")
                : sutJarPath;
    }

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
        return sutJarPath;
    }

    @Override
    public String[] getJVMParameters() {
        String sutXms = System.getProperty("sut.jvm.xms", "256m");
        String sutXmx = System.getProperty("sut.jvm.xmx", "768m");
        String smtpPass = System.getProperty("smtp.pass", "evomaster-local");
        return new String[]{
                "-Xms" + sutXms,
                "-Xmx" + sutXmx,
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
                "-DSMTP_PASS=" + smtpPass,
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
        // "Starting ..." appears too early (before the embedded server is ready).
        // Waiting for "Started ..." prevents EvoMaster from sending traffic while
        // Spring is still bootstrapping.
        return "Started CRAPIBootApplication";
    }

    @Override
    public long getMaxAwaitForInitializationInSeconds() {
        return Long.getLong("sut.startup.timeout.seconds", 420L);
    }

    @Override
    public int getWaitingSecondsForIncomingConnection() {
        // Despite the method name, EvoMaster expects this in milliseconds.
        return Integer.getInteger("sut.instrumentation.socket.timeout.ms", 120_000);
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
     *   <li>Re-seed four fixed accounts (two customers, one mechanic, one admin)
     *       so that {@link #getInfoForAuthentication()} can log them in and hand
     *       valid JWTs to every EvoMaster test action.</li>
     *   <li>Seed vehicles with locations, OTP records, email-change tokens,
     *       phone-change OTPs, and profile-video stubs so that EvoMaster can
     *       reach the deeper branches that depend on pre-existing DB state.</li>
     * </ol>
     */
    @Override
    public void resetStateOfSUT() {
        if (Boolean.parseBoolean(System.getProperty("reset.postgres", "true"))) {
            resetPostgres();
        }
        if (Boolean.parseBoolean(System.getProperty("reset.mongo", "false"))) {
            resetMongo();
        }
        if (Boolean.parseBoolean(System.getProperty("seed.users", "true"))) {
            seedUsers();
            seedVehicles();
            seedOtps();
            seedOtpTokens();
            seedPhoneChangeOtps();
            seedProfileVideos();
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
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            conn.setAutoCommit(false);
            try {
                if (tableExists(conn, "user_login") && sequenceExists(conn, "user_login_id_seq")) {
                    seedUsersCurrentSchema(conn);
                } else {
                    seedUsersLegacySchema(conn);
                }
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            System.err.println("[driver] Seed users skipped: " + e.getMessage());
        }
    }

    private void seedUsersCurrentSchema(Connection conn) throws SQLException {
        String insertLogin = "INSERT INTO public.user_login "
                + "(id, email, number, password, role, api_key) "
                + "VALUES (nextval('public.user_login_id_seq'), ?, ?, ?, ?, ?) "
                + "RETURNING id";
        String insertDetails = "INSERT INTO public.user_details "
                + "(id, available_credit, name, status, user_id) "
                + "VALUES (nextval('public.user_details_id_seq'), ?, ?, ?, ?)";

        try (PreparedStatement loginPs = conn.prepareStatement(insertLogin);
             PreparedStatement detailsPs = conn.prepareStatement(insertDetails)) {
            for (SeedUser u : SEED_USERS) {
                loginPs.setString(1, u.email);
                loginPs.setString(2, u.phone);
                loginPs.setString(3, SEED_PASSWORD_BCRYPT);
                loginPs.setShort(4, roleOrdinal(u.role));
                loginPs.setString(5, u.apiKey);

                long userId;
                try (ResultSet rs = loginPs.executeQuery()) {
                    if (!rs.next()) {
                        throw new SQLException("Failed to insert user_login row for " + u.email);
                    }
                    userId = rs.getLong(1);
                }

                detailsPs.setDouble(1, 10_000.0);
                detailsPs.setString(2, u.name);
                detailsPs.setString(3, "ACTIVE");
                detailsPs.setLong(4, userId);
                detailsPs.executeUpdate();
            }
        }
    }

    private void seedUsersLegacySchema(Connection conn) throws SQLException {
        String sql = "INSERT INTO public.user_login (email, number, password, role, api_key) VALUES (?,?,?,?,?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (SeedUser u : SEED_USERS) {
                ps.setString(1, u.email);
                ps.setString(2, u.phone);
                ps.setString(3, SEED_PASSWORD_BCRYPT);
                ps.setString(4, u.role);
                ps.setString(5, u.apiKey);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    /**
     * Seeds one vehicle per customer account (Alice and Bob) so EvoMaster's
     * BOLA detector has real vehicleIds to probe.  Without seeded vehicles,
     * the /identity/api/v2/vehicle/{vehicleId}/location endpoint (crAPI's
     * canonical BOLA target) is unreachable because no valid IDs exist.
     *
     * <p>Each vehicle is linked to a freshly inserted {@code vehicle_location}
     * row so the location endpoint returns real data rather than null.
     *
     * <p>Vehicle VINs are fixed and deterministic so test runs are reproducible.
     * The method is a no-op when the vehicle_details table does not exist
     * (version skew) or when the vehicle_model catalog is empty.
     *
     * <p><b>Fixed bugs vs. original implementation:</b>
     * <ul>
     *   <li>Column is {@code owner_id}, not {@code user_id}.</li>
     *   <li>{@code status} is a {@code smallint} (EStatus ordinal), not a string.</li>
     *   <li>{@code uuid} and {@code year} are NOT NULL and must be supplied.</li>
     *   <li>{@code id} must be fetched from {@code vehicle_details_seq} explicitly.</li>
     * </ul>
     */
    private void seedVehicles() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            if (!tableExists(conn, "vehicle_details")) {
                return;
            }

            // Pick any available model from the catalog seeded at startup.
            long modelId;
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery(
                         "SELECT id FROM public.vehicle_model LIMIT 1")) {
                if (!rs.next()) {
                    return;
                }
                modelId = rs.getLong(1);
            }

            // Fetch Alice and Bob's user IDs (inserted by seedUsers()).
            String lookupSql = "SELECT id FROM public.user_login WHERE email = ?";
            long aliceId = lookupUserId(conn, lookupSql, USER_ALICE.email);
            long bobId   = lookupUserId(conn, lookupSql, USER_BOB.email);
            if (aliceId < 0 || bobId < 0) {
                return;
            }

            conn.setAutoCommit(false);
            try {
                insertVehicle(conn, aliceId, modelId,
                        "1HGEM21303L000001", "000001",
                        "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1",
                        "37.7749295", "-122.4194155");
                insertVehicle(conn, bobId, modelId,
                        "1HGEM21303L000002", "000002",
                        "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2",
                        "37.3382082", "-121.8863286");
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            System.err.println("[driver] Seed vehicles skipped: " + e.getMessage());
        }
    }

    /**
     * Seeds OTP records for all users so EvoMaster can exercise the
     * password-reset verification flow ({@code /identity/api/v2/user/reset-password}).
     * Without a pre-seeded OTP the verify step always returns 400 and EvoMaster
     * can never reach the success branch.
     */
    private void seedOtps() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            if (!tableExists(conn, "otp")) return;
            String lookupSql = "SELECT id FROM public.user_login WHERE email = ?";
            String insertSql = "INSERT INTO public.otp (id, otp, status, count, user_id) "
                    + "VALUES (nextval('public.otp_seq'), ?, 'ACTIVE', 0, ?)";
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                for (SeedUser u : SEED_USERS) {
                    long userId = lookupUserId(conn, lookupSql, u.email);
                    if (userId < 0) continue;
                    ps.setString(1, SEED_OTP);
                    ps.setLong(2, userId);
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            System.err.println("[driver] Seed OTPs skipped: " + e.getMessage());
        }
    }

    /**
     * Seeds email-change token records so EvoMaster can exercise the
     * verify-email-change endpoint ({@code /identity/api/v2/user/change-email}).
     * The token value {@value #SEED_EMAIL_TOKEN} is fixed so EvoMaster can
     * discover and submit it via taint analysis.
     */
    private void seedOtpTokens() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            if (!tableExists(conn, "otp_token")) return;
            String lookupSql = "SELECT id FROM public.user_login WHERE email = ?";
            String insertSql = "INSERT INTO public.otp_token "
                    + "(id, email_token, new_email, old_email, status, user_id) "
                    + "VALUES (nextval('public.otp_token_seq'), ?, ?, ?, 'ACTIVE', ?)";
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                for (SeedUser u : SEED_USERS) {
                    long userId = lookupUserId(conn, lookupSql, u.email);
                    if (userId < 0) continue;
                    String newEmail = u.email.replace("@evomaster.test", ".new@evomaster.test");
                    ps.setString(1, SEED_EMAIL_TOKEN);
                    ps.setString(2, newEmail);
                    ps.setString(3, u.email);
                    ps.setLong(4, userId);
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            System.err.println("[driver] Seed OTP tokens skipped: " + e.getMessage());
        }
    }

    /**
     * Seeds phone-change OTP records so EvoMaster can reach the phone-number
     * change confirmation branch.
     */
    private void seedPhoneChangeOtps() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            if (!tableExists(conn, "otp_phone_number_change")) return;
            String lookupSql = "SELECT id FROM public.user_login WHERE email = ?";
            String insertSql = "INSERT INTO public.otp_phone_number_change "
                    + "(id, otp, new_phone, old_phone, status, user_id) "
                    + "VALUES (nextval('public.otp_phone_number_change_seq'), ?, ?, ?, 'ACTIVE', ?)";
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                for (SeedUser u : SEED_USERS) {
                    long userId = lookupUserId(conn, lookupSql, u.email);
                    if (userId < 0) continue;
                    // Derive a new phone by incrementing the last digit.
                    String newPhone = u.phone.substring(0, u.phone.length() - 1)
                            + ((Integer.parseInt(u.phone.substring(u.phone.length() - 1)) + 1) % 10);
                    ps.setString(1, SEED_PHONE_OTP);
                    ps.setString(2, newPhone);
                    ps.setString(3, u.phone);
                    ps.setLong(4, userId);
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            System.err.println("[driver] Seed phone-change OTPs skipped: " + e.getMessage());
        }
    }

    /**
     * Seeds a profile-video stub for every user.
     *
     * <p>The {@code profile_video} table has a unique constraint on {@code user_id},
     * so without a pre-seeded row the GET/UPDATE/DELETE/convert-video endpoints
     * all return "Video not found" and EvoMaster can never reach the success
     * or BOLA branches on those paths.  The actual video binary ({@code oid})
     * is left null — the endpoints for retrieving metadata and the
     * command-injection convert endpoint do not require it.
     */
    private void seedProfileVideos() {
        try (Connection conn = DriverManager.getConnection(dbJdbcUrl(), dbUser(), dbPassword())) {
            if (!tableExists(conn, "profile_video")) return;
            String lookupSql = "SELECT id FROM public.user_login WHERE email = ?";
            String insertSql = "INSERT INTO public.profile_video "
                    + "(id, video_name, conversion_params, user_id) "
                    + "VALUES (nextval('public.profile_video_seq'), ?, null, ?)";
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(insertSql)) {
                int idx = 1;
                for (SeedUser u : SEED_USERS) {
                    long userId = lookupUserId(conn, lookupSql, u.email);
                    if (userId < 0) continue;
                    ps.setString(1, "seed-video-" + idx++ + ".mp4");
                    ps.setLong(2, userId);
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            }
        } catch (Exception e) {
            System.err.println("[driver] Seed profile videos skipped: " + e.getMessage());
        }
    }

    private long lookupUserId(Connection conn, String sql, String email) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong(1) : -1L;
            }
        }
    }

    /**
     * Inserts a vehicle row together with a fresh location row.
     *
     * <p>Required columns fixed vs. original broken implementation:
     * <ul>
     *   <li>{@code owner_id} — the correct FK column name (was {@code user_id}).</li>
     *   <li>{@code status 1} — smallint ACTIVE ordinal (was the string {@code 'inactive'}).</li>
     *   <li>{@code uuid} — NOT NULL, supplied as a fixed deterministic value.</li>
     *   <li>{@code year} — NOT NULL, supplied as 2023.</li>
     *   <li>{@code id} — fetched from {@code vehicle_details_seq}.</li>
     *   <li>{@code location_id} — FK to a freshly inserted {@code vehicle_location} row,
     *       enabling the location endpoint to return real coordinates.</li>
     * </ul>
     */
    private void insertVehicle(Connection conn, long ownerId, long modelId,
                                String vin, String pincode, String uuid,
                                String latitude, String longitude) throws SQLException {
        // Insert location first so we can reference it.
        long locationId;
        String locationSql = "INSERT INTO public.vehicle_location "
                + "(id, latitude, longitude) "
                + "VALUES (nextval('public.vehicle_location_seq'), ?, ?) "
                + "RETURNING id";
        try (PreparedStatement ps = conn.prepareStatement(locationSql)) {
            ps.setString(1, latitude);
            ps.setString(2, longitude);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                locationId = rs.getLong(1);
            }
        }

        // status=1 → EStatus.ACTIVE (ordinal 1 in the EStatus enum).
        String vehicleSql = "INSERT INTO public.vehicle_details "
                + "(id, pincode, status, uuid, year, vin, vehicle_model_id, owner_id, location_id) "
                + "VALUES (nextval('public.vehicle_details_seq'), ?, 1, ?::uuid, 2023, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(vehicleSql)) {
            ps.setString(1, pincode);
            ps.setString(2, uuid);
            ps.setString(3, vin);
            ps.setLong(4, modelId);
            ps.setLong(5, ownerId);
            ps.setLong(6, locationId);
            ps.executeUpdate();
        }
    }

    private boolean tableExists(Connection conn, String tableName) throws SQLException {
        String sql = "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, tableName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private boolean sequenceExists(Connection conn, String sequenceName) throws SQLException {
        String sql = "SELECT 1 FROM information_schema.sequences WHERE sequence_schema = 'public' AND sequence_name = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, sequenceName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Maps a role name to the {@code ERole} enum ordinal stored in
     * the {@code user_login.role} smallint column.
     *
     * <p>Ordinals confirmed by decompiling
     * {@code BOOT-INF/classes/com/crapi/enums/ERole.class} from the identity-service JAR:
     * <pre>
     *   iconst_0 → ROLE_PREDEFINE  (0)
     *   iconst_1 → ROLE_USER       (1)
     *   iconst_2 → ROLE_MECHANIC   (2)
     *   iconst_3 → ROLE_ADMIN      (3)
     * </pre>
     *
     * <p>Spring Security authorization rules (from {@code WebSecurityConfig}):
     * <ul>
     *   <li>{@code /identity/management/admin/**} → {@code hasRole("ADMIN")} → ordinal 3</li>
     *   <li>all other protected paths → {@code authenticated()} → any role passes</li>
     * </ul>
     *
     * <p>Seeded users need the correct ordinals so that Spring Security
     * authorities match what each endpoint requires after
     * {@link #resetStateOfSUT()} re-inserts them.
     */
    private short roleOrdinal(String role) {
        switch (role.toLowerCase()) {
            case "user":     return 1; // ROLE_USER
            case "mechanic": return 2; // ROLE_MECHANIC
            case "admin":    return 3; // ROLE_ADMIN
            default:         return 0; // ROLE_PREDEFINE (fallback)
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
        if (Boolean.parseBoolean(System.getProperty("driver.disable.sql.spec", "false"))) {
            return Collections.emptyList();
        }
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
     * Registers the four seed accounts with EvoMaster.
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
     * <p>Having two customer accounts (Alice and Bob) enables EvoMaster's BOLA
     * detector: it repeats the same request under Alice's token using Bob's
     * object IDs (and vice versa) and flags any 2xx response as a
     * Broken-Object-Level-Authorization fault.
     *
     * <p>The admin account (role=3, ROLE_ADMIN) unlocks
     * {@code /identity/management/admin/**} endpoints that Spring Security
     * restricts to the ADMIN role.
     */
    /**
     * Registers eight auth identities with EvoMaster — four JWT-based and four
     * static-header (ApiKey) entries, one of each per seed account.
     *
     * <h3>Why two entries per user?</h3>
     * <ul>
     *   <li><b>JWT entries</b> (alice, bob, mech, admin): EvoMaster dynamically
     *       POSTs to {@code /identity/api/auth/login} before each test and attaches
     *       the returned RS256-signed Bearer token.  These are the primary auth
     *       identities used during exploration.  Having two customer accounts enables
     *       EvoMaster's BOLA detector (cross-user object access checks).</li>
     *   <li><b>ApiKey entries</b> (alice-key, bob-key, mech-key, admin-key): crAPI's
     *       {@code JwtAuthTokenFilter} accepts {@code Authorization: ApiKey <jwt>}
     *       as an alternative auth path.  On this path, JWT <em>signature validation
     *       is skipped</em> — only structural JWT parsing happens — so we use a
     *       deterministic fake-signed JWT generated by {@link #buildFakeJwt}.
     *       Because these are fixed headers, EvoMaster embeds them verbatim in
     *       generated test code, avoiding the {@code "Bearer {}"} placeholder bug
     *       in EvoMaster 5.1.0 where the JWT is not substituted at code-gen time.</li>
     * </ul>
     */
    @Override
    public List<AuthenticationDto> getInfoForAuthentication() {
        List<AuthenticationDto> list = new ArrayList<>();
        // JWT-based auth (dynamic — used during exploration)
        list.add(buildLogin("alice", USER_ALICE));
        list.add(buildLogin("bob",   USER_BOB));
        list.add(buildLogin("mech",  USER_MECH));
        list.add(buildLogin("admin", USER_ADMIN));
        // API-key-based auth (static — embeds cleanly in generated test code)
        list.add(buildApiKeyAuth("alice-key", USER_ALICE));
        list.add(buildApiKeyAuth("bob-key",   USER_BOB));
        list.add(buildApiKeyAuth("mech-key",  USER_MECH));
        list.add(buildApiKeyAuth("admin-key", USER_ADMIN));
        return list;
    }

    private static AuthenticationDto buildLogin(String name, SeedUser u) {
        AuthenticationDto auth = new AuthenticationDto(name);

        LoginEndpoint login = new LoginEndpoint();
        login.setEndpoint("/identity/api/auth/login");
        login.setVerb(LoginEndpoint.HttpVerb.POST);
        login.setContentType("application/json");
        login.setPayloadRaw("{\"email\":\"" + u.email
                + "\",\"password\":\"" + SEED_PASSWORD_PLAIN + "\"}");
        login.setExpectCookies(false);

        TokenHandling token = new TokenHandling();
        token.setExtractFrom(TokenHandling.ExtractFrom.BODY);
        token.setExtractSelector("/token");
        token.setSendIn(TokenHandling.SendIn.HEADER);
        token.setSendName("Authorization");
        token.setSendTemplate("Bearer {}");
        login.setToken(token);

        auth.setLoginEndpointAuth(login);
        return auth;
    }

    /**
     * Builds a fixed-header auth entry using crAPI's {@code ApiKey} auth path.
     *
     * <h3>How crAPI's ApiKey auth actually works (decompiled from JAR)</h3>
     * <ol>
     *   <li>{@code JwtAuthTokenFilter.getKeyType()} reads the {@code Authorization}
     *       header and returns {@code APIKEY} if the value
     *       {@code startsWith("ApiKey")}.</li>
     *   <li>{@code getToken()} strips the first 7 characters of the
     *       {@code Authorization} value (i.e. the {@code "ApiKey "} prefix,
     *       7 chars including the space).</li>
     *   <li>On the APIKEY path, {@code getUserFromToken()} calls
     *       {@code tokenProvider.getUserNameFromJwtToken(token)}, which uses
     *       {@code com.nimbusds.jwt.JWTParser.parse(token).getJWTClaimsSet().getSubject()}.
     *       <b>Crucially, {@code validateJwtToken()} is never called on the APIKEY
     *       path — there is no signature verification.</b>  Only the structural
     *       validity of the JWT and the presence of a {@code sub} claim are
     *       required.</li>
     * </ol>
     *
     * <h3>Why this fixes the generated-test {@code "Bearer {}"} problem</h3>
     * EvoMaster 5.1.0 has a code-generation bug where the JWT placeholder is
     * not substituted when writing the static {@code _faults_Test.java} file.
     * Fixed headers are embedded verbatim — no placeholder substitution — so
     * generated tests use the real {@code Authorization: ApiKey <jwt>} value.
     *
     * @see #buildFakeJwt(String, String)
     */
    private static AuthenticationDto buildApiKeyAuth(String name, SeedUser u) {
        AuthenticationDto auth = new AuthenticationDto(name);
        Header header = new Header();
        // The filter reads the Authorization header and checks startsWith("ApiKey").
        // getToken() strips 7 chars ("ApiKey "), so the remaining string must be
        // parseable by JWTParser.parse() — a plain string is NOT valid JWT syntax.
        header.setName("Authorization");
        header.setValue("ApiKey " + buildFakeJwt(u.email, u.role));
        auth.setFixedHeaders(Collections.singletonList(header));
        return auth;
    }

    /**
     * Builds a structurally valid JWT that will be accepted by crAPI's APIKEY
     * authentication path without requiring a valid RSA signature.
     *
     * <p>On the APIKEY path, {@code getUserNameFromJwtToken()} uses
     * {@code JWTParser.parse(token)} (Nimbus JOSE+JWT), which parses the token
     * structure without verifying the signature.  The signature is therefore
     * a dummy value — only the header and payload must be well-formed base64url
     * JSON with a {@code sub} claim.
     *
     * <p>The expiry ({@code exp}) is set to 2099-01-01 so the token is valid
     * for any test run regardless of clock drift.
     *
     * @param email  placed in the {@code sub} claim (used by
     *               {@code loadUserByUsername()} to look up the user in the DB)
     * @param role   placed in the {@code role} claim (informational; the filter
     *               loads the actual role from the DB)
     * @return a three-part dot-separated JWT string
     */
    private static String buildFakeJwt(String email, String role) {
        String headerJson  = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        // exp=4102444800 is 2099-01-01T00:00:00Z in Unix epoch seconds.
        String payloadJson = String.format(
                "{\"sub\":\"%s\",\"role\":\"%s\",\"iat\":1700000000,\"exp\":4102444800}",
                email, role);
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String h = enc.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String p = enc.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        // Any non-empty base64url bytes work as the dummy signature on the APIKEY path.
        return h + "." + p + ".AAAAAAAAAA";
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
        /** Static API key seeded into {@code user_login.api_key}.
         *  The crAPI {@code JwtAuthTokenFilter} accepts an {@code ApiKey}
         *  request header as an alternative to a Bearer JWT.  Because API keys
         *  never expire they can be embedded as fixed headers in EvoMaster's
         *  generated test code, which solves the {@code "Bearer {}"} placeholder
         *  problem that arises when JWT tokens expire before code generation. */
        final String apiKey;

        SeedUser(String email, String name, String phone, String role, String apiKey) {
            this.email  = email;
            this.name   = name;
            this.phone  = phone;
            this.role   = role;
            this.apiKey = apiKey;
        }
    }
}
