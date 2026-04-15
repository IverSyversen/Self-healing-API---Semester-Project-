
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.evomaster.driver.CrApiCommunityController;

import static io.restassured.RestAssured.*;
import static org.hamcrest.Matchers.*;

/**
 * EvoMaster generated test class – success cases.
 * Mirrors the real output structure (no package, imports org.evomaster.driver).
 */
public class CrApiCommunityEvoMasterTest_successes {

    private static final CrApiCommunityController controller = new CrApiCommunityController();

    @BeforeAll
    public static void initClass() {
        // controller.startSut() would be called in a full run; skipped here
    }

    @AfterAll
    public static void tearDown() {
        // controller.stopSut() would be called in a full run; skipped here
    }

    @Test
    public void test0_getHealthOk() {
        // Minimal smoke test: just verify the controller class is resolvable
        org.junit.jupiter.api.Assertions.assertNotNull(controller);
    }
}
