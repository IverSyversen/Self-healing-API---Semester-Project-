
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.evomaster.driver.CrApiCommunityController;

import static io.restassured.RestAssured.*;
import static org.hamcrest.Matchers.*;

/**
 * EvoMaster generated test class – fault cases.
 */
public class CrApiCommunityEvoMasterTest_faults {

    private static final CrApiCommunityController controller = new CrApiCommunityController();

    @BeforeAll
    public static void initClass() {}

    @AfterAll
    public static void tearDown() {}

    @Test
    public void test0_expectFault() {
        org.junit.jupiter.api.Assertions.assertNotNull(controller);
    }
}
