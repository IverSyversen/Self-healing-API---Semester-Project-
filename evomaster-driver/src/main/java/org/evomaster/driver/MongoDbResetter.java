package org.evomaster.driver;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility that drops and recreates every collection in the crAPI MongoDB
 * database, giving each EvoMaster-generated test a clean state.
 *
 * <p>Collections reset:
 * <ul>
 *   <li>{@code posts}    – community forum posts</li>
 *   <li>{@code comments} – post comments</li>
 *   <li>{@code users}    – cached user references</li>
 * </ul>
 */
public class MongoDbResetter {

    private static final Logger log = LoggerFactory.getLogger(MongoDbResetter.class);

    /** Collections owned by the community service that must be cleared between tests. */
    private static final String[] COLLECTIONS = {"posts", "comments", "users"};

    private MongoDbResetter() {
        // utility class
    }

    /**
     * Drops all community-service collections and re-creates them as empty.
     *
     * @param mongoUri MongoDB connection URI, e.g. {@code mongodb://localhost:27017/crapi}
     */
    public static void reset(String mongoUri) {
        // Extract database name from the URI (last path segment).
        String dbName = extractDatabaseName(mongoUri);

        try (MongoClient client = MongoClients.create(mongoUri)) {
            MongoDatabase db = client.getDatabase(dbName);

            for (String collection : COLLECTIONS) {
                try {
                    db.getCollection(collection).drop();
                    db.createCollection(collection);
                    log.debug("Reset MongoDB collection: {}", collection);
                } catch (Exception e) {
                    // A missing collection is not an error – log and continue.
                    log.warn("Could not reset collection '{}': {}", collection, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Failed to connect to MongoDB for state reset: {}", e.getMessage(), e);
            throw new RuntimeException("MongoDB state reset failed", e);
        }
    }

    /**
     * Parses the database name from a standard MongoDB URI.
     *
     * <p>Examples:
     * <pre>
     *   mongodb://localhost:27017/crapi       →  crapi
     *   mongodb://user:pass@host:27017/mydb   →  mydb
     * </pre>
     *
     * @param uri MongoDB connection URI
     * @return database name extracted from the URI, or {@code "crapi"} if it cannot be parsed
     */
    static String extractDatabaseName(String uri) {
        // Strip query string, then take the last path segment.
        String stripped = uri.contains("?") ? uri.substring(0, uri.indexOf('?')) : uri;
        int lastSlash = stripped.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < stripped.length() - 1) {
            return stripped.substring(lastSlash + 1);
        }
        return "crapi";
    }
}
