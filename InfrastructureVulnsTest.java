import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests to verify that the weak MD5 cryptographic algorithm has been replaced
 * with the secure SHA-256 algorithm (CWE-327 remediation).
 */
public class InfrastructureVulnsTest {

    private InfrastructureVulns vulns;

    @BeforeEach
    public void setUp() {
        vulns = new InfrastructureVulns();
    }

    /**
     * Verify that the hash method returns a SHA-256 digest (32 bytes),
     * not an MD5 digest (16 bytes). This is the primary regression guard
     * for CWE-327: Use of Broken or Risky Cryptographic Algorithm.
     */
    @Test
    public void testHashUsesSha256NotMd5() throws Exception {
        byte[] digest = vulns.md5("test-input");

        // SHA-256 produces a 32-byte (256-bit) digest
        assertEquals(32, digest.length,
                "Expected SHA-256 output length of 32 bytes, not MD5's 16 bytes");
    }

    /**
     * Verify the output matches the expected SHA-256 digest for a known input,
     * confirming the algorithm is SHA-256 and not MD5.
     */
    @Test
    public void testHashProducesCorrectSha256Digest() throws Exception {
        String input = "hello";
        byte[] actual = vulns.md5(input);

        // Compute expected SHA-256 digest via stdlib to compare
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(input.getBytes());

        assertArrayEquals(expected, actual,
                "Hash output should match SHA-256 digest for the same input");
    }

    /**
     * Verify the output does NOT match the MD5 digest for the same input,
     * confirming MD5 is no longer in use.
     */
    @Test
    public void testHashDoesNotProduceMd5Digest() throws Exception {
        String input = "hello";
        byte[] actual = vulns.md5(input);

        // Compute MD5 digest to confirm it is NOT being returned
        byte[] md5Digest = MessageDigest.getInstance("MD5")
                .digest(input.getBytes());

        assertFalse(java.util.Arrays.equals(md5Digest, actual),
                "Hash output must NOT be an MD5 digest (MD5 is broken per CWE-327)");
    }

    /**
     * Verify that the method is deterministic — same input yields same output,
     * confirming correct use of the MessageDigest API.
     */
    @Test
    public void testHashIsDeterministic() throws Exception {
        String input = "deterministic-input";
        byte[] first = vulns.md5(input);
        byte[] second = vulns.md5(input);

        assertArrayEquals(first, second,
                "Same input must always produce the same SHA-256 digest");
    }

    /**
     * Verify that different inputs produce different digests (collision resistance),
     * a basic property expected of SHA-256 but not reliably provided by MD5.
     */
    @Test
    public void testDifferentInputsProduceDifferentDigests() throws Exception {
        byte[] digest1 = vulns.md5("input-one");
        byte[] digest2 = vulns.md5("input-two");

        assertFalse(java.util.Arrays.equals(digest1, digest2),
                "Different inputs should produce different SHA-256 digests");
    }

    /**
     * Verify that the method handles an empty string input without throwing,
     * and still returns a valid 32-byte SHA-256 digest.
     */
    @Test
    public void testHashHandlesEmptyString() throws Exception {
        byte[] digest = vulns.md5("");

        assertNotNull(digest, "Digest should not be null for empty input");
        assertEquals(32, digest.length,
                "SHA-256 digest of empty string should be 32 bytes");
    }
}
