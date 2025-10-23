// Example of Hardcoded Credentials and Secrets
// This file demonstrates common hardcoded secret patterns for testing security reviews

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

public class HardcodedSecrets {

    // VULNERABILITY 1: Hardcoded database credentials
    private static final String DB_PASSWORD = "MySecretP@ssw0rd123";
    private static final String DB_USER = "admin";
    private static final String DB_URL = "jdbc:mysql://db.example.com:3306/myapp";

    // VULNERABILITY 2: Hardcoded API keys
    private static final String API_KEY = "sk_live_abc123def456ghi789jkl012mno345";
    private static final String STRIPE_SECRET = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";

    // VULNERABILITY 3: Hardcoded AWS credentials
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // VULNERABILITY 4: Hardcoded JWT secret
    private static final String JWT_SECRET = "myVerySecretJWTKey12345";

    // VULNERABILITY 5: Hardcoded encryption key
    private static final byte[] ENCRYPTION_KEY = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // INSECURE: Database connection with hardcoded credentials
    public Connection connectToDatabase_insecure() throws Exception {
        // VULNERABILITY: Hardcoded credentials in source code
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    // INSECURE: API call with hardcoded API key
    public void makeAPICall_insecure() {
        // VULNERABILITY: Hardcoded API key
        String url = "https://api.example.com/data";
        // HTTP request with hardcoded API key in header
        // headers.put("Authorization", "Bearer " + API_KEY);
    }

    // INSECURE: AWS S3 client with hardcoded credentials
    public S3Client createS3Client_insecure() {
        // VULNERABILITY: Hardcoded AWS credentials
        AwsBasicCredentials awsCreds = AwsBasicCredentials.create(
            AWS_ACCESS_KEY,
            AWS_SECRET_KEY
        );

        return S3Client.builder()
            .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
            .build();
    }

    // INSECURE: Connection string with embedded password
    public void connectWithConnectionString_insecure() {
        // VULNERABILITY: Password in connection string
        String connectionString = "Server=myserver;Database=mydb;User Id=admin;Password=SecretPass123;";
        // Use connection string...
    }

    // INSECURE: Hardcoded OAuth token
    public void authenticateWithOAuth_insecure() {
        // VULNERABILITY: Hardcoded OAuth token
        String accessToken = "ya29.a0AfH6SMBx...longTokenString...";
        // Use token for authentication...
    }

    // SECURE EXAMPLES (for comparison)

    // SECURE: Using environment variables
    public Connection connectToDatabase_secure() throws Exception {
        // SECURE: Credentials from environment variables
        String dbUrl = System.getenv("DB_URL");
        String dbUser = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");

        if (dbPassword == null || dbUser == null || dbUrl == null) {
            throw new IllegalStateException("Database credentials not configured");
        }

        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    // SECURE: Using AWS default credential provider chain
    public S3Client createS3Client_secure() {
        // SECURE: Uses IAM roles, environment variables, or AWS credentials file
        // No hardcoded credentials needed
        return S3Client.builder()
            .build();  // Uses DefaultCredentialsProvider
    }

    // SECURE: Using configuration file (not in version control)
    public void loadConfiguration_secure() {
        // SECURE: Load from external configuration
        Properties config = new Properties();
        // Load from file not in version control (e.g., /etc/myapp/config.properties)
        // Or use secret management service like AWS Secrets Manager, HashiCorp Vault
    }

    // SECURE: API key from environment
    public void makeAPICall_secure() {
        // SECURE: API key from environment variable
        String apiKey = System.getenv("API_KEY");

        if (apiKey == null) {
            throw new IllegalStateException("API_KEY environment variable not set");
        }

        String url = "https://api.example.com/data";
        // HTTP request with API key from environment
        // headers.put("Authorization", "Bearer " + apiKey);
    }
}

// Additional examples of sensitive data that should not be hardcoded:
// - Private keys
// - OAuth client secrets
// - SSH keys
// - TLS/SSL certificates and keys
// - Webhook secrets
// - HMAC secrets
// - Service account keys
// - Database connection strings with credentials
// - Third-party service credentials (Twilio, SendGrid, etc.)
