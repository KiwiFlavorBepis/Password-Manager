import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    private static final String token = "Token";
    private static final String filePath = "passwords.txt";
    private static final File passwordFile = new File(filePath);

    public static void main(String[] args) {

        //Create a password file if it doesn't exist
        if (!passwordFile.exists()) createFile(passwordFile, token);

        //Get user passcode
        String passcode = promptUser("Enter the passcode to access your passwords: ");

        //Read file header
        String[] header = parseHeader(passwordFile);
        String salt = header[0];

        //Generate session CipherKey
        CipherKey cipherKey = generateCipherKey(passcode, salt);

        //Verify user passcode
        if (!verifyToken(cipherKey, header[1], token)) {
            System.out.println("Incorrect passcode!");
            System.exit(0);
        }

        //Main menu loop
        while (true) {
            System.out.println("\na : Add Password");
            System.out.println("r : Read Password");
            System.out.println("q : Quit");
            String option = promptUser("Enter choice: ");
            switch (option) {
                case "a":
                    addPassword(passwordFile, cipherKey, promptUser("Enter label for password: "), promptUser("Enter password to store: "));
                    break;
                case "r":
                    String password = readPassword(passwordFile, cipherKey, promptUser("Enter label for password: "));
                    if (password != null) System.out.println("Found: " + password);
                    else System.out.println("Label not found!");
                    break;
                case "q":
                    System.out.println("Quitting");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid option!");
                    break;
            }
        }

    }

    /**
     * Automates the process of creating a new password file, including creating the header
     *
     * @param passwordFile The password file to be created
     * @param token        The token to be encrypted in the header
     */
    private static void createFile(File passwordFile, String token) {
        System.out.println("No password file detected. Creating new password file...");
        try {
            passwordFile.createNewFile();
            FileWriter writer = new FileWriter(passwordFile, false);
            String key = promptUser("Create master passcode: ");
            String salt = createSalt();
            CipherKey cypherKey = generateCipherKey(key, salt);
            String encryptedToken = encrypt(cypherKey, token);
            writer.write(salt + ":" + encryptedToken);
            writer.close();
            System.out.println("Password file created.");
        } catch (IOException e) {
            System.out.println("Error creating Password File!");
            e.printStackTrace();
        }
    }

    /**
     * Method to print a prompt and get the user's response
     *
     * @param prompt The prompt to be displayed to the user
     * @return The user's response
     */
    private static String promptUser(String prompt) {
        System.out.println(prompt);
        Scanner userInput = new Scanner(System.in);
        return userInput.nextLine();
    }

    /**
     * Returns an array of the salt and encrypted token contained within a password file's header.
     *
     * @param file The password file to parse the header of
     * @return A 2 element array of strings containing the salt and encrypted token ordered respectively
     */
    private static String[] parseHeader(File file) {
        String header = "";
        try {
            Scanner scanner = new Scanner(file);
            header = scanner.nextLine();
            scanner.close();
        } catch (FileNotFoundException e) {
            System.out.println("Error reading password file header!");
            e.printStackTrace();
        }
        return parseLine(header);
    }

    /**
     * Parses a string of the password file entry format and returns the components
     *
     * @param line A line of the password file with the colon delimiter
     * @return An array containing the content preceding the colon and the content anteceding the colon in respective order
     */
    private static String[] parseLine(String line) {
        String first = line.substring(0, line.indexOf(":"));
        String second = line.substring(line.indexOf(":") + 1);
        return new String[]{first, second};
    }

    /**
     * Returns a CipherKey object created from a key and a salt
     *
     * @param key  A String used as the key
     * @param salt A base 64 encoded string  used as the salt
     * @return A CipherKey object generated using the key and salt
     */
    private static CipherKey generateCipherKey(String key, String salt) {
        byte[] saltBytes = Base64.getDecoder().decode(salt);
        KeySpec keySpec = new PBEKeySpec(key.toCharArray(), saltBytes, 65536, 128);
        Cipher cipher = null;
        SecretKeySpec secretKeySpec = null;
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
            cipher = Cipher.getInstance("AES");
            secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error creating keyFactory!");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.out.println("Error generating secretKey!");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.out.println("Error creating cipher!");
            e.printStackTrace();
        }

        return new CipherKey(cipher, secretKeySpec);
    }

    /**
     * Method to determine if the decrypted encrypted token matches the token
     *
     * @param cipherKey      The CipherKey used to decrypt the token
     * @param encryptedToken The encrypted token to be decrypted and compared
     * @param token          The token to be compared
     * @return Whether the decrypted encrypted token matches the token
     */
    private static boolean verifyToken(CipherKey cipherKey, String encryptedToken, String token) {
        String unencryptedToken = decrypt(cipherKey, encryptedToken);
        return token.equals(unencryptedToken);
    }

    /**
     * Encrypts and adds a password entry to the password file, or updates it if the label already exists
     *
     * @param passwordFile        The password file
     * @param cipherKey           The session CipherKey
     * @param label               The label to add or update
     * @param unencryptedPassword The password to add
     */
    private static void addPassword(File passwordFile, CipherKey cipherKey, String label, String unencryptedPassword) {
        String encryptedPassword = encrypt(cipherKey, unencryptedPassword);
        try {
            Scanner scanner = new Scanner(passwordFile);
            StringBuilder buffer = new StringBuilder();
            boolean found = false;
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String lineLabel = parseLine(line)[0];
                if (lineLabel.equals(label)) {
                    found = true;
                    line = label + ":" + encryptedPassword;
                }
                buffer.append(line).append("\n");
            }
            if (!found) buffer.append(label).append(":").append(encryptedPassword).append("\n");
            scanner.close();
            FileWriter writer = new FileWriter(passwordFile, false);
            writer.write(buffer.toString());
            writer.close();
        } catch (IOException e) {
            System.out.println("Error reading password file!");
            e.printStackTrace();
        }
    }

    /**
     * Reads and decrypts an entry from the password file
     *
     * @param passwordFile The password file
     * @param cipherKey    The session CipherKey
     * @param label        The label of the password to read
     * @return The decrypted decoded password, or null if the label cannot be found
     */
    private static String readPassword(File passwordFile, CipherKey cipherKey, String label) {
        String password = null;
        try {
            Scanner scanner = new Scanner(passwordFile);
            String lineLabel;
            String encryptedPassword = null;
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String[] entries = parseLine(line);
                lineLabel = entries[0];
                if (label.equals(lineLabel)) {
                    encryptedPassword = entries[1];
                    break;
                }
            }
            scanner.close();
            if (encryptedPassword != null) password = decrypt(cipherKey, encryptedPassword);
        } catch (FileNotFoundException e) {
            System.out.println("Error reading password file!");
            e.printStackTrace();
        }
        return password;
    }

    /**
     * Returns a secure randomly generated base 64 encoded salt String.
     *
     * @return A base 64 encoded String
     */
    private static String createSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        System.out.println("Created salt: " + Base64.getEncoder().encodeToString(salt));
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Encrypts and encodes a string using the CipherKey
     *
     * @param cipherKey         The CipherKey used to encrypt
     * @param unencryptedString The unencrypted string to be encrypted
     * @return An encrypted string encoded in base 64
     */
    private static String encrypt(CipherKey cipherKey, String unencryptedString) {
        Cipher cipher = cipherKey.getCipher();
        SecretKeySpec secretKeySpec = cipherKey.getSecretKeySpec();
        String encryptedString = "";
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedData = cipher.doFinal(unencryptedString.getBytes());
            encryptedString = new String(Base64.getEncoder().encode(encryptedData));
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key, could not initialize cipher!");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("Illegal block size, could not encrypt!");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.out.println("Bad padding, could not encrypt!");
            e.printStackTrace();
        }
        return encryptedString;
    }

    /**
     * Decrypts a base 64 encoded encrypted string using the CipherKey
     *
     * @param cipherKey       The CipherKey used to decrypt
     * @param encryptedString The base 64 encoded encrypted string to be decrypted and decoded
     * @return A decrypted decoded string
     */
    private static String decrypt(CipherKey cipherKey, String encryptedString) {
        Cipher cipher = cipherKey.getCipher();
        SecretKeySpec secretKeySpec = cipherKey.getSecretKeySpec();
        String decryptedString = "";
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decodedString = Base64.getDecoder().decode(encryptedString);
            decryptedString = new String(cipher.doFinal(decodedString));
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key, could not initialize cipher!");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("Illegal block size, could not decrypt!");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.out.println("Bad padding, could not decrypt!");
            e.printStackTrace();
        }
        return decryptedString;
    }


}

/**
 * A record to store the two components needed to encrypt or decrypt
 *
 * @param cipher        A Cipher object
 * @param secretKeySpec A SecretKeySpec object
 */
record CipherKey(Cipher cipher, SecretKeySpec secretKeySpec) {

    /**
     * Getter method for the record's Cipher
     *
     * @return A Cipher object
     */
    Cipher getCipher() {
        return cipher;
    }

    /**
     * Getter method for the record's SecretKeySpec
     *
     * @return A SecretKeySpec object
     */
    SecretKeySpec getSecretKeySpec() {
        return secretKeySpec;
    }
}