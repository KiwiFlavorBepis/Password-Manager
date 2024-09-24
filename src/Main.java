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
    private final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        if (!passwordFile.exists()) {
            createFile(passwordFile, token);
        }
        String passcode = promptUser("Enter the passcode to access your passwords: ");
        String[] header = parseHeader(passwordFile);
        String salt = header[0];
        String encryptedToken = header[1];
        if (!verifyToken(passcode, token, salt, encryptedToken)) {
            System.out.println("Incorrect passcode!");
            System.exit(0);
        }
        CipherKey cipherKey = generateCipherKey(salt, passcode);
        while (true) {
            System.out.println("a : Add Password");
            System.out.println("r : Read Password");
            System.out.println("q : Quit");
            String option = promptUser("Enter choice: ");
            switch (option) {
                case "a":
                    addPassword(promptUser("Enter label for password: "), promptUser("Enter password to store: "));
                    break;
                case "r":
                    String password = readPassword(promptUser("Enter label for password: "), passwordFile, cipherKey);
                    System.out.println("Found: " + password);
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

    private static void createFile(File file, String token) {
        System.out.println("No password file detected. Creating new password file...");
        try {
            file.createNewFile();
            FileWriter writer = new FileWriter(file.getPath());
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

    private static String[] parseHeader(File file) {
        String salt = "";
        String encryptedToken = "";
        try {
            Scanner scanner = new Scanner(file);
            String header = scanner.nextLine();
            scanner.close();
            salt = header.substring(0, header.indexOf(":"));
            encryptedToken = header.substring(header.indexOf(":") + 1);
        } catch (FileNotFoundException e) {
            System.out.println("Error reading password file header!");
            e.printStackTrace();
        }
        return new String[]{salt, encryptedToken};
    }

    private static boolean verifyToken(String passcode, String token, String encryptedToken, String salt) {
        CipherKey cypherKey = generateCipherKey(passcode, salt);
        String unencryptedToken = decrypt(cypherKey, encryptedToken);
        return token.equals(unencryptedToken);
    }

    private static void addPassword(String label, String encryptedPassword) {


    }

    private static String readPassword(String label, File passwordFile, CipherKey cipherKey) {
        String password = "";
        try {
            Scanner scanner = new Scanner(passwordFile);
            String lineLabel;
            String encryptedPassword = "";
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                lineLabel = line.substring(0, line.indexOf(":"));
                if (label.equals(lineLabel)) {
                    encryptedPassword = line.substring(line.indexOf(":") + 1);
                    break;
                }
            }
            scanner.close();
            password = decrypt(cipherKey, encryptedPassword);
        } catch (FileNotFoundException e) {
            System.out.println("Error reading password file!");
            e.printStackTrace();
        }
        return password;
    }

    private static String promptUser(String prompt) {
        System.out.println(prompt);
        Scanner userInput = new Scanner(System.in);
        //return scanner input
        return userInput.nextLine();
    }

    private static String createSalt() {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

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

    private static CipherKey generateCipherKey(String key, String salt) {
        byte[] saltBytes = salt.getBytes();
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

}

record CipherKey(Cipher cipher, SecretKeySpec secretKeySpec) {
    Cipher getCipher() {
        return cipher;
    }

    SecretKeySpec getSecretKeySpec() {
        return secretKeySpec;
    }
}