package main;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        CustomKeyGenerator keyGenerator = new CustomKeyGenerator();
        ApplicationTextOutput appTxtOutput = new ApplicationTextOutput();
        Scanner s = new Scanner(System.in);
        boolean a = true;
        String input;
        String cipher;
        String password;
        int keySize;
        while (a) {
            input = appTxtOutput.getIntroDialog(s);

            switch (input) {
                case "1" -> {
                    cipher = appTxtOutput.getCipher(s);
                    keySize = appTxtOutput.getKeySize(s);
                    Key randomKey = keyGenerator.getRandomKey(cipher, keySize);
                    appTxtOutput.outputResult(cipher, keySize, randomKey, null);
                }
                case "2" -> {
                    cipher = appTxtOutput.getCipher(s);
                    keySize = appTxtOutput.getKeySize(s);
                    Key randomKey = keyGenerator.getSecureRandomKey(cipher, keySize);
                    appTxtOutput.outputResult(cipher, keySize, randomKey, null);
                }
                case "3" -> {
                    cipher = appTxtOutput.getCipher(s);
                    keySize = appTxtOutput.getKeySize(s);
                    Key randomKey = keyGenerator.getKeyFromKG(cipher, keySize);
                    appTxtOutput.outputResult(cipher, keySize, randomKey, null);
                }
                case "4" -> {
                    cipher = appTxtOutput.getCipher(s);
                    keySize = appTxtOutput.getKeySize(s);
                    password = appTxtOutput.getPassword(s);
                    Key randomKey;
                    try {
                        randomKey = keyGenerator.getPasswordBasedKey(cipher, keySize, password.toCharArray());
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e ) {
                        throw new RuntimeException(e);
                    }
                    appTxtOutput.outputResult(cipher, keySize, randomKey, password);
                }
                case "5" -> a = false;
                default -> System.out.println();
            }
        }
    }
}
