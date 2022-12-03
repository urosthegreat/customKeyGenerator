package main;

import java.security.Key;
import java.util.Arrays;
import java.util.Scanner;

public class ApplicationTextOutput {
    public String getIntroDialog(Scanner s) {
        System.out.println("Welcome to the key generator!");
        System.out.println();
        System.out.println("Pick the type of key generator, choose a number:");
        System.out.println("1. Random key [1]");
        System.out.println();
        System.out.println("2. Secure Random key [2]");
        System.out.println();
        System.out.println("3. CustomKeyGenerator key [3]");
        System.out.println();
        System.out.println("4. Password Based key [4]");
        System.out.println();
        System.out.println("5. Press to end application [5]");
        System.out.println();

        String result = s.nextLine().trim().toLowerCase();
        if (result.equals("")) {
            result = s.nextLine().trim().toLowerCase();
        }
        return result;
    }

    public String getCipher(Scanner s) {
        System.out.println("Input the cipher:");
        return s.nextLine();
    }

    public int getKeySize(Scanner s) {
        System.out.println("Input the key size:");
        return s.nextInt();
    }

    public void outputResult(String cipher, int keySize, Key key, String password) {
        if (password == null) {
            System.out.printf("""
                            The inputted cipher: %s
                             The inputted key size %d
                             The resulted key %s
                             """
                    , cipher, keySize, Arrays.toString(key.getEncoded()));
        } else {
            System.out.printf("""
                            The inputted cipher: %s
                             The inputted key size %d
                             The inputted password %s
                             The resulted key %s
                             """
                    , cipher, keySize, password, Arrays.toString(key.getEncoded()));
        }
    }

    public String getPassword(Scanner s) {
        System.out.println("Input desired password: ");
        String result = s.nextLine();
        if (result.equals("")) {
            result = s.nextLine();
        }
        return result;
    }
}
