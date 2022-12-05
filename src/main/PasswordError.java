package main;

public class PasswordError extends RuntimeException {
    private static final String MESSAGE = """
            This password is a secret and must be protected. The password guidelines must be followed,
            such as a minimum length of 8 characters, the use of special characters,
            the combination of uppercase and lowercase letters, digits, and so on.
            """;
    private static final int CODE = 400;

    public PasswordError() {
        super(MESSAGE + CODE);
    }
}
