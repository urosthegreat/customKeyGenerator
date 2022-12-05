package main;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

/**
 * CustomKeyGenerator se koristi za generisanje 4 tipa bezbednih ključeva,
 * od najnižeg do najbezbednijeg metoda.
 */
public class CustomKeyGenerator {
    private static final String REGEX_EXPRESSION = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
    private static final String PBKDF2_WITH_HMAC_SHA256 = "PBKDF2WithHmacSHA256";
    private static final Random random = new Random();
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Java Random klasa je generator pseudo-slučajnih brojeva (PRNG),
     * takođe poznat kao Deterministički generator slučajnih brojeva (DRNG).
     * To znači da nije zaista slučajno.
     * Redosled nasumičnih brojeva u PRNG može se u potpunosti odrediti na osnovu njegovog seed-a.
     * Java ne preporučuje korišćenje Random-a za kriptografske aplikacije.
     * <p>
     * Uz to rečeno, NIKADA ne koristite Random za generisanje ključeva.
     *
     * @param cipher  {@link String}
     * @param keySize {@link Integer}
     * @return {@link Key}
     */
    protected Key getRandomKey(String cipher, int keySize) {
        byte[] randomKeyBytes = new byte[keySize / 8];
        random.nextBytes(randomKeyBytes);
        return new SecretKeySpec(randomKeyBytes, cipher);
    }

    /**
     * Instanciramo niz bajtova željene veličine ključa.
     * Sada, umesto da koristimo Random, koristimo SecureRandom da generišemo nasumične bajtove za naš niz bajtova.
     * Java preporučuje SecureRandom za generisanje slučajnog broja za kriptografske aplikacije.
     * Minimalno je u skladu sa FIPS 140-2, bezbednosnim zahtevima za kriptografske module.
     * <p>
     * Jasno je da je u Javi SecureRandom de-fakto standard za dobijanje nasumice.
     *
     * @param cipher  {@link String}
     * @param keySize {@link Integer}
     * @return {@link Key}
     */
    protected Key getSecureRandomKey(String cipher, int keySize) {
        byte[] secureRandomKeyBytes = new byte[keySize / 8];
        secureRandom.nextBytes(secureRandomKeyBytes);
        return new SecretKeySpec(secureRandomKeyBytes, cipher);
    }

    /**
     * Instanciramo klasu KeyGenerator gde prosledjujemo odgovarajući šifrat.
     * Nakon toga, inicijalizujemo generator ključa sa odgovarajućom dužinom ključa.
     * <p>
     * Dakle, kako se razlikuje od Random i SecureRandom pristupa?
     * Postoje dve ključne razlike koje vredi istaći.
     * <p>
     * Kao prvo, ni Random ni SecureRandom pristup
     * ne može da kaže da li generišemo ključeve prave veličine prema specifikaciji šifre.
     * Tek kada idemo na šifrovanje, naići ćemo na izuzetke ako su ključevi nepodržane veličine.
     * Korišćenje SecureRandom-a sa nevažećim keySize-om dovodi do izuzetka kada inicijalizujemo šifru za šifrovanje.
     * Korišćenje KeyGenerator, s druge strane, ne uspeva tokom samog generisanja ključa,
     * omogućavajući nam da to bolje postupamo.
     *
     * @param cipher  {@link String}
     * @param keySize {@link Integer}
     * @return {@link Key}
     */
    protected static Key getKeyFromKeyGenerator(String cipher, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(cipher);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public Key getKeyFromKG(String cipher, int keySize) {
        try {
            return getKeyFromKeyGenerator(cipher, keySize);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generisali smo ključeve iz nasumičnih nizova bajtova koji nisu prilagođeni ljudima.
     * Ključ zasnovan na lozinki (Password-Based Key - PBK) nam nudi mogućnost da generišemo tajni ključ
     * na osnovu lozinke koja se može pročitati.
     * <p>
     * Lozinka prilagođena korisniku nema dovoljno entropije.
     * Zbog toga dodajemo dodatne nasumično generisane bajtove zvane sol(salt) da bismo otežali pogađanje.
     * Minimalna dužina soli treba da bude 128 bita. Koristili smo SecureRandom da generišemo našu so.
     * Sol nije tajna i čuva se kao otvoreni tekst.
     * Trebalo bi da generišemo so u parovima sa svakom lozinkom i ne koristimo istu so globalno.
     * Ovo će zaštititi od napada Rainbow Table,
     * koje koriste pretrage iz unapred izračunate heš tabele za razbijanje lozinki.
     * </p>
     * <p>
     * Broj iteracija je koliko puta algoritam generisanja tajne primenjuje funkciju transformacije.
     * Trebalo bi da bude što je moguće veće. Minimalni preporučeni broj ponavljanja je 1.000.
     * Veći broj ponavljanja povećava složenost napadača tokom izvođenja
     * bruteforce provera za sve moguće lozinke.
     * Veličina ključa je ista o kojoj smo ranije govorili, a može biti 128, 192 ili 256 za AES.
     * Sva četiri elementa o kojima smo gore govorili smo umotali u PBEKeySpec objekat.
     * Zatim, koristeći SecretKeyFactory, dobijamo instancu PBKDF2WithHmacSHA256 algoritma za generisanje ključa.
     * Konačno, pozivanjem generateSecret sa PBEKeySpec, generišemo SecretKey na osnovu lozinke čitljive ljudima.
     * </p>
     *
     * @param cipher   {@link String}
     * @param keySize  {@link Integer}
     * @param password {@link Character}
     * @return {@link Key}
     */
    public Key getPasswordBasedKey(String cipher, int keySize, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[100];
        secureRandom.nextBytes(salt);
        if (isValidPassword(password)) {
            throw new PasswordError();
        }
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, keySize);
        SecretKey pbeKey = SecretKeyFactory.getInstance(PBKDF2_WITH_HMAC_SHA256).generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), cipher);
    }

    /**
     * Ova lozinka je tajna i mora biti zaštićena. Moraju se poštovati uputstva za lozinku,
     * kao što je minimalna dužina od 8 znakova, upotreba specijalnih znakova,
     * kombinacija velikih i malih slova, cifara i tako dalje.
     *
     * @param password {@link Character}
     * @return {@link Boolean}
     */
    private boolean isValidPassword(char[] password) {
        return password.length >= 8 && Arrays.toString(password).matches(REGEX_EXPRESSION);
    }
}
