package de.schildbach.wallet.crypto;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.google.protobuf.ByteString;

import org.bitcoinj.crypto.EncryptedData;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import static de.schildbach.wallet.Constants.KEY_STORE_KEY_REF;
import static de.schildbach.wallet.Constants.KEY_STORE_PROVIDER;
import static de.schildbach.wallet.Constants.KEY_STORE_TRANSFORMATION;

public class KeyStoreKeyCrypter extends KeyCrypterScrypt {

    private static final Logger log = LoggerFactory.getLogger(KeyStoreKeyCrypter.class);

    public static final int BLOCK_LENGTH = 16;  // = 128 bits.

    private final Context context;

    public KeyStoreKeyCrypter(Context context) {
        this.context = context;
    }

    /**
     * Generates a key in the android key store
     *
     * @return AesKey
     * @throws KeyCrypterException
     */
    @Override
    public KeyParameter deriveKey(CharSequence unusedPassword) throws KeyCrypterException {
        KeyStore keyStore;
        try {
            log.info("Available KeyStore providers: {}", Arrays.toString(Security.getProviders()));
            keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            if (!keyStore.containsAlias(KEY_STORE_KEY_REF)) {
                KeyGenerator keyGenerator;
                try {
                    keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE_PROVIDER);
                    KeyGenParameterSpec keyGenParameterSpec;
                    // If else block to indicate a preference to use the embedded Secure Element over other hardware security modules like e.g. the TEE
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                            keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_STORE_KEY_REF,
                                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                    .setKeySize(256)
                                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                    .setUserAuthenticationRequired(true)
                                    .setInvalidatedByBiometricEnrollment(true)
                                    .setUserConfirmationRequired(true)
                                    .setIsStrongBoxBacked(true)
                                    .build();
                            log.info("Using SE: " + keyGenParameterSpec.isStrongBoxBacked());
                        } else {
                            keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_STORE_KEY_REF,
                                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                    .setKeySize(256)
                                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                    .setUserAuthenticationRequired(true)
                                    .setInvalidatedByBiometricEnrollment(true)
                                    .setUserConfirmationRequired(true)
                                    .setIsStrongBoxBacked(false)
                                    .build();
                            log.info("Using SE: false, but using Android Key Store");
                        }
                    } else {
                        log.info("Android version 28 or higher is required for KeyStore encryption");
                        throw new KeyCrypterException("Android version 28 or higher is required for KeyStore encryption");
                    }
                    keyGenerator.init(keyGenParameterSpec);
                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
                    log.info("Exception was " + e.getClass());
                    throw new KeyCrypterException("Exception: ", e);
                }

                keyGenerator.generateKey();
            }
        } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException e) {
            throw new RuntimeException(e);
        }

        // Unused return
        return new KeyParameter(new byte[BLOCK_LENGTH]);
    }

    /**
     * Decrypt bytes previously encrypted with this class.
     *
     * @param encryptedBytesToDecode    IV and data to decrypt
     * @param unusedAesKey              Required only by the interface. The key doesn't actually get used.
     * @return                          The decrypted bytes
     * @throws                          KeyCrypterException if bytes could not be decrypted
     */
    @Override
    public byte[] decrypt(EncryptedData encryptedBytesToDecode, KeyParameter unusedAesKey) throws KeyCrypterException {
        log.info("Starting HWKeyCrypter decrypt method");
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_KEY_REF, null);
            Cipher cipher = Cipher.getInstance(KEY_STORE_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(128,encryptedBytesToDecode.initialisationVector);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(encryptedBytesToDecode.encryptedBytes);
        } catch (Exception e) {
            log.info("Exception was " + e.getClass());
            throw new KeyCrypterException("Could not encrypt bytes.", e);
        }
    }

    /**
     * Encrypts data with an AES key stored in the Android key store
     *
     * @param plainBytes    data to be encrypted
     * @param unusedAesKey  Required only by the interface. The key doesn't actually get used.
     * @return              IV and encrypted data in an EncryptedData object
     * @throws              KeyCrypterException if bytes could not be decrypted
     */
    @Override
    public EncryptedData encrypt(byte[] plainBytes, KeyParameter unusedAesKey) throws KeyCrypterException {
        log.info("Starting HWKeyCrypter encrypt method");
        Cipher cipher;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_KEY_REF, null);
            cipher = Cipher.getInstance(KEY_STORE_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedText = cipher.doFinal(plainBytes);
            return new EncryptedData(cipher.getIV(), encryptedText);
        } catch (Exception e) {
            log.info("Exception was" + e.getClass());
            throw new KeyCrypterException("Could not encrypt bytes.", e);
        }
    }

    /**
     * Return the EncryptionType enum value which denotes the type of encryption/ decryption that this KeyCrypter
     * can understand.
     * For the Bitcoinj KeyCrypter interface only the Enum values of ENCRYPTED_SCRYPT_AES and UNENCRYPTED are supported.
     * As none match fully, we need to make due with what we got. We can take the ENCRYPTED_SCRYPT_AES enum even though
     * we don't use a passphrase based KDF of scrypt, as we are using the secure element of the Android device.
     */
    @Override
    public EncryptionType getUnderstoodEncryptionType() {
        return EncryptionType.ENCRYPTED_SCRYPT_AES;
    }
}