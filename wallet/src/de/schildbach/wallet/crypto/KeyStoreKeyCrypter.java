package de.schildbach.wallet.crypto;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.google.protobuf.ByteString;

import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.EncryptedData;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.protobuf.wallet.Protos.ScryptParameters;
import org.bitcoinj.protobuf.wallet.Protos.Wallet.EncryptionType;
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
import javax.crypto.spec.IvParameterSpec;

import static de.schildbach.wallet.Constants.KEY_STORE_KEY_REF;
import static de.schildbach.wallet.Constants.KEY_STORE_PROVIDER;

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
    public AesKey deriveKey(CharSequence unusedPassword) throws KeyCrypterException {
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
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P
                            && context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                        keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_STORE_KEY_REF,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setIsStrongBoxBacked(true)
                                .build();
                        log.info("Using SE: " + keyGenParameterSpec.isStrongBoxBacked());
                    } else {
                        keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_STORE_KEY_REF,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .build();
                        log.info("Using SE: false, but using Android Key Store");
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
        return new AesKey(new byte[BLOCK_LENGTH]);
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
    public byte[] decrypt(EncryptedData encryptedBytesToDecode, AesKey unusedAesKey) throws KeyCrypterException {
        log.info("Starting HWKeyCrypter decrypt method");
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_KEY_REF, null);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
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
    public EncryptedData encrypt(byte[] plainBytes, AesKey unusedAesKey) throws KeyCrypterException {
        log.info("Starting HWKeyCrypter encrypt method");
        Cipher cipher;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_KEY_REF, null);
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
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
