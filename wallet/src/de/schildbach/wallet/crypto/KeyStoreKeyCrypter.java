
package de.schildbach.wallet.crypto;

import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.hardware.biometrics.BiometricPrompt;
import org.bitcoinj.wallet.Protos.ScryptParameters;

import org.bitcoinj.crypto.EncryptedData;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.utils.ContextPropagatingThreadFactory;
import org.bitcoinj.wallet.Protos;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import static de.schildbach.wallet.Constants.KEY_STORE_KEY_REF;
import static de.schildbach.wallet.Constants.KEY_STORE_PROVIDER;
import static de.schildbach.wallet.Constants.KEY_STORE_TRANSFORMATION;

import androidx.annotation.AnyThread;
import androidx.annotation.RequiresApi;
import androidx.fragment.app.FragmentActivity;

import com.google.protobuf.ByteString;

public class KeyStoreKeyCrypter extends KeyCrypterScrypt {

    private static final Logger log = LoggerFactory.getLogger(KeyStoreKeyCrypter.class);
    private static final int TAG_LENGTH = 128; // bits
    private static final int KEY_LENGTH = 256; // bits
    private static final int KEY_AUTHENTICATION_DURATION = 15; // seconds
    private final Context context;

    private CompletableFuture<EncryptedData> encryptionFuture;
    private CompletableFuture<byte[]> decryptionFuture;
    private byte[] currentPlainBytes;
    private EncryptedData currentEncryptedData;
    private final Protos.ScryptParameters scryptParameters;

    public KeyStoreKeyCrypter(Context context) {
        this.context = context;
        byte[] bytes = "KeyStoreKeyCrypter".getBytes();
        Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(
                ByteString.copyFrom(bytes));
        this.scryptParameters = scryptParametersBuilder.build();
    }

    /**
     * Generates a key in the android key store
     *
     * @return AesKey
     * @throws KeyCrypterException
     */
    @RequiresApi(api = Build.VERSION_CODES.R)
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
                                    .setKeySize(KEY_LENGTH)
                                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                    .setUserAuthenticationRequired(true)
                                    .setInvalidatedByBiometricEnrollment(true)
                                    .setUserAuthenticationParameters(5, KeyProperties.AUTH_BIOMETRIC_STRONG) // in case of multiple actions?
                                    .setIsStrongBoxBacked(true)
                                    .build();
                        } else {
                            keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_STORE_KEY_REF,
                                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                    .setKeySize(KEY_LENGTH)
                                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                    .setUserAuthenticationRequired(true)
                                    .setInvalidatedByBiometricEnrollment(true)
                                    .setUserAuthenticationParameters(5, KeyProperties.AUTH_BIOMETRIC_STRONG) // in case of multiple actions?
                                    .setIsStrongBoxBacked(false)
                                    .build();
                        }
                        log.info("Using SE: " + keyGenParameterSpec.isStrongBoxBacked());
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
        return new KeyParameter(new byte[0]);
    }

    /**
     * Decrypt bytes previously encrypted with this class.
     *
     * @param dataToDecrypt    IV and data to decrypt
     * @param unusedAesKey              Required only by the interface. The key doesn't actually get used.
     * @return                          The decrypted bytes
     * @throws                          KeyCrypterException if bytes could not be decrypted
     */
    @Override
    public byte[] decrypt(EncryptedData dataToDecrypt, KeyParameter unusedAesKey) throws KeyCrypterException {
        log.info("Starting KeyStoreKeyCrypter decrypt method");
        try {
            return doDecrypt(dataToDecrypt);
        } catch (UserNotAuthenticatedException e) {
            // User must authenticate so catch exception and continue
        }
        catch (Exception e) {
            log.info("Exception was" + e.getClass());
            throw new KeyCrypterException("Could not decrypt the encrypted data.", e);
        }

        // only reach code if user needs to authenticate
        decryptionFuture = new CompletableFuture<>();
        this.currentEncryptedData = dataToDecrypt;

        Thread test = Looper.getMainLooper().getThread();
        log.info("Crypter", "Dec main thread is: " + test.getName());



        // Move to the UI thread to call authenticate
        log.info("got right in front of decrypt new Handler call");
        new Handler(Looper.getMainLooper()).post(() -> {
            log.info("Is Main Thread: " + (Looper.myLooper() == Looper.getMainLooper()));
            try {
                createBiometricPrompt(false);
            } catch (Exception e) {
                decryptionFuture.completeExceptionally(new KeyCrypterException("Failed to initialize encryption", e));
            }
        });



        // Now wait for the future to complete
        try {
            return decryptionFuture.get(); // This will block, but since you're in a background thread, it's okay.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore the interrupted status
            throw new KeyCrypterException("Decryption was interrupted.", e);
        } catch (ExecutionException e) {
            throw new KeyCrypterException("Decryption failed.", e.getCause());
        }
    }

    public byte[] doDecrypt(EncryptedData dataToDecrypt) throws UserNotAuthenticatedException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_KEY_REF, null);
            Cipher cipher = Cipher.getInstance(KEY_STORE_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, dataToDecrypt.initialisationVector);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(dataToDecrypt.encryptedBytes);
        } catch (UserNotAuthenticatedException e) {
            throw new UserNotAuthenticatedException("User needs to authenticate");
        }
        catch (Exception e) {
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
        log.info("Starting KeyStoreKeyCrypter encrypt method");
        try {
            return doEncrypt(plainBytes);
        } catch (UserNotAuthenticatedException e) {
            // User must authenticate so catch exception and continue
        }
        catch (Exception e) {
            log.info("Exception was" + e.getClass());
            throw new KeyCrypterException("Could not encrypt bytes.", e);
        }

        // only reach code if user needs to authenticate
        encryptionFuture = new CompletableFuture<>();
        this.currentPlainBytes = plainBytes;

        // Move to the UI thread to call authenticate
        new Handler(Looper.getMainLooper()).post(() -> {
            log.info("Is Main Thread: " + (Looper.myLooper() == Looper.getMainLooper()));
            try {
                createBiometricPrompt(true);
            } catch (Exception e) {
                encryptionFuture.completeExceptionally(new KeyCrypterException("Failed to initialize encryption", e));
            }
        });


        // Now wait for the future to complete
        try {
            return encryptionFuture.get(); // This will block, but since you're in a background thread, it's okay.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore the interrupted status
            throw new KeyCrypterException("Encryption was interrupted.", e);
        } catch (ExecutionException e) {
            throw new KeyCrypterException("Encryption failed.", e.getCause());
        }
    }

    private EncryptedData doEncrypt(byte[] plainBytes) throws UserNotAuthenticatedException {
        Cipher cipher;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_KEY_REF, null);
            cipher = Cipher.getInstance(KEY_STORE_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedText = cipher.doFinal(plainBytes);
            return new EncryptedData(cipher.getIV(), encryptedText);
        } catch (UserNotAuthenticatedException e) {
            // User must authenticate
            throw new UserNotAuthenticatedException("User must authenticate");
        }
        catch (Exception e) {
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

    private CancellationSignal getCancellationSignal() {
        CancellationSignal cancellationSignal = new CancellationSignal();
        cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {
                log.info("Cancelled via signal");
            }
        });
        return cancellationSignal;
    }

    private void createBiometricPrompt(boolean isEncrypt) {
        Executor executor = Executors.newSingleThreadExecutor();
        BiometricPrompt.AuthenticationCallback callback = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            callback = new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    if (isEncrypt) {
                        encryptionFuture.completeExceptionally(new KeyCrypterException("Biometric authentication error: " + errString));
                    } else {
                        decryptionFuture.completeExceptionally(new KeyCrypterException("Biometric authentication error: " + errString));
                    }
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    if (isEncrypt) {
                        encryptionFuture.completeExceptionally(new KeyCrypterException("Biometric authentication failed."));
                    } else {
                        decryptionFuture.completeExceptionally(new KeyCrypterException("Biometric authentication failed."));
                    }
                }

                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    try {
                        if (isEncrypt) {
                            EncryptedData encryptedDataResult = doEncrypt(currentPlainBytes);
                            encryptionFuture.complete(encryptedDataResult);
                        } else {
                            byte[] decryptedData = doDecrypt(currentEncryptedData);
                            decryptionFuture.complete(decryptedData);
                        }
                    } catch (Exception e) {
                        if (isEncrypt) {
                            encryptionFuture.completeExceptionally(e);
                        } else {
                            decryptionFuture.completeExceptionally(e);
                        }
                    }
                }
            };
        }

        CancellationSignal cancellationSignal = new CancellationSignal();
        cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {
                log.info("Cancelled via signal");
            }
        });


        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            BiometricPrompt biometricPrompt = new BiometricPrompt.Builder(context)
                    .setTitle("Biometric Fingerprint Authentication")
                    .setSubtitle("Authentication is required to continue")
                    .setDescription("This app uses biometric authentication to protect your data.")
                    .setNegativeButton("Cancel", context.getMainExecutor(),
                            new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialogInterface, int i) {
                                    log.info("Authentication cancelled");
                                }
                            })
                    .build();
            biometricPrompt.authenticate(getCancellationSignal(), executor, callback);
        }
    }
}
