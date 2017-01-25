package com.fenchtose.securestore;

import android.content.Context;
import android.support.annotation.NonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by Jay Rambhia on 10/25/16.
 */

public abstract class BaseEncryptionStore implements EncryptionStore {

    private KeyStore keyStore;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;

    private Context context;

    public BaseEncryptionStore(Context context) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        this.context = context;
        keyStore = KeyStore.getInstance(EncryptionStore.PROVIDER_ANDROID_KEY_STORE);
        keyStore.load(null);
    }

    @Override
    public void initialize(@NonNull String alias) throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
        if (keyStore == null) {
            throw new NullPointerException("keystore is null");
        }

        if (keyStore.containsAlias(alias)) {
            onGeneratorInitialized(alias);
            return;
        }

        Calendar startDate = Calendar.getInstance();
        Calendar expiryDate = Calendar.getInstance();
        expiryDate.add(Calendar.YEAR, 1);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(getAlgorithm(),
                EncryptionStore.PROVIDER_ANDROID_KEY_STORE);

        AlgorithmParameterSpec spec = initializeAlgoParamSpec(context, alias, startDate.getTime(), expiryDate.getTime());
        generator.initialize(spec);
        generator.generateKeyPair();
        onGeneratorInitialized(alias);
    }

    protected void onGeneratorInitialized(@NonNull String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchPaddingException {
        generateKeys(alias);
        initCiphers();
    }

    protected void generateKeys(@NonNull String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        privateKey = privateKeyEntry.getPrivateKey();
        publicKey = privateKeyEntry.getCertificate().getPublicKey();
    }

    protected void initCiphers() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        decryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    @Override
    public byte[] encrypt(@NonNull String data) throws IOException {
        if (encryptionCipher == null) {
            throw new NullPointerException("Encryption cipher is null");
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream(1024);
        CipherOutputStream cos = new CipherOutputStream(os, encryptionCipher);
        cos.write(data.getBytes("UTF-8"));
        cos.close();
        os.flush();
        os.close();

        return os.toByteArray();
    }

    @Override
    public String decrypt(byte[] data) throws IOException {
        if (decryptionCipher == null) {
            throw new NullPointerException("Decryption Cipher is null");
        }

        ByteArrayInputStream is = new ByteArrayInputStream(data);
        CipherInputStream cis = new CipherInputStream(is, decryptionCipher);

        int index = 0;
        int nextByte;
        byte[] decryptedBytes = new byte[1024];

        while ((nextByte = cis.read()) != -1) {
            decryptedBytes[index] = (byte)nextByte;
            index++;
        }

        cis.close();
        is.close();

        return new String(decryptedBytes, 0, index);
    }

    protected abstract AlgorithmParameterSpec initializeAlgoParamSpec(@NonNull Context context, @NonNull String alias,
                                                                      @NonNull Date startDate, @NonNull Date endDate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;
}
