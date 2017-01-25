package com.fenchtose.securestore;

import android.os.Build;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;

import javax.crypto.NoSuchPaddingException;

/**
 * Created by Jay Rambhia on 10/25/16.
 */

public interface EncryptionStore {

    String PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore";
    String ENCRYPTION_ALGORITHM = Build.VERSION.SDK_INT < 23 ? "RSA" : KeyProperties.KEY_ALGORITHM_RSA;

    void initialize(@NonNull String alias) throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException;
    byte[] encrypt(@NonNull String data) throws IOException;
    String decrypt(byte[] data) throws IOException;

    String getAlgorithm();

}
