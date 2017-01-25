package com.fenchtose.securestore;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;


/**
 * Created by Jay Rambhia on 10/25/16.
 */

@TargetApi(Build.VERSION_CODES.M)
public class MarshmallowEncryptionStore extends BaseEncryptionStore {

    public MarshmallowEncryptionStore(Context context) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        super(context);
    }

    @Override
    protected AlgorithmParameterSpec initializeAlgoParamSpec(@NonNull Context context, @NonNull String alias,
                                                             @NonNull Date startDate, @NonNull Date endDate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeyValidityStart(startDate)
                .setKeyValidityEnd(endDate)
                .build();

        return spec;
    }

    @Override
    public String getAlgorithm() {
        return KeyProperties.KEY_ALGORITHM_RSA;
    }
}
