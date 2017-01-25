package com.fenchtose.securestore;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.NonNull;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/**
 * Created by Jay Rambhia on 10/25/16.
 */

public class LegacyEncryptionStore extends BaseEncryptionStore {

    private static final String TAG = "LegacyEncryptionStore";

    public LegacyEncryptionStore(@NonNull Context context) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        super(context);
    }

    @SuppressWarnings({"WrongConstant", "deprecation"})
    @Override
    protected AlgorithmParameterSpec initializeAlgoParamSpec(@NonNull Context context, @NonNull String alias,
                                                         @NonNull Date startDate, @NonNull Date endDate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setKeyType(getAlgorithm())
                .setKeySize(2048)
                .setSubject(new X500Principal("CN=test"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(startDate)
                .setEndDate(endDate)
                .build();

        return spec;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }
}
