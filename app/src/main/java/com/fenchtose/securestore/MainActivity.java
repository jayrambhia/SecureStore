package com.fenchtose.securestore;

import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        doDemo1();
    }

    private void doDemo1() {
        try {
            BaseEncryptionStore encryptionStore;

            if (Build.VERSION.SDK_INT < 23) {
                encryptionStore = new LegacyEncryptionStore(this.getApplicationContext());
            } else {
                encryptionStore = new MarshmallowEncryptionStore(this.getApplicationContext());
            }

            encryptionStore.initialize("Test");
            byte[] encrypted = encryptionStore.encrypt("Hello, World!-!");
            String decrypted = encryptionStore.decrypt(encrypted);
            Log.d(TAG, "Decrypted data: " + decrypted);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

}
