package com.fenchtose.securestore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Set;

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

		TextView textView = (TextView) findViewById(R.id.textview);

        String data = "Time is " + new Date();
		SharedPreferences preferences = getSharedPreferences("encrypted", Context.MODE_PRIVATE);

        try {
            BaseEncryptionStore encryptionStore;

            if (Build.VERSION.SDK_INT < 23) {
                encryptionStore = new LegacyEncryptionStore(this.getApplicationContext());
            } else {
                encryptionStore = new MarshmallowEncryptionStore(this.getApplicationContext());
            }

            encryptionStore.initialize("Test1");
			String encrypted = preferences.getString("encrypted", null);
			if (encrypted != null) {
				String decrypted = encryptionStore.decrypt(encrypted);
				Log.d(TAG, "Decrypted data: " + decrypted);
				textView.setText(decrypted);
			} else {
				Log.e(TAG, "no encrypted data available");
				textView.setText("No encrypted data available");
			}

			encrypted = encryptionStore.encrypt(data);
			SharedPreferences.Editor editor = preferences.edit();
			editor.putString("encrypted", encrypted);
			editor.apply();

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

    private void listProviders() {
		Provider[] providers = Security.getProviders();
		for (Provider p : providers) {
			Log.d(TAG, "provider: " + p.getName());
			Set<Provider.Service> services = p.getServices();
			for (Provider.Service s : services) {
				Log.d(TAG, "--> algorithm: " + s.getAlgorithm());
			}
		}
	}

}
