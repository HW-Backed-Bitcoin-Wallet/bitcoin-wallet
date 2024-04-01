package de.schildbach.wallet.crypto;

import android.content.Context;

import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.crypto.KeyCrypterFactory;

public class KeyStoreKeyCrypterFactory implements KeyCrypterFactory {
    private Context context;

    public KeyStoreKeyCrypterFactory(Context context) {
        this.context = context;
    }

    @Override
    public KeyCrypter createKeyCrypter() {
        return new HWKeyCrypter(context);
    }
}
