package org.mhcheng.demo.encryption;

import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class EncryptionUtilSpringImpl implements EncryptionUtil {

	public String encrypt(String planText, String salt, String password) throws Exception {

		TextEncryptor encryptor = Encryptors.text(password, salt);
		return encryptor.encrypt(planText);

	}

	public String decrypt(String cipher, String salt, String password) throws Exception {
	
		TextEncryptor encryptor = Encryptors.text(password, salt);
		return encryptor.decrypt(cipher);

	}

}
