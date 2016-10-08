package org.mhcheng.demo.encryption;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.mhcheng.demo.encryption.EncryptionUtil;
import org.mhcheng.demo.encryption.EncryptionUtilJdkImpl;
import org.mhcheng.demo.encryption.EncryptionUtilSpringImpl;

public class EncryptionUtilJdkImplTest {

	@Test
	public void decrypt_ShouldDecryptFromEncryptResult() throws Exception {
		
		String salt = "3b9297373e79778e";
		String password = "HelloWorld";
		String plainText = "This is a test message";
		
		EncryptionUtil util = new EncryptionUtilJdkImpl();
		
		String cipherText = util.encrypt(plainText, salt, password);
		String decryptedText = util.decrypt(cipherText, salt, password);
		
		assertThat(decryptedText, equalTo(plainText));
		
	}

	@Test
	public void encrypt_ShouldDecryptBySpringImpl() throws Exception {
		
		String salt = "3b9297373e79778e";
		String password = "HelloWorld";
		String plainText = "This is a test message";
		
		EncryptionUtil jdkImpl = new EncryptionUtilJdkImpl();
		EncryptionUtil springImpl = new EncryptionUtilSpringImpl();
		
		String cipherText = jdkImpl.encrypt(plainText, salt, password);
		String decryptedText = springImpl.decrypt(cipherText, salt, password);
		
		assertThat(decryptedText, equalTo(plainText));
		
	}

}
