package com.nitrohub.ldap;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

public class LDAPClient {

	public static void main(String[] args) {
		authenticateUsingJavax();
	}

	private static void authenticateUsingApache() {
		try {
			LdapConnection connection = new LdapNetworkConnection( "localhost", 389 );
			String enPassword = encryptSHA("Vi$h2002");
			System.out.println("Encrypted password is " + enPassword);
			enPassword = encryptSSHA("Vi$h2002");
			System.out.println("Encrypted password is " + enPassword);
			connection.bind("cn=Gaurav Shinde,ou=People,dc=maxcrc,dc=com" ,enPassword);
			System.out.println("Authenticated");
			EntryCursor cursor = connection.search( "ou=People,dc=maxcrc,dc=com", "(objectclass=*)", SearchScope.ONELEVEL, "*" );
			while ( cursor.next() )
			{
				Entry entry = cursor.get();
				System.out.println(entry.toString());
			}
			connection.unBind();
			connection.close();
		} catch(Exception ex) {
			ex.printStackTrace();
		}
	}

	private static void authenticateUsingJavax() {
		try {
			Hashtable<String,String> env = new Hashtable<String,String>(11);
			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			env.put(Context.PROVIDER_URL, "ldap://localhost:389");
			env.put(Context.SECURITY_AUTHENTICATION, "simple");
			env.put(Context.SECURITY_PRINCIPAL,"cn=Gaurav Shinde,ou=People,dc=maxcrc,dc=com");
			env.put(Context.SECURITY_CREDENTIALS,"Vi$h2002");
			LdapContext ctx = new InitialLdapContext(env, null);
			ctx.setRequestControls(null);
			NamingEnumeration<?> namingEnum = ctx.search("ou=people,dc=maxcrc,dc=com", "(objectclass=*)", getSimpleSearchControls());
			while (namingEnum.hasMore ()) {
				SearchResult result = (SearchResult) namingEnum.next ();    
				Attributes attrs = result.getAttributes ();
				System.out.println(result.toString());

			} 
			namingEnum.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static SearchControls getSimpleSearchControls() {
	    SearchControls searchControls = new SearchControls();
	    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
	    searchControls.setTimeLimit(30000);
	    //String[] attrIDs = {"objectGUID"};
	    //searchControls.setReturningAttributes(attrIDs);
	    return searchControls;
	}
	
	private static String encryptSHA(final String plaintext) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
		try {
			md.update(plaintext.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
		byte raw[] = md.digest();
		String hash = Base64.encodeBase64String(raw);
		return hash;
	}
	private static final int SALT_LENGTH = 4;

	public static String encryptSSHA(String strPassword)
			throws NoSuchAlgorithmException {
		byte[] password = strPassword.getBytes();
		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = new byte[SALT_LENGTH];
		secureRandom.nextBytes(salt);

		MessageDigest crypt = MessageDigest.getInstance("SHA-1");
		crypt.reset();
		crypt.update(password);
		crypt.update(salt);
		byte[] hash = crypt.digest();

		byte[] hashPlusSalt = new byte[hash.length + salt.length];
		System.arraycopy(hash, 0, hashPlusSalt, 0, hash.length);
		System.arraycopy(salt, 0, hashPlusSalt, hash.length, salt.length);

		return new StringBuilder().append("{SSHA}")
				.append(Base64.encodeBase64String(hashPlusSalt))
				.toString();
	}
}
