/**
 * *************************************************************************
 * Copyright (C) 2014 Ping Identity Corporation All rights reserved.
 *
 * The contents of this file are subject to the terms of the Ping Identity
 * Corporation SDK Developer Guide.
 *
 *************************************************************************
 */
package com.pingidentity.passwordcredentialvalidator.oauth;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Array;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500PrivateCredential;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.util.log.AttributeMap;

import org.jose4j.jws.JsonWebSignature;
import org.json.simple.*;
import org.json.simple.parser.*;

import com.pingidentity.access.KeyAccessor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.PasswordValidationException;
import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;

public class OAuthPasswordCredentialValidator implements PasswordCredentialValidator {
	
	// initialize logger into PF
    private final Log logger = LogFactory.getLog(this.getClass());
    
    // instantiate and obtain config object
    private OAuthPasswordCredentialValidatorConfiguration config = new OAuthPasswordCredentialValidatorConfiguration();

	/**
	 * Validates the given username and password in the manner appropriate to the plugin implementation.
	 * 
	 * @param username
	 *            the given username/id
	 * @param password
	 *            the given password
	 * @return An AttributeMap with at least one entry representing the principal. The key of the entry does not matter,
	 *         so long as the map is not empty. If the map is empty or null, the username and password combination is
	 *         considered invalid.
	 * @throws PasswordValidationException
	 *             runtime exception when the validator cannot process the username and password combination due to
	 *             system failure such as data source off line, host name unreachable, etc.
	 */
    @Override
    public AttributeMap processPasswordCredential(String username, String password) throws PasswordValidationException {
    	logger.debug("processPasswordCredential :: BEGIN");
    	
        AttributeMap attrs = null;
        logger.debug("processPasswordCredential :: username: " + username);

        try {
            if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            	
            	attrs = verifyAccessToken(username, password);
            	if (attrs != null) {
                    logger.debug("processPasswordCredential :: authentication successful");
                    logger.debug("-- returning " + attrs.size() + " attributes");
                    attrs.put("username", attrs.get(config.subjectAttribute));
                    
            	} else {
                    logger.debug("processPasswordCredential :: authentication failed");
            	}

            }
        } catch (PasswordCredentialValidatorAuthnException ex) {
            logger.debug("processPasswordCredential :: Exception is: " + ex + ", with message: " + ex.getMessageKey());
            throw new PasswordCredentialValidatorAuthnException(false, ex.getMessageKey());
        } catch (Exception ex) {
            logger.debug("Exception is " + ex);
            throw new PasswordValidationException("processPasswordCredential :: other error validating username/password", ex);
        }

        logger.debug("processPasswordCredential :: END");

       	return attrs;
    }

    private Boolean validateScope(JSONObject payload, String expectedScope) {
    	
    	if (expectedScope != null && expectedScope != "") {
			logger.debug("-- checking for scope (" + expectedScope + ")");
			Boolean scopePresent = false;
			
			if (payload.get("scope") != null) {
				ArrayList<String> payloadScopes = null;
				Object payloadScopesObj = payload.get("scope");

				if (payloadScopesObj instanceof JSONArray) {
					payloadScopes = (ArrayList<String>)payloadScopesObj;
				} else {
					payloadScopes = new ArrayList<String>();
					payloadScopes.add((String)payloadScopesObj);
				}
				
				for(String payloadScope : payloadScopes) {
					if (payloadScope.equalsIgnoreCase(config.expectedScope)) {
						scopePresent = true;
					}
				}
			}
			
			if (!scopePresent) {
				logger.debug("-- scope not present - FAILING AUTHENTICATION");
				return false;
			}
				
		} else {
			logger.debug("-- skipping scope validation");
		}
    	
    	return true;
    }
    
    private Boolean validateClientId(JSONObject payload, String expectedClientId) {

    	logger.debug("-- checking client_id (" + expectedClientId + ")");
        String tokenClientId = (String)payload.get("client_id");
		if (!tokenClientId.equalsIgnoreCase(expectedClientId)) {
			logger.debug("-- client_id nat valid - FAILING AUTHENTICATION");
			return false;
		}
		
		return true;
    }
    
    private Boolean validateSubject(JSONObject payload, String username) {

    	logger.debug("-- checking subject (" + config.subjectAttribute + ")");

		JSONObject accessTokenObject = null;

		if (payload.get("access_token") != null) {
    		accessTokenObject = (JSONObject)payload.get("access_token");
    	} else {
    		accessTokenObject = payload;
    	}

		if (accessTokenObject.get(config.subjectAttribute) != null) {
			String tokenSubject = (String)accessTokenObject.get(config.subjectAttribute);
			if (tokenSubject.equalsIgnoreCase(username)) {
				return true;
			} else {
				logger.debug("-- subject does not match - FAILING AUTHENTICATION");
				return false;
			}
		}
		
		return true;
    }
    
    private AttributeMap retrieveAttributes(JSONObject payload) {

    	AttributeMap returnAttributes = new AttributeMap();
    	JSONObject accessTokenObject;
    	
    	logger.debug("-- retrieving attributes");

    	if (payload.get("access_token") != null) {
    		accessTokenObject = (JSONObject)payload.get("access_token");
    	} else {
    		accessTokenObject = payload;
    	}

        for(Object id : accessTokenObject.keySet()) {
        	if (id != null) {
            	logger.debug("-- adding attribute: " + id);
        		Object value = accessTokenObject.get(id);
        		logger.debug("-- value of type " + value.getClass().getName());
        		if (value instanceof JSONArray) {
        			returnAttributes.put(id.toString(), StringUtils.join(((JSONArray) value).toArray(), ","));
        		} else if (value instanceof Long) {
        			returnAttributes.put(id.toString(), Long.toString((Long)value));
        		} else {
            		logger.debug("-- handling other attribute type " + value.getClass().getName());
        			returnAttributes.put(id.toString(), (String)value);
        		}
        	}
        }
		
		return returnAttributes;
    }
        
    private AttributeMap validateAtAS(String username, String access_token) throws Exception {
    	
		AttributeMap returnAttributeMap = null;

		URL tokenEndpoint = new URL(config.tokenEndpoint);
		URLConnection urlConnection = tokenEndpoint.openConnection();

		// Create Authorization header
		String rsCredentials = config.rsClientId + ":" + config.rsClientSecret;
		byte[] authzBytes = rsCredentials.getBytes();
		String authzHeader = "BASIC " + Base64.encodeBase64String(authzBytes);
		urlConnection.addRequestProperty("Authorization", authzHeader);

		String validateRequest = "grant_type=urn:pingidentity.com:oauth2:grant_type:validate_bearer&token=" + access_token;

		logger.debug("-- Sending Request...");

		urlConnection.setDoOutput(true);
		OutputStreamWriter outputStreamWriter = new OutputStreamWriter(urlConnection.getOutputStream(), "UTF-8");
		outputStreamWriter.write(validateRequest);
		outputStreamWriter.flush();
		outputStreamWriter.close();

		if (urlConnection instanceof HttpURLConnection) {
			HttpURLConnection httpConnection = (HttpURLConnection) urlConnection;
			int responseCode = httpConnection.getResponseCode();

			logger.debug("-- Got HTTP Response code: " + responseCode);

			if (responseCode == 200) {
				logger.debug("-- Token validated at AS");
				
				// validate the client_id, scope and subject
			    String encoding = urlConnection.getContentEncoding();
			    InputStream is = urlConnection.getInputStream();
			    InputStreamReader streamReader = new InputStreamReader(is, encoding != null ? encoding : "UTF-8");
			    JSONObject responseBody = (JSONObject)new JSONParser().parse(streamReader);
				
				httpConnection.disconnect();

				if (!validateClientId(responseBody, config.expectedClientId)) {
					return null;
				}
				
				if (!validateScope(responseBody, config.expectedScope)) {
					return null;
				}

				if (!validateSubject(responseBody, username)) {
					return null;
				}
				
				returnAttributeMap = retrieveAttributes(responseBody);
				
			} else {
				logger.debug("-- Token failed validation at AS (" + httpConnection.getResponseMessage() + ")");
				httpConnection.disconnect();

			}
		} else {
			throw new Exception("Not a HTTP connection");
		}
		
		return returnAttributeMap;
    }
    
	private AttributeMap validateLocally(String username, String access_token) throws Exception {

		AttributeMap returnAttributeMap = null;
		
	    JsonWebSignature jws = new JsonWebSignature();
	    jws.setCompactSerialization(access_token);
	    
		logger.debug("-- validating signature...");

		if (config.sharedSecret != null && !config.sharedSecret.isEmpty()) {
			logger.debug("-- using shared secret");
			// using symmetric key
			SecretKeySpec signingKey = new SecretKeySpec(config.sharedSecret.getBytes(), 0, config.sharedSecret.getBytes().length, "DES");
			jws.setKey(signingKey);
			
		} else {
		    // Symmetric or Asymmetric
		    KeyAccessor pfKeys = new KeyAccessor();
		    logger.debug("-- using cert alias " + config.signingCertAlias);
		    X500PrivateCredential signingCert = pfKeys.getDsigKeypair(config.signingCertAlias);
		    if (signingCert == null) {
		    	logger.debug("-- cert null");
		    }
		    X509Certificate publicKey = signingCert.getCertificate();
		    logger.debug("-- cert serial == " + publicKey.getSerialNumber());
		    
		    jws.setKey(publicKey.getPublicKey());
		}
		
	    if (jws.verifySignature()) {
			logger.debug("-- signature verified");
		    JSONObject payload = (JSONObject)new JSONParser().parse(jws.getPayload());

			if (!validateClientId(payload, config.expectedClientId)) {
				return null;
			}
			
			if (!validateScope(payload, config.expectedScope)) {
				return null;
			}

			if (!validateSubject(payload, username)) {
				return null;
			}

			returnAttributeMap = retrieveAttributes(payload);

	    } else {
			logger.debug("-- invalid signature - FAILING AUTHENTICATION");

	    }
	    
        logger.debug("-- about to return " + returnAttributeMap.size() + " attributes");
	    return returnAttributeMap;
	}
	
	private AttributeMap verifyAccessToken(String username, String access_token) throws Exception {

		AttributeMap returnAttributeMap = null;
		
		logger.debug("---[ Validating Access Token ]------");
		logger.debug(" Username : " + username);
		
		if (config.validationMethod.equals(config.validationMethod_UseAS)) {
			returnAttributeMap = validateAtAS(username, access_token);
		} else {
			returnAttributeMap = validateLocally(username, access_token);
		}
		
        logger.debug("-- about to return " + returnAttributeMap.size() + " attributes");
		
		return returnAttributeMap;
	}
    
	/**
	 * The getSourceDescriptor method returns the configuration details.
	 */
	@Override
	public PluginDescriptor getPluginDescriptor() {
		return config.getPluginDescriptor(this);
	}

	/**
	 * The configure method sets the configuration details.
	 */
	@Override
	public void configure(Configuration configuration) {
		config.configure(configuration);
	}    
}