package com.pingidentity.passwordcredentialvalidator.oauth;

import java.util.HashSet;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.RadioGroupFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.gui.DsigKeypairFieldDescriptor;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;

public class OAuthPasswordCredentialValidatorConfiguration {

	// initialize configuration object
    protected Configuration configuration = null;
    
    private static final String PLUGIN_NAME = "OAuth Password Credential Validator";
    private static final String PLUGIN_DESC = "OAuth Password Credential Validator";

    private static final String OAUTH_TOKEN_ENDPOINT = "Token Endpoint";
    private static final String OAUTH_TOKEN_ENDPOINT_DESC = "The token endpoint on the OAuth AS.";
    private static final String RS_CLIENT_ID = "RS Client ID";
    private static final String RS_CLIENT_ID_DESC = "The client ID of the OAuth RS.";
    private static final String RS_CLIENT_SECRET = "RS Client Secret";
    private static final String RS_CLIENT_SECRET_DESC = "The client secret of the OAuth RS.";
    private static final String SUBJECT_ATTR = "Subject Attribute";
    private static final String SUBJECT_ATTR_DESC = "The attribute name containing the username to compare.";
    private static final String EXPECTED_CLIENT_ID = "OAuth Client ID";
    private static final String EXPECTED_CLIENT_ID_DESC = "Expected OAuth client id required to pass validation.";
    private static final String EXPECTED_SCOPE = "Required Scope";
    private static final String EXPECTED_SCOPE_DESC = "Scope value required to pass validation.";
    private static final String VALIDATION_METHOD = "Validation Method";
    private static final String VALIDATION_METHOD_DESC = "How to validate the access token (locally for JWT or against the AS).";
    private static final String SHARED_SECRET = "AT Shared Secret";
    private static final String SHARED_SECRET_DESC = "The shared secret used to sign the AT (symmetric key).";
    private static final String SIGNING_CERT = "AT Signing Secret";
    private static final String SIGNING_CERT_DESC = "The signing cert used to sign the AT (asymmetric key).";
    
    protected final String validationMethod_Locally = "Locally";
    protected final String validationMethod_UseAS = "Use AS";
    
    protected String tokenEndpoint = null;
    protected String rsClientId = null;
    protected String rsClientSecret = null;
    protected String subjectAttribute = null;
    protected String expectedClientId = null;
    protected String expectedScope = null;
    protected String validationMethod = null;
    protected String sharedSecret = null;
    protected String signingCertAlias = null;
    
	/**
	 * This method is called by the PingFederate server to push configuration values entered by the administrator via
	 * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
	 * should use the {@link Configuration} parameter to configure its own internal state as needed. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your plugin implementation this method will be
	 * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your plugin implementation instance until after
	 * creation and configuration is completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered by the user via the GUI.
	 */    
    public void configure(Configuration configuration) {
        this.tokenEndpoint = configuration.getFieldValue(OAUTH_TOKEN_ENDPOINT);
        this.rsClientId = configuration.getFieldValue(RS_CLIENT_ID);
        this.rsClientSecret = configuration.getFieldValue(RS_CLIENT_SECRET);
        this.subjectAttribute = configuration.getFieldValue(SUBJECT_ATTR);
        this.expectedClientId = configuration.getFieldValue(EXPECTED_CLIENT_ID);
        this.expectedScope = configuration.getFieldValue(EXPECTED_SCOPE);
        this.validationMethod = configuration.getFieldValue(VALIDATION_METHOD);
        this.sharedSecret = configuration.getFieldValue(SHARED_SECRET);
        this.signingCertAlias = configuration.getFieldValue(SIGNING_CERT);
    }

	/**
	 * Returns the {@link PluginDescriptor} that describes this plugin to the PingFederate server. This includes how
	 * PingFederate will render the plugin in the administrative console, and metadata on how PingFederate will treat
	 * this plugin at runtime.
	 * 
	 * @return A {@link PluginDescriptor} that describes this plugin to the PingFederate server.
	 */    
    public PluginDescriptor getPluginDescriptor(OAuthPasswordCredentialValidator opcv) {
    	RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();
    	
    	GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
		guiDescriptor.setDescription(PLUGIN_DESC);
		
        TextFieldDescriptor tokenEndpointDescriptor = new TextFieldDescriptor(OAUTH_TOKEN_ENDPOINT, OAUTH_TOKEN_ENDPOINT_DESC);
        tokenEndpointDescriptor.addValidator(requiredFieldValidator);
        tokenEndpointDescriptor.setDefaultValue("https://<pf_server>/as/token.oauth2");
        guiDescriptor.addField(tokenEndpointDescriptor);

        TextFieldDescriptor rsClientIdDescriptor = new TextFieldDescriptor(RS_CLIENT_ID, RS_CLIENT_ID_DESC);
        rsClientIdDescriptor.addValidator(requiredFieldValidator);
        rsClientIdDescriptor.setDefaultValue("oauth_pcv");
        guiDescriptor.addField(rsClientIdDescriptor);

        TextFieldDescriptor rsClientSecretDescriptor = new TextFieldDescriptor(RS_CLIENT_SECRET, RS_CLIENT_SECRET_DESC, true);
        guiDescriptor.addField(rsClientSecretDescriptor);

        String[] validationOptions = { this.validationMethod_Locally, this.validationMethod_UseAS };
        RadioGroupFieldDescriptor validationMethodDescriptor = new RadioGroupFieldDescriptor(VALIDATION_METHOD, VALIDATION_METHOD_DESC, validationOptions);
        validationMethodDescriptor.setDefaultValue(this.validationMethod_Locally);
        guiDescriptor.addField(validationMethodDescriptor);

        TextFieldDescriptor sharedSecretDescriptor = new TextFieldDescriptor(SHARED_SECRET, SHARED_SECRET_DESC, true);
        guiDescriptor.addField(sharedSecretDescriptor);
        
        DsigKeypairFieldDescriptor signingCertDescriptor = new DsigKeypairFieldDescriptor(SIGNING_CERT, SIGNING_CERT_DESC);
        guiDescriptor.addField(signingCertDescriptor);
        
        TextFieldDescriptor subjectAttributeDescriptor = new TextFieldDescriptor(SUBJECT_ATTR, SUBJECT_ATTR_DESC);
        subjectAttributeDescriptor.addValidator(requiredFieldValidator);
        subjectAttributeDescriptor.setDefaultValue("sub");
        guiDescriptor.addField(subjectAttributeDescriptor);

        TextFieldDescriptor expectedClientIdDescriptor = new TextFieldDescriptor(EXPECTED_CLIENT_ID, EXPECTED_CLIENT_ID_DESC);
        expectedClientIdDescriptor.addValidator(requiredFieldValidator);
        expectedClientIdDescriptor.setDefaultValue("activesync_client");
        guiDescriptor.addField(expectedClientIdDescriptor);

        TextFieldDescriptor jsonObjectDescriptor = new TextFieldDescriptor(EXPECTED_SCOPE, EXPECTED_SCOPE_DESC);
        guiDescriptor.addField(jsonObjectDescriptor);
        
        PluginDescriptor pluginDescriptor = new PluginDescriptor(PLUGIN_NAME, opcv, guiDescriptor);
		//pluginDescriptor.setAttributeContractSet(Collections.singleton(USERNAME));
        HashSet<String> attributes = new HashSet<String>();
        attributes.add("username");
        pluginDescriptor.setAttributeContractSet(attributes);
		pluginDescriptor.setSupportsExtendedContract(true);
    	
		return pluginDescriptor;
    }
    

	/**
	 * The buildName method returns the name and version from the information in META-INF/MANIFEST.MF, in order to name the jar within this package.
	 * 
	 * @return name of the plug-in
	 */
	private String buildName() {
		Package plugin = OAuthPasswordCredentialValidator.class.getPackage();
		String title = plugin.getImplementationTitle(); // Implementation-Title
		String version = plugin.getImplementationVersion(); // Implementation-Version:
		String name = title + " " + version;
		return name;
	}     
}