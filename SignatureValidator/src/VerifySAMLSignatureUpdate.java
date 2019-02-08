
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;



public class VerifySAMLSignatureUpdate {

	private static final String X509 = "X509";
	private static String SIGNING_CERT = "C://Users//prasadt//Desktop//Test//SAML//AVIXA//avixa.cer";
	Logger logger = LoggerFactory.getLogger(VerifySAMLSignatureUpdate.class);
	
	public static void main(String args[]) {
		try {

			
			System.out.println("Starting signature verifyier");
			//String contents = readFile("C://CSIWorkspace//SignatureValidator//src//fail.txt");
			String contents = readFile("C://CSIWorkspace//SignatureValidator//src//NotSigned.txt");
			//String contents = readFile("C://CSIWorkspace//SignatureValidator//src//SAMLAsssertion.txt");

			VerifySAMLSignatureUpdate ieee = new VerifySAMLSignatureUpdate();
			Signature signature = ieee.getSignature(ieee.decodeResponse(contents));
			//Signature signature = ieee.getSignature(contents);
			
			if(ieee.validateSignature(signature)){
				System.out.println("Signature is valid.");
			}else{
				System.out.println("Signature is NOT valid.");
			}
			
		} catch (Exception e) {
			System.out.println("Exception :"+ ExceptionUtils.getStackTrace(e));
		} finally {
			System.exit(0);
		}

	}




	public static String readFile(String file) throws IOException {
		return new String(Files.readAllBytes(Paths.get(file)));
	
	}

	private String decodeResponse(String encodedResponseXmlString) {

			byte[] base64DecodedByteArray = Base64.decode(encodedResponseXmlString);
			if (base64DecodedByteArray == null) {
				logger.error("Unable to Base64 decode incoming message");
			}

			InputStream is = new ByteArrayInputStream(base64DecodedByteArray);
			String samlXmlString = getStringFromInputStream(is);

			logger.debug("Decoded SAML xml: " + samlXmlString);

			return samlXmlString;
		
	}

	/**
	 * convert InputStream to String
	 * 
	 * @param is
	 * @return
	 */
	private static String getStringFromInputStream(InputStream is) {

		BufferedReader br = null;
		StringBuilder sb = new StringBuilder();

		String line;
		try {

			br = new BufferedReader(new InputStreamReader(is));
			while ((line = br.readLine()) != null) {
				sb.append(line);
			}

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return sb.toString();
	}

	public Signature getSignature(String xmlString) throws ParserConfigurationException, SAXException, IOException, UnmarshallingException {
		Document doc = null;
		Response response = null;
		Assertion assertion = null;
		Signature signatureToValidate = null;

		try {
			doc = createDomDoc(xmlString);
		} catch (ParserConfigurationException pce) {
			logger.error("Unable to parse configuration ");
			throw pce;
		} catch (SAXException saxe) {
			logger.error("SAXException: ");
			throw saxe;
		} catch (IOException ioe) {
			logger.error("IOException: ");
			throw ioe;
		}

		if (doc != null) {

			try {
				DefaultBootstrap.bootstrap();
			} catch (Exception e1) {
				e1.printStackTrace();
			}
			Element metadataRoot = doc.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
			
			response = (Response) unmarshaller.unmarshall(metadataRoot);
			assertion = response.getAssertions().get(0);

			// get the signature to validate from the Response object
			signatureToValidate = assertion.getSignature();

			if (null == signatureToValidate) {
				signatureToValidate = response.getSignature();
			}
		}
		return signatureToValidate;
	}

	private boolean validateSignature(Signature signature) throws ValidationException, FileNotFoundException, CertificateException {
		
		boolean flag = true;
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(signature);
		} catch (ValidationException e) {
			/* Indicates signature did not conform to SAML Signature profile */
			logger.error("profileValidator Exception: ");
			flag = false;
			throw e;
		}

		Credential verificationCredential = getVerificationCredential();
		SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
		try {
			sigValidator.validate(signature);
		} catch (ValidationException e) {
			logger.error("Exception in Signature Validator : ");
			flag = false;
			throw e;
		}		
		return flag;
	}

	private Credential getVerificationCredential() throws FileNotFoundException, CertificateException {
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(SIGNING_CERT));
		CertificateFactory cf = CertificateFactory.getInstance(X509);
		X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
		BasicX509Credential x509Credential = new BasicX509Credential();
		x509Credential.setPublicKey(cert.getPublicKey());
		x509Credential.setEntityCertificate(cert);
		Credential credential = x509Credential;
		return credential;
	}

	private Document createDomDoc(String xmlString) throws ParserConfigurationException, SAXException, IOException {

		DocumentBuilderFactory db = DocumentBuilderFactory.newInstance();
		db.setNamespaceAware(true);
		DocumentBuilder dbf = db.newDocumentBuilder();

		InputSource is = new InputSource();
		is.setCharacterStream(new StringReader(xmlString));

		Document document = dbf.parse(is);

		return document;
	}

}
