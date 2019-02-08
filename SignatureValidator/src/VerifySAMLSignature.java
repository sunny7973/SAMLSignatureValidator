
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;



public class VerifySAMLSignature {

	public static void main(String args[]) {
		try {

			System.out.println("Starting signature verifyer");
			String contents = readFile("C://CSIWorkspace//SignatureValidator//src//fail.txt");
			//String contents = readFile("C://CSIWorkspace//SignatureValidator//src//base64Response.txt");
			//String contents = readFile("C://CSIWorkspace//SignatureValidator//src//SAMLAsssertion.txt");

			VerifySAMLSignature ieee = new VerifySAMLSignature();
			Signature signature = ieee.getSignature(decodeResponse(contents));
			//Signature signature = ieee.getSignature(contents);
			
			if(ieee.validateSignature(signature)){
				System.out.println("Signature is valid.");
			}else{
				System.out.println("Signature is NOT valid.");
			}
			
		} catch (Exception e) {
			System.out.println("Exception Validating Signature " + e);
		} finally {
			System.exit(0);
		}

	}

	private static String SIGNING_CERT = "C://Users//prasadt//Desktop//Test//SAML//AVIXA//avixa.cer";
	Response response = null;
	Assertion assertion = null;


	public static String readFile(String file) throws IOException {
		return new String(Files.readAllBytes(Paths.get(file)));
	
	}

	private static String decodeResponse(String encodedResponseXmlString) throws SAXException {

		try {
			byte[] base64DecodedByteArray = Base64.decode(encodedResponseXmlString);
			if (base64DecodedByteArray == null) {
				System.out.println("Unable to Base64 decode incoming message");
			}

			InputStream is = new ByteArrayInputStream(base64DecodedByteArray);
			String samlXmlString = getStringFromInputStream(is);

			System.out.println("Decoded SAML xml: " + samlXmlString);

			return samlXmlString;
		} catch (Exception mde) {
			System.out.println("Unable to Base64 decode incoming message" + mde);
		}

		return null;
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

	public Signature getSignature(String xmlString) {
		Document doc = null;
		Signature signatureToValidate = null;

		try {
			doc = createDomDoc(xmlString);
		} catch (ParserConfigurationException pce) {
			System.out.println("Unable to parse configuration " + pce);
		} catch (SAXException saxe) {
			System.out.println("SAXException: " + saxe);
		} catch (IOException ioe) {
			System.out.println("IOException: " + ioe);
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
			try {
				response = (Response) unmarshaller.unmarshall(metadataRoot);
			} catch (Exception e1) {
				e1.printStackTrace();
			}

			assertion = response.getAssertions().get(0);
			System.out.println("Value of assertion: " + assertion);

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
			System.out.println("profileValidator Exception: ");
			flag = false;
			throw e;
		}

		Credential verificationCredential = getVerificationCredential();
		SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
		try {
			sigValidator.validate(signature);
		} catch (ValidationException e) {
			System.out.println("Exception in Signature Validator : ");
			flag = false;
			throw e;
		}		
		return flag;
	}

	private Credential getVerificationCredential() throws FileNotFoundException, CertificateException {
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(SIGNING_CERT));
		CertificateFactory cf = CertificateFactory.getInstance("X509");
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

	public List<Attribute> getSAMLAttributes(Assertion assertion) {
		List<Attribute> attributes = new ArrayList<Attribute>();
		if (assertion != null) {
			for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
				for (Attribute attribute : attributeStatement.getAttributes()) {
					attributes.add(attribute);
				}
			}
		}
		return attributes;
	}

	public Map<String, String> getAttributesMap(List<Attribute> attributes) {
		Map<String, String> result = new HashMap<String, String>();
		for (Attribute attribute : attributes) {
			result.put(attribute.getName(), attribute.getDOM().getTextContent());
		}
		return result;
	}
}
