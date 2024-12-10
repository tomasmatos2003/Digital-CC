import pt.gov.cartaodecidadao.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Iterator;

import java.lang.reflect.Method;
import java.security.cert.CertificateException;  // Import the CertificateException class

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class CcData {
    static {
        try {
            System.loadLibrary("pteidlibj");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load. \n" + e);
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        try {
            PTEID_ReaderSet.initSDK();

            PTEID_ReaderContext reader = PTEID_ReaderSet.instance().getReader();

            if (reader.isCardPresent()) {
                try {
                    // Get card details
                    PTEID_EIDCard card = reader.getEIDCard();
                    PTEID_EId eid = card.getID();
                    
                    PTEID_Certificates certs = card.getCertificates();
                   

                    for (long i = 0; i < certs.countAll(); i++) {
                        // Get the cert object (ensure the correct type, here we assume it provides getCert())
                        PTEID_Certificate cert = certs.getCert(i); // Retrieve certificate at index i (check method signature)
                        byte[] certBytes = cert.getCertData().GetBytes();
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        InputStream certInputStream = new ByteArrayInputStream(certBytes);
                        Certificate certificate = factory.generateCertificate(certInputStream);

                        // Extract the public key from the certificate
                        PublicKey publicKey = certificate.getPublicKey();
                        
                        String pemKey = exportToPEM(publicKey);
                        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                        BigInteger modulus = rsaPublicKey.getModulus();
                        int keySize = modulus.bitLength();                        
                        System.out.println("Public Key: \n" + pemKey);
                        System.out.println("Key Size: " + keySize + " bits");
                        
                        break;
                    }


                    // Retrieve personal information
                    String nome = eid.getGivenName();
                    String sobrenome = eid.getSurname();
                    String nrCC = eid.getDocumentNumber();
                    String gender = eid.getGender();
                    String birth = eid.getDateOfBirth();
                    String documentVersion = eid.getDocumentVersion();
                    String documentType = eid.getDocumentType();
                    String validityBegin = eid.getValidityBeginDate();
                    String nationality = eid.getNationality();
                    String documentPAN = eid.getDocumentPAN();
                    String validityEnd = eid.getValidityEndDate();
                    String height = eid.getHeight();
                    String civilianIdNumber = eid.getCivilianIdNumber();
                    String taxNo = eid.getTaxNo();
                    String socialSecurityNumber = eid.getSocialSecurityNumber();
                    String healthNumber = eid.getHealthNumber();
                    String issuingEntity = eid.getIssuingEntity();
                    String localOfRequest = eid.getLocalofRequest();
                    String givenNameFather = eid.getGivenNameFather();
                    String surnameFather = eid.getSurnameFather();
                    String givenNameMother = eid.getGivenNameMother();
                    String surnameMother = eid.getSurnameMother();
                    String parents = eid.getParents();  // Assuming this returns a string
                    PTEID_Photo photoObj = eid.getPhotoObj();

                    // Retrieve the photo in different formats
                    PTEID_ByteArray praw = photoObj.getphotoRAW(); // JPEG2000 format
                    PTEID_ByteArray ppng = photoObj.getphoto(); // PNG format
                    byte[] bytes = ppng.GetBytes();
                    String base64Image = Base64.getEncoder().encodeToString(bytes);

                    // saveImage(bytes, "photo.png", "PNG");

                    // Print all the retrieved information
                    System.out.println("Name: " + nome);
                    System.out.println("Surname: " + sobrenome);
                    System.out.println("Document Number: " + nrCC);
                    System.out.println("Gender: " + gender);
                    System.out.println("Date of Birth: " + birth);
                    System.out.println("Document Version: " + documentVersion);
                    System.out.println("Document Type: " + documentType);   
                    System.out.println("Validity Start Date: " + validityBegin);
                    System.out.println("Nationality: " + nationality);
                    System.out.println("Document PAN: " + documentPAN);
                    System.out.println("Validity End Date: " + validityEnd);
                    System.out.println("Height: " + height);
                    System.out.println("Civilian ID Number: " + civilianIdNumber);
                    System.out.println("Tax Number: " + taxNo);
                    System.out.println("Social Security Number: " + socialSecurityNumber);
                    System.out.println("Health Number: " + healthNumber);
                    System.out.println("Issuing Entity: " + issuingEntity);
                    System.out.println("Local of Request: " + localOfRequest);
                    System.out.println("Father's Name: " + givenNameFather + " " + surnameFather);
                    System.out.println("Mother's Name: " + givenNameMother + " " + surnameMother);
                    System.out.println("Parents: " + parents);   
                    System.out.println("Image bytes "+ base64Image);

                 
                } catch (CertificateException | PTEID_Exception e) {
                    // Detailed error handling
                    System.err.println("Failed to retrieve card details: " + e.getMessage());
                    e.printStackTrace();
                }
            } else {
                System.out.println("error: No card inserted");
            }

        } catch (PTEID_Exception e) {
            System.out.println("error: An error occurred while initializing the SDK");

            // System.err.println("An error occurred while initializing the SDK: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                PTEID_ReaderSet.releaseSDK();
            } catch (PTEID_Exception e) {
                // System.err.println("An error occurred while releasing the SDK: " + e.getMessage());
                System.out.println("error: An error occurred while releasing the SDK");

                e.printStackTrace();
            }
        }
    }
     // Method to convert a PublicKey to PEM format
    public static String exportToPEM(PublicKey publicKey) {
        try {
            // Encode the public key in Base64
            byte[] encodedKey = publicKey.getEncoded();
            String base64Encoded = Base64.getEncoder().encodeToString(encodedKey);

            // Format as PEM
            StringBuilder pem = new StringBuilder();
            pem.append("-----BEGIN PUBLIC KEY-----\n");
            pem.append(base64Encoded);
            pem.append("\n-----END PUBLIC KEY-----");
            return pem.toString();

        } catch (Exception e) {
            System.out.println("error: An error occurred while exporting the public key to PEM");

            // System.err.println("An error occurred while exporting the public key to PEM:");
            e.printStackTrace();
            return null;
        }
    }

}
