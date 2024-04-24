/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Create Root CA Certificate and Signing Certificate, signed with the CA certificate
// Written by Michael Howard, Azure Data Platform, Microsoft Corp.
// 
// Code to setup a Certificate Authority using .NET
// This is for *experimental purposes only* so you don't need to use self-signed certificates.
// This mimics a PKI hierarchy without setting up a PKI hierarchy!
//
// Background info:
// https://learn.microsoft.com/en-US/sql/database-engine/configure-windows/configure-sql-server-encryption
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#region Cert Generation 
const int NotBeforeSkew = -2; // 2 Hour skew for the notBefore value

static X509Certificate2 CreateRootCertificate(string caName)
{
    var rsa = RSA.Create(4096);

    var subject = new X500DistinguishedName($"CN={caName}");
    var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

    var notBefore = DateTimeOffset.UtcNow.AddHours(NotBeforeSkew);
    var notAfter = notBefore.AddYears(2);

    return request.CreateSelfSigned(notBefore, notAfter);
}

static X509Certificate2 CreateSigningCertificate(string subjectName, X509Certificate2 issuerCertificate)
{
    var rsa = RSA.Create(2048);

    var subject = new X500DistinguishedName($"CN={subjectName}");
    var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                                            new OidCollection { 
                                                new Oid("1.3.6.1.5.5.7.3.3")}, // Code and Doc Signing
                                            true)); 

    var notBefore = DateTimeOffset.UtcNow.AddHours(NotBeforeSkew);
    var notAfter = notBefore.AddYears(1);

    // Get the CA private key for signing
    using RSA? issuerPrivateKey = issuerCertificate.GetRSAPrivateKey();
    if (issuerPrivateKey is null)
    {
        throw new Exception("Issuer certificate does not have a private key");
    }

    var signingCertificate = request.Create(issuerCertificate.SubjectName, 
            X509SignatureGenerator.CreateForRSA(issuerPrivateKey, RSASignaturePadding.Pkcs1), 
            notBefore, notAfter,
    Guid.NewGuid().ToByteArray());

    // need to get the private key from the RSA object
    return signingCertificate.CopyWithPrivateKey(rsa);
}

#endregion

#region Add Certs to Cert Respective Store

static void AddRootCaCertToCertStore(string certPath)
{
    var certificate = new X509Certificate2(certPath);
    var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    store.Add(certificate);
    store.Close();
}
static void AddSigningCertToUserCertStore(string certPath, string pfxPwd)
{
    var cert = new X509Certificate2(certPath, pfxPwd, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    store.Add(cert);
    store.Close();
}

#endregion

#region Main

// Create and save the Root CA certificate
var rootCACertFilename = "RootCA.cer";
var rootCertificate = CreateRootCertificate("Mikehow Experimental Root CA");
File.WriteAllBytes(rootCACertFilename, rootCertificate.Export(X509ContentType.Cert));

// Create and save the signing certificate
Console.Write("Enter email for the cert: ");
var cn = Console.ReadLine();

Console.Write("Enter PFX password: ");
var pfxPwd = Console.ReadLine();
if (pfxPwd is null || pfxPwd.Length == 0)
{
    Console.WriteLine("Please enter a password to encrypt the PFX file.");
    return;
}

var signingCertFilename = "SigningCert.pfx";
var signingCertWithPrivateKey = CreateSigningCertificate(cn, rootCertificate);
File.WriteAllBytes(signingCertFilename, signingCertWithPrivateKey.Export(X509ContentType.Pfx, pfxPwd));

// Add certs to cert store
AddRootCaCertToCertStore(rootCACertFilename);
AddSigningCertToUserCertStore(signingCertFilename, pfxPwd);

Console.WriteLine("Success!");
Console.WriteLine($"Root CA cert is in {rootCACertFilename} and 'User->TrustedRoot' Cert Store");
Console.WriteLine($"Signing cert and private key is in {signingCertFilename} encrypted with {pfxPwd}, and in the 'User->My' Cert Store");
#endregion