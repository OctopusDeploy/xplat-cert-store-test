using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace cert
{
    class Program
    {
        private static StoreName storeName = StoreName.Root;
        private static StoreLocation storeLocation = StoreLocation.CurrentUser;

        static void Main(string[] args)
        {
            if (args[0] == "install") {
                Install(args.ToList().Skip(1));
            }

            if (args[0] == "remove") {
                Remove(args.ToList().Skip(1));
            }

            if (args[0] == "list") {
                List(args.ToList().Skip(1));
            }

            if (args[0] == "listall") {
                ListAll(args.ToList().Skip(1));
            }
        }

        private static void List(IEnumerable<string> args)
        {
            string subject = args.Any() ? args.First() : string.Empty;
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            var certs = string.IsNullOrEmpty(subject) ? store.Certificates : store.Certificates.Find(X509FindType.FindBySubjectName, subject, false);
            if (certs == null || certs.Count == 0) {
                certs = store.Certificates.Find(X509FindType.FindByThumbprint, subject, false);
            }
            foreach (var cert in certs) {
                PrintCert(store, cert);
            }
        }

        private static void ListAll(IEnumerable<string> args)
        {
            string subject = args.Any() ? args.First() : string.Empty;

            foreach (var storeLocation in new [] { StoreLocation.CurrentUser, StoreLocation.LocalMachine})
            foreach (var storeName in new [] { StoreName.My, StoreName.Root, StoreName.CertificateAuthority})
            {
                if (storeLocation == StoreLocation.LocalMachine && storeName == StoreName.My) continue;
                var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                var certs = string.IsNullOrEmpty(subject) ? store.Certificates : store.Certificates.Find(X509FindType.FindBySubjectName, subject, false);
                if (certs == null || certs.Count == 0) {
                    certs = store.Certificates.Find(X509FindType.FindByThumbprint, subject, false);
                }
                foreach (var cert in certs) {
                    PrintCert(store, cert);
                }
            }
        }

        private static void Remove(IEnumerable<string> args)
        {
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadWrite);
            var thumbprint = args.First();
            var cert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            if  (cert == null) {
                Console.WriteLine($"{thumbprint} not found");
                return;
            }
            store.Remove(cert[0]);
        }

        private static void Install(IEnumerable<string> args)
        {
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadWrite);

            var file = args.First();
            var bytes = File.ReadAllBytes(file);
            X509Certificate2 cert = new X509Certificate2(bytes, "password");
            PrintCert(store, cert);

            
            
            store.Add(cert);

        }

        private static void PrintCert(X509Store store, X509Certificate2 cert) {
            try {
                Console.WriteLine($"Store: {store.Location}.{store.Name}");
                //Console.WriteLine(store.ToString());
                Console.WriteLine(cert.Thumbprint);
                Console.WriteLine(cert.PublicKey.Key);
                Console.WriteLine(cert.PrivateKey != null);
                Console.WriteLine($"HasPrivateKey = {cert.HasPrivateKey}");
                Console.WriteLine(cert.Subject);
                Console.WriteLine($"Not before: {cert.NotBefore}");
                Console.WriteLine($"Not after: {cert.NotAfter}");
                //Console.WriteLine(cert.SubjectName.Name);
                // if (cert.HasPrivateKey)
                // {
                //     Console.WriteLine(cert.PrivateKey.ToXmlString(true));
                // }
                Console.WriteLine(string.Empty);
                Console.WriteLine(" ");
            }
            catch (PlatformNotSupportedException) {}
            catch (Exception) {}
        }
    }
}
