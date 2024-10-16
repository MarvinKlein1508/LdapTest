using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace LdapLoginExample
{
    class Program
    {
        static void Main(string[] args)
        {
            ActiveDirectory();
            Console.WriteLine("----------------------------");
            OpenDJ();
        }

        private static void ActiveDirectory()
        {
            string server = "mksrv"; // Ersetzen Sie dies durch Ihren LDAP-Server
            int port = 389; // Standardport für LDAP
            string username = "klein"; // Benutzername
            string password = "12Tester34#";
            string domain = "mk.local";


            try
            {
                using var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(server, port));
                var credential = new NetworkCredential(username, password, domain);
                ldapConnection.AuthType = AuthType.Negotiate;

                // Versuchen Sie, sich zu authentifizieren
                ldapConnection.Bind(credential);


                var searchRequest = new SearchRequest
                (
                    distinguishedName: "CN=Users,DC=mk,DC=local",
                    ldapFilter: $"(SAMAccountName={username})",
                    searchScope: SearchScope.Subtree,
                    attributeList:
                    [
                        "cn",
                        "mail",
                        "displayName",
                        "givenName",
                        "sn",
                        "objectGUID",
                        "memberOf"
                    ]
                );

                var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

                SearchResultEntry searchResultEntry = searchResponse.Entries[0];

                Dictionary<string, string> attributes = [];
                Guid? guid = null;

                List<string> gruppen = [];
                foreach (DirectoryAttribute userReturnAttribute in searchResultEntry.Attributes.Values)
                {
                    if (userReturnAttribute.Name == "objectGUID")
                    {
                        byte[] guidByteArray = (byte[])userReturnAttribute.GetValues(typeof(byte[]))[0];
                        guid = new Guid(guidByteArray);
                        attributes.Add("guid", ((Guid)guid).ToString());
                    }
                    else if (userReturnAttribute.Name == "memberOf")
                    {
                        foreach (string item in userReturnAttribute.GetValues(typeof(string)).Cast<string>())
                        {
                            gruppen.Add(item);
                        }
                    }
                    else
                    {
                        attributes.Add(userReturnAttribute.Name, (string)userReturnAttribute.GetValues(typeof(string))[0]);
                    }
                }

                attributes.TryAdd("mail", string.Empty);
                attributes.TryAdd("sn", string.Empty);
                attributes.TryAdd("givenName", string.Empty);
                attributes.TryAdd("displayName", string.Empty);

                if (guid is null)
                {
                    throw new InvalidOperationException();
                }

                foreach (var item in attributes)
                {
                    Console.WriteLine($"{item.Key}: {item.Value}");
                }

            }
            catch (LdapException ex)
            {
                // LDAP-Fehler
                Console.WriteLine($"LDAP-Fehler: {ex.Message}");

            }
            catch (Exception ex)
            {
                // Allgemeiner Fehler
                Console.WriteLine($"Ein Fehler ist aufgetreten: {ex.Message}");
            }
        }

        private static void OpenDJ()
        {
          
            string password = "12Tester34#";

            string ldapServer = "localhost"; // Ersetzen Sie dies durch Ihren LDAP-Server
            int ldapPort = 389; // Standardport für LDAP

            string username = "mk"; // Benutzername
            string distinguishedName = "cn=mk,ou=People,dc=example,dc=com"; // Vollständiger DN

            if (AuthenticateUser(ldapServer, ldapPort, distinguishedName, password))
            {
                Console.WriteLine("Anmeldung erfolgreich!");

                // Alle Attribute abfragen
                var attributes = GetUserAttributes(ldapServer, ldapPort, distinguishedName, password);
                Console.WriteLine("Attribute des Benutzers:");

                foreach (var attr in attributes)
                {
                    Console.WriteLine($"{attr.Key}: {string.Join(", ", attr.Value)}");
                }
            }
            else
            {
                Console.WriteLine("Anmeldung fehlgeschlagen. Überprüfen Sie Ihren Benutzernamen und Ihr Passwort.");
            }
        }

        static bool AuthenticateUser(string server, int port, string distinguishedName, string password)
        {
            try
            {
                using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(server, port)))
                {
                    var credential = new NetworkCredential(distinguishedName, password);
                    ldapConnection.AuthType = AuthType.Basic;

                    // Versuchen Sie, sich zu authentifizieren
                    ldapConnection.Bind(credential);
                    return true; // Authentifizierung erfolgreich
                }
            }
            catch (LdapException ex)
            {
                // LDAP-Fehler
                Console.WriteLine($"LDAP-Fehler: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                // Allgemeiner Fehler
                Console.WriteLine($"Ein Fehler ist aufgetreten: {ex.Message}");
                return false;
            }
        }

        static string ReadPassword()
        {
            string password = string.Empty;

            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password[0..^1]; // Entferne das letzte Zeichen
                    Console.Write("\b \b"); // Löschen des letzten Zeichens in der Konsole
                }
                else
                {
                    password += key.KeyChar;
                    Console.Write("*"); // Zeige ein Sternchen für jedes eingegebene Zeichen
                }
            }

            return password;
        }

        static Dictionary<string, List<string>> GetUserAttributes(string server, int port, string distinguishedName, string password)
        {
            var attributes = new Dictionary<string, List<string>>();

            try
            {
                using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(server, port)))
                {
                    // Der Bindvorgang ist erforderlich, um die Verbindung zu authentifizieren
                    var credential = new NetworkCredential(distinguishedName, password);
                    ldapConnection.AuthType = AuthType.Basic;

                    // Versuchen Sie, sich zu authentifizieren
                    ldapConnection.Bind(credential);

                    var searchRequest = new SearchRequest(distinguishedName, "(objectClass=*)", SearchScope.Base, null);
                    var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        foreach (string attribute in entry.Attributes.AttributeNames)
                        {
                            var values = new List<string>();
                            foreach (var value in entry.Attributes[attribute])
                            {
                                // Konvertieren Sie die Werte in Strings
                                if (value is byte[])
                                {
                                    // Konvertieren von byte[] in einen lesbaren String
                                    values.Add(Encoding.UTF8.GetString((byte[])value));
                                }
                                else
                                {
                                    values.Add(value.ToString());
                                }
                            }
                            attributes[attribute] = values;
                        }


                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fehler beim Abrufen der Attribute: {ex.Message}");
            }

            return attributes;
        }
    }
}
