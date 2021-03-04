using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Runtime.Remoting.Messaging;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityConsoleApplication
{
    public class AsynchronousTaskExecution:IAsyncResult
    {
        #region LDAPVariables

        private LdapConnection _ldapConnection = null;
        private LdapConnection _ldapConnectionUsers = null;
        private string currentDomain = string.Empty;
        private int defaultPort = 636;
        private SecureString password;
        private string userName = string.Empty;
        private readonly string ldapUserFilter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName={0}))";
        System.Diagnostics.Stopwatch watchGetGrioups;
        public bool IsCompleted { get; }

        public WaitHandle AsyncWaitHandle { get; }

        public object AsyncState { get; }

        public bool CompletedSynchronously { get; }

        #endregion
        public async Task<LdapConnection> GetLdapConnection()
        {
            try
            {
                var flag = 0;
                _ldapConnectionUsers = GetLDAPConnection();
                _ldapConnectionUsers.AuthType = AuthType.Basic;
                _ldapConnectionUsers.SessionOptions.SecureSocketLayer = false;
                _ldapConnectionUsers.SessionOptions.ProtocolVersion = 3;
                _ldapConnectionUsers.SessionOptions.VerifyServerCertificate =
                    ServerCallback;
                _ldapConnectionUsers.SessionOptions.VerifyServerCertificate =
                    (con, cer) => true;
                password = GetPasswordForUser();
                NetworkCredential network = LdapHelper.GetNetworkCredentials();
                LdapHelper.network = network;
                _ldapConnectionUsers.Timeout = new TimeSpan(0, 0, 1, 0);
                _ldapConnectionUsers.Bind(network);
                Thread.Sleep(180000);
                return _ldapConnectionUsers;
            }
            catch (Exception ex)
            {
                
            }
            return _ldapConnectionUsers;
        }
        public LdapConnection GetLDAPConnection()
        {
            currentDomain =
                ((System.DirectoryServices.ActiveDirectory.ActiveDirectoryPartition)(Domain.GetCurrentDomain())).Name;
            //string str = GetNetbiosDomainName(currentDomain);
            // GetNetBiosName();
            currentDomain = "ad001.siemens.net";
            return LdapHelper.GetLDAPConnection(currentDomain, defaultPort);

        }
        private bool ServerCallback(LdapConnection connection, X509Certificate certificate)
        {
            X509Certificate2 cer = new X509Certificate2(certificate);
            return cer.Verify();

            //X509Store store = new X509Store(StoreLocation.CurrentUser);
            //store.Certificates.Add(cer);

            //X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindBySubjectName, "My Cert's Subject Name", false);
            //if (cers.Count > 0)
            //{
            //    cer = cers[0];
            //};
            //store.Close();
            return false;
        }

        private SecureString GetPasswordForUser()
        {
            var s = new SecureString();
            s.AppendChar('S');
            s.AppendChar('u');
            s.AppendChar('p');
            s.AppendChar('r');
            s.AppendChar('i');
            s.AppendChar('y');
            s.AppendChar('a');
            s.AppendChar('_');
            s.AppendChar('2');
            s.AppendChar('0');
            s.AppendChar('2');
            s.AppendChar('1');
            s.AppendChar('@');
            return s;
        }
    }
}
