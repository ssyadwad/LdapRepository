using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using System;
using System.Threading;
using System.Runtime.Remoting.Messaging;
namespace SecurityConsoleApplication
{
    public class LDAP
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

        #endregion

        public delegate LdapConnection AsyncMethodCaller();

        public async void GetGroupsForCurrentUser()
        {
            //Retrieve the NetBIOS name. 
            var result = System.Environment.MachineName;

            //Display the results to the console window.
            Console.WriteLine("NetBIOS Name = {0}", result);

            //Retrieve the DNS name. 
            //result = System.Net.Dns.GetHostByName("LocalHost").HostName;

            //Display the results to the console window.
            Console.WriteLine("DNS Name = {0}", result);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            //1. Get a LDAP Connection
            //_ldapConnection = GetLDAPConnection();

            ////Get a current User
            ////Get a current user Distinguished Name.
            //string distinguishedUserName = LdapHelper.GetCurrentUser(_ldapConnection, currentDomain);

            //watch.Stop();
            //var elapsedMsForConnection = watch.ElapsedMilliseconds;
            //Console.WriteLine("Logged In User and Connection Binding time :-" + elapsedMsForConnection);
            //watchGetGrioups = System.Diagnostics.Stopwatch.StartNew();

            // await GetLdapConnection();

            AsyncMethodCaller caller = new AsyncMethodCaller(BindLDAPConnection);
            int dummy = 0;
            IAsyncResult resultas = caller.BeginInvoke(
                new AsyncCallback(CallbackMethod),
                "The call executed on thread {0}, with return value \"{1}\".");
            ////Get LDAP connection
            //_ldapConnectionUsers = BindLDAPConnection();
            
            //LdapHelper.SetLDAPConnection(_ldapConnectionUsers);
            //LdapHelper.GetLdapGroupMembers("RG CN BSCE ALL");
            ////LdapHelper.GetLdapGroupMembers("RG IN SL Siemens Learning Manager");
            ////LdapHelper.GetLdapGroupMembers("RG IN STS BLR Bangalore Group2");
            //// LdapHelper.GetLdapGroupMembers("RG IN STS SPIRIDON SAP USERS");
            ////LdapHelper.GetLdapGroupMembers("DF FA SE DS FTH BR (IMD)");
            ////Get parent groups
            //SearchRequest searchRequest = GetSearchQuery(distinguishedUserName);
            Console.WriteLine("CoHo Thread Ends here!!");

            //GetGroups(searchRequest);

        }

        public void CallbackMethod(IAsyncResult ar)
        {
            AsyncResult result = (AsyncResult)ar;
            AsyncMethodCaller caller = (AsyncMethodCaller)result.AsyncDelegate;
            _ldapConnectionUsers = caller.EndInvoke(result);
            string distinguishedUserName = LdapHelper.GetCurrentUser(_ldapConnectionUsers, currentDomain);
            LdapHelper.SetLDAPConnection(_ldapConnectionUsers);
            LdapHelper.GetLdapGroupMembers("RG CN BSCE ALL");
            //LdapHelper.GetLdapGroupMembers("RG IN SL Siemens Learning Manager");
            //LdapHelper.GetLdapGroupMembers("RG IN STS BLR Bangalore Group2");
            // LdapHelper.GetLdapGroupMembers("RG IN STS SPIRIDON SAP USERS");
            //LdapHelper.GetLdapGroupMembers("DF FA SE DS FTH BR (IMD)");
            //Get parent groups
            SearchRequest searchRequest = GetSearchQuery(distinguishedUserName);
            

            GetGroups(searchRequest);
        }

        public async Task<LdapConnection> GetLdapConnection()
        {
            AsynchronousTaskExecution asyncTask = new AsynchronousTaskExecution();
            return  await asyncTask.GetLdapConnection();
        }
        private void GetGroups(SearchRequest searchRequest)
        {
            IAsyncResult asyncResult = _ldapConnectionUsers.BeginSendRequest(
                searchRequest,
                PartialResultProcessing.NoPartialResultSupport,
                RunAsyncSearch,
                null);
        }

        public LdapConnection GetLDAPConnection()
        {
            currentDomain =
                ((System.DirectoryServices.ActiveDirectory.ActiveDirectoryPartition) (Domain.GetCurrentDomain())).Name;
            //string str = GetNetbiosDomainName(currentDomain);
            // GetNetBiosName();
            currentDomain = "ad001.siemens.net";
            return LdapHelper.GetLDAPConnection(currentDomain, defaultPort);

        }

        private string GetNetbiosDomainName(string dnsDomainName)
        {
            string netbiosDomainName = string.Empty;

            DirectoryEntry rootDSE = new DirectoryEntry("LDAP://RootDSE");

            string configurationNamingContext = rootDSE.Properties["configurationNamingContext"][0].ToString();

            DirectoryEntry searchRoot = new DirectoryEntry("LDAP://cn=Partitions," + configurationNamingContext);

            DirectorySearcher searcher = new DirectorySearcher(searchRoot);
            //searcher.SearchScope = SearchScope.OneLevel;
            searcher.PropertiesToLoad.Add("netbiosname");
            searcher.Filter = string.Format("(&(objectcategory=Crossref)(dnsRoot={0})(netBIOSName=*))", dnsDomainName);

            SearchResult result = searcher.FindOne();

            if (result != null)
            {
                netbiosDomainName = result.Properties["netbiosname"][0].ToString();
            }

            return netbiosDomainName;
        }

        private void GetNetBiosName()
        {
            var filter = "(&(objectClass=*))";
            var searchRequest = new SearchRequest(null, filter, SearchScope.Base, "configurationNamingContext");
            var response = _ldapConnectionUsers.SendRequest(searchRequest) as SearchResponse;
            var usn = response.Entries[0].Attributes["configurationNamingContext"][0];
        }

        private SearchRequest GetSearchQuery(string distinguishedUserName)
        {
            userName = LdapHelper.GetCurrentLoggedInUse();
            string ldapUserQuery = string.Format(ldapUserFilter, userName);
            return new SearchRequest(distinguishedUserName, ldapUserQuery, SearchScope.Subtree, null);
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
            s.AppendChar('*');
            return s;
        }

        public LdapConnection BindLDAPConnection()
        {
            var flag = 0;
            _ldapConnectionUsers = GetLDAPConnection();
            _ldapConnectionUsers.AuthType = AuthType.Basic;
            _ldapConnectionUsers.SessionOptions.SecureSocketLayer = true;
            _ldapConnectionUsers.SessionOptions.ProtocolVersion = 3;
            _ldapConnectionUsers.SessionOptions.VerifyServerCertificate =
                ServerCallback;
            password = GetPasswordForUser();
            NetworkCredential network = LdapHelper.GetNetworkCredentials();
            LdapHelper.network = network;
            _ldapConnectionUsers.Timeout = new TimeSpan(0, 0, 1, 0);
            _ldapConnectionUsers.Bind(network);
            return _ldapConnectionUsers;
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

        public static bool ServerCallback(
            LdapConnection connection, X509Certificate2 certificate)
        {
            return true;
            //try
            //{
            //    X509Certificate expectedCert =
            //        X509Certificate.CreateFromCertFile(
            //        "C:\\certificates\\certificate.cer");

            //    if (expectedCert.Equals(certificate))
            //    {
            //        return true;
            //    }
            //    else
            //    {
            //        return false;
            //    }
            //}
            //catch (Exception ex)
            //{
            //    return false;
            //}
        }

        public void GetNestedGroups(List<string> groupDataForLDAP)
        {
            //  LdapHelper.GetCurrentGroup();
            foreach (var groupData in groupDataForLDAP)
            {
                //LdapHelper.GetChildGroups(groupData, 0);
                //LdapHelper.GetParentGroups(groupData, 0);
                LdapHelper.GetMmbersOfGroup(groupData);
            }
        }

        public void GetUsers(List<string> groupDataForLDAP)
        {
            foreach (var groupData in groupDataForLDAP)
            {
                LdapHelper.GetUsersLdap(groupData);
            }
        }

        private List<string> GetAllGroupNames()
        {
            List<string> groups = new List<string>();
            LdapConnection conn = null;
            int defaultADPageSize = 500;
            int pageCount = 0;
            try
            {
                string ActiveDirectoryGroupFilterQuery2 =
                    "(|(objectClass=msExchDynamicDistributionList)(objectClass=group))";
                string[] propertiesToQuery = {"distinguishedname", "objectguid", "member", "memberof", "objectClass"};
                SearchRequest request = new SearchRequest(
                    null,
                    ActiveDirectoryGroupFilterQuery2,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    propertiesToQuery);
                // Set the result page size
                SearchRequest searchRequestDistinguishedName = new SearchRequest
                {
                    Scope = SearchScope.Subtree,
                    Filter = ActiveDirectoryGroupFilterQuery2
                };
                SearchOptionsControl searchOptions =
                    new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.PhantomRoot);
                searchRequestDistinguishedName.Controls.Add(searchOptions);
                //PageResultRequestControl requestPageSize = new PageResultRequestControl(defaultADPageSize);

                //request.Controls.Add(requestPageSize);
                while (true)
                {
                    PageResultResponseControl pageResponse = null;

                    SearchResponse results =
                        (SearchResponse) _ldapConnectionUsers.SendRequest(searchRequestDistinguishedName);

                    if (null == results)
                    {
                        break;
                    }
                    pageCount++;

                    // verify support for this advanced search operation
                    if (results.Controls.Length != 1 ||
                        !(results.Controls[0] is PageResultResponseControl))
                    {
                        break;
                    }
                    // cast the diretory control into a PageResultResponseControl object.
                    pageResponse = (PageResultResponseControl) results.Controls[0];
                    if (results.Entries.Count > 0)
                    {
                        foreach (SearchResultEntry searchResult in results.Entries)
                        {
                            SearchResultAttributeCollection attColl = searchResult.Attributes;
                            groups.Add(attColl["distinguishedname"][0].ToString());
                        }

                        // if this is true, there are no more pages to request
                        if (pageResponse != null && pageResponse.Cookie.Length == 0)
                        {
                            break;
                        }

                        // set the cookie of the pageRequest equal to the cookie of the pageResponse to
                        // request the next page of data in the send request
                        if (pageResponse != null)
                        {
                            //requestPageSize.Cookie = pageResponse.Cookie;
                        }
                    }
                }
            }
            catch (Exception ex)
            {

            }
            finally
            {
                if (conn != null)
                {
                    conn.Dispose();
                }
            }
            return groups;
        }

        private void RunAsyncSearch(IAsyncResult asyncResult)
        {


            try
            {
                // end the send request search operation
                SearchResponse response =
                    (SearchResponse) _ldapConnectionUsers.EndSendRequest(asyncResult);
                LdapHelper.SetLDAPConnection(_ldapConnectionUsers);
                List<string> GroupData = new List<string>();
                List<string> GroupDataLDAP = new List<string>();
                var groupData = string.Empty;
                if (response != null && response.Entries.Count == 1)
                {
                    SearchResultAttributeCollection a = response.Entries[0].Attributes;

                    SearchResultEntry obj = response.Entries[0];
                    var groups = obj.Attributes["memberOf"][0];
                    var groupCount = ((System.Collections.CollectionBase) (obj.Attributes["memberOf"])).Count;
                    for (int i = 0; i < groupCount; i++)
                    {
                        groupData = obj.Attributes["memberOf"][i].ToString();
                        GroupData.Add(groupData.ToString().Split('=')[1].Split(',')[0]);
                        GroupDataLDAP.Add(groupData);
                    }
                }
                watchGetGrioups.Stop();
                var elapsedMsForParentGourps = watchGetGrioups.ElapsedMilliseconds;
                Console.WriteLine("Parent Groups:-" + elapsedMsForParentGourps);
                var watchGetNestedGrioups = System.Diagnostics.Stopwatch.StartNew();
                // LdapHelper.GtGroups();
                //GetNestedGroups(GroupDataLDAP);
                LdapHelper.GetLdapGroups();
                GetUsers(GroupDataLDAP);
                //watchGetNestedGrioups.Stop();
                //var elapsedMsFornestedGourps = watchGetNestedGrioups.ElapsedMilliseconds;
                //Console.WriteLine("Nested Groups:-" + elapsedMsFornestedGourps);
                //GroupData.AddRange(LdapHelper._subGroupList);
                //GroupData = GroupData.Distinct().OrderBy(x => x).ToList();
                //Console.WriteLine("\n");
                //foreach (var item in GroupData)
                //{

                //    Console.WriteLine(item);
                //}
                //    LdapHelper.GetLdapGroups();
                //LdapHelper.GetUsersLdap();
                Console.WriteLine("Search Ended");
            }

            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                SearchResponse response = (SearchResponse) e.Response;

                foreach (SearchResultEntry entry in response.Entries)
                {
                    Console.WriteLine("{0}:{1}",
                        response.Entries.IndexOf(entry),
                        entry.DistinguishedName);
                }
            }
            catch (LdapException e)
            {
                Console.WriteLine(e.Message);
            }


        }
    }

}
