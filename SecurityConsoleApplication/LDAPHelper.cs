using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Policy;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.SqlServer.Server;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace SecurityConsoleApplication
{
    public class LdapHelper
    {
        public static NetworkCredential network;
        public static LdapConnection ldap = null;
        public static string LdapQuery = string.Empty;
        public static List<string> _subGroupList = new List<string>();
        public static Dictionary<string, string> _dictionary = new Dictionary<string, string>();

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static void SetLDAPConnection(LdapConnection ldapconn)
        {
            ldap = ldapconn;
        }

        internal const string LDAP_SEARCH_FILTER_DOMAIN =
                "(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.804:=1)(systemFlags:1.2.840.113556.1.4.804:=2))"
            ;

        /// <summary>
        /// Properties to load from the crossRef object that provide information about the domain
        /// </summary>
        internal static readonly string[] domainObjectPropertiesToLoad = new string[]
        {
            "distinguishedName", "dnsRoot", "msDS-Behavior-Version", "nCName", "nETBIOSName", "ntMixedDomain",
            "trustParent"
        };

        public static SearchResultEntry GetLdapGroup(string strGroupDN)
        {
            //string ldapFilterGroup = string.Format(CultureInfo.InvariantCulture, "(&(objectClass=Group)(CN={0}))", strGroupDN.Split('=')[1].Split(',')[0]);
            //Get the Domain
            string ldapFilterGroup = string.Format(CultureInfo.InvariantCulture, "(&(objectClass=Group)(CN={0}))",
                strGroupDN);
            //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
            //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
            SearchRequest searchRequestUsers1 =
                new SearchRequest("DC=ad001,DC=siemens,DC=net", ldapFilterGroup, SearchScope.Subtree);
            //This is crucial in getting the request speed you want. 
            //Setting the DomainScope will suppress any refferal creation during the search
            var SearchControl1 = new SearchOptionsControl(SearchOption.PhantomRoot);
            searchRequestUsers1.Controls.Add(SearchControl1);
            var pageResultRequestControl1 = new PageResultRequestControl(1000);
            searchRequestUsers1.Controls.Add(pageResultRequestControl1);

            SearchResultEntry objGroup = null;
            SearchResponse responseUsers1 = (SearchResponse) ldap.SendRequest(searchRequestUsers1);
            if (responseUsers1 != null && responseUsers1.Entries.Count > 0)
            {
                objGroup = responseUsers1.Entries[0];
            }
            return objGroup;
        }

        public static void GetUsers(List<string> aa)
        {
            aa.Add("aa");
        }

        public static void GetUsersLdap(string strGroupDN)
        {
            //Find the Group First
            var objLdapGroup = GetLdapGroup(strGroupDN);
            if (objLdapGroup != null)
            {
                string LdapGroup = objLdapGroup.Attributes["distinguishedname"][0].ToString();
                if (objLdapGroup.Attributes["primaryGroupID"] != null)
                {

                }
                foreach (var attributes in objLdapGroup.Attributes.AttributeNames)
                {
                    string a = attributes.ToString();
                }
                List<string> aa = new List<string>();
                GetUsers(aa);
                var IsObjectSidAttributePresent = objLdapGroup.Attributes["objectsid"] != null;
                var i = ConvertSidToString((byte[]) objLdapGroup.Attributes["objectsid"][0]);
                //var LdapUsers = GetLdapUsers(LdapGroup);
                LdapGroupEntity groupLdap=new LdapGroupEntity(objLdapGroup);
                var LdapGroupPr = IsValidGroup(groupLdap);
                var LdapUsers = GetLdapMembers(LdapGroupPr);
                var usersNested= GetNestedLdapUsers(LdapGroupPr);
                foreach (var item in usersNested)
                {
                    if (!LdapUsers.Contains(item))
                    {
                        LdapUsers.Add(item);
                    }
                }
                //List<string> MemberLdapUsers=new  List<string>();
                //foreach (SearchResultEntry LdapUser in LdapUsers.Entries)
                //{
                //    MemberLdapUsers.Add(LdapUser.Attributes["cn"][0].ToString());
                //}
            }
        }

        private static string ConvertSidToString(byte[] objectSid)
        {
            SecurityIdentifier si = new SecurityIdentifier(objectSid, 0);
            return si.ToString();
        }

        public static void GetLdapGroupMembers(string groupName)
        {
            GetDomainNetBIOS("ad001.siemens.net", null);
            string ldapFilterGroup = string.Format(CultureInfo.InvariantCulture, "(&(objectClass=Group)(CN={0}))",
                groupName);
            GetUsersLdap(groupName);
            //Get the Domain

            //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
            //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
            SearchRequest searchRequestUsers1 =
                new SearchRequest("DC=ad001,DC=siemens,DC=net", ldapFilterGroup, SearchScope.Subtree);
            //This is crucial in getting the request speed you want. 
            //Setting the DomainScope will suppress any refferal creation during the search
            var SearchControl1 = new SearchOptionsControl(SearchOption.PhantomRoot);
            searchRequestUsers1.Controls.Add(SearchControl1);
            var pageResultRequestControl1 = new PageResultRequestControl(1000);
            searchRequestUsers1.Controls.Add(pageResultRequestControl1);

            SearchResultEntry objGroup = null;
            SearchResponse responseUsers1 = (SearchResponse) ldap.SendRequest(searchRequestUsers1);
            if (responseUsers1 != null && responseUsers1.Entries.Count > 0)
            {
                objGroup = responseUsers1.Entries[0];
            }
            GetUsersLdap(objGroup.DistinguishedName);
            int childCount = objGroup.Attributes["member"].Count;
            List<string> LdapMembers = new List<string>();
            for (int i = 0; i < childCount; i++)
            {
                string ldapGroupMember = objGroup.Attributes["member"][i].ToString();
                LdapMembers.Add(ldapGroupMember);
            }
            string LdapmembersWithoutPatch = null;
            string LdapmembersWithPatch = null;
            List<string> LdapMemberWithoutPatch = new List<string>();
            List<string> LdapMemberWithPatch = new List<string>();
            foreach (var ldapMember in LdapMembers)
            {
                GetLdapUserWithoutPatch(ldapMember, out LdapmembersWithoutPatch);
                if (LdapmembersWithoutPatch != null)
                {
                    LdapMemberWithoutPatch.Add(LdapmembersWithoutPatch);


                }
                GetLdapUserWithPatch(ldapMember, out LdapmembersWithPatch);
                if (LdapmembersWithPatch != null)
                {
                    LdapMemberWithPatch.Add(LdapmembersWithPatch);
                }
            }

        }

        public static void GetLdapUserWithoutPatch(string ldapMember, out string LdapmembersWithoutPatch)
        {
            // string userDistinguishedname = @"CN=Joao Miranda(Domain -1\,SC),OU=Users,OU=WIN7,OU=CH,DC=AD001,DC=Siemens,dc=net";
            string userDistinguishedname = ldapMember;
            string strWithoutPatch = userDistinguishedname.Split('=')[1].Split(',')[0].Replace(@"\", string.Empty);
            string ldapuserFilterWithoutPatch = string.Format(CultureInfo.InvariantCulture,
                "(&(objectClass=person)(CN={0}))", strWithoutPatch);

            SearchRequest searchRequestUsers =
                new SearchRequest("DC=AD001,DC=siemens,DC=net", ldapuserFilterWithoutPatch, SearchScope.Subtree);
            //This is crucial in getting the request speed you want. 
            //Setting the DomainScope will suppress any refferal creation during the search
            var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
            searchRequestUsers.Controls.Add(SearchControl);
            var pageResultRequestControl = new PageResultRequestControl(1000);
            searchRequestUsers.Controls.Add(pageResultRequestControl);
            searchRequestUsers.DistinguishedName = userDistinguishedname;
            LdapmembersWithoutPatch = null;

            try
            {



                SearchResponse responseUsers = (SearchResponse) ldap.SendRequest(searchRequestUsers);

                foreach (SearchResultEntry response in responseUsers.Entries)
                {
                    LdapmembersWithoutPatch = (response.Attributes["samaccountname"][0].ToString());
                }


            }
            catch (Exception ex)
            {

            }


        }

        public static void GetLdapUserWithPatch(string ldapMember, out string LdapmembersWithPatch)
        {
            //string userDistinguishedname = @"CN=Joshi\, Akshay,OU=Pune,OU=APAC,OU=Users,OU=_Central,OU=RA026,DC=ad001,DC=siemens,DC=net";
            string userDistinguishedname = ldapMember;

            string ldapuserFilterWithPatch = string.Format(CultureInfo.InvariantCulture,
                "(&(objectClass=person)(distinguishedName={0}))", userDistinguishedname);

            SearchRequest searchRequestUsers =
                new SearchRequest("DC=ad001,DC=siemens,DC=net", ldapuserFilterWithPatch, SearchScope.Subtree);
            //This is crucial in getting the request speed you want. 
            //Setting the DomainScope will suppress any refferal creation during the search
            var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
            searchRequestUsers.Controls.Add(SearchControl);
            var pageResultRequestControl = new PageResultRequestControl(1000);
            searchRequestUsers.Controls.Add(pageResultRequestControl);
            searchRequestUsers.DistinguishedName = userDistinguishedname;
            LdapmembersWithPatch = null;

            try
            {



                SearchResponse responseUsers = (SearchResponse) ldap.SendRequest(searchRequestUsers);

                foreach (SearchResultEntry response in responseUsers.Entries)
                {
                    LdapmembersWithPatch = (response.Attributes["samaccountname"][0].ToString());
                }


            }
            catch (Exception ex)
            {

            }


        }


        

        
            public static LdapUserEntity IsValidLdapUser(string ldapUser)
            {
                LdapUserEntity ldapUserEntity = null;
                string ldapFilter = string.Empty;
                string currentDomain = GetDomain("DC=ad001,DC=siemens,DC=net");
                //2. Get Ldap Query To Fetch Group from LDAP
                //Ldap Filter (&(objectCategory=Group)(CN=GroupName))
                if (!string.IsNullOrEmpty(ldapUser))
                    ldapFilter = String.Format(CultureInfo.InvariantCulture,
                        Common.LdapFetchUserValidationQuery,
                        ldapUser);
                //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
                //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
                SearchRequest searchRequest = new SearchRequest(currentDomain, ldapFilter, SearchScope.Subtree);
                //This is crucial in getting the request speed you want. 
                //Setting the DomainScope will suppress any refferal creation during the search
                var searchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
                searchRequest.Controls.Add(searchControl);

                searchRequest.DistinguishedName = ldapUser;

                if (ldapUser != null)
                    searchRequest.Filter = String.Format(CultureInfo.InvariantCulture,
                        Common.LdapFetchUserValidationQuery,
                        ldapUser);


                SearchResponse responseLdapUser =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                if (responseLdapUser != null && responseLdapUser.Entries.Count > 0)
                {
                    SearchResultEntry objUser = responseLdapUser.Entries[0];
                    ldapUserEntity = new LdapUserEntity(objUser);

                }
                return ldapUserEntity;
            }


        public static List<string> GetNestedLdapUsers(LdapGroupEntity ldapGroup)
        {
            Stack<LdapGroupEntity> stack=new Stack<LdapGroupEntity>();

            if (ldapGroup.HasNestedGroups)
            {
                foreach (var item in ldapGroup.NestedGroups)
                {
                    stack.Push(item);
                }
                
            }
            List<string> users=new List<string>();
            while (stack.Count != 0)
            {
                LdapGroupEntity nestedGroup = stack.Pop();
                var usersNested = GetLdapMembers(nestedGroup);
                
                if (nestedGroup.HasNestedGroups)
                {
                    foreach (var item in nestedGroup.NestedGroups)
                    {
                        stack.Push(item);
                    }
                }
                foreach (var iteam in usersNested)
                {
                    if (!users.Contains(iteam))
                    {
                        users.Add(iteam);
                    }
                }
                


                
            }
            return users;
        }

            public static List<string> GetLdapMembers(LdapGroupEntity ldapGroup)
            {
                var childCount = ldapGroup.LdapMembers.Count;
                List<string> LdapMmbers = new List<string>();
                for (int i = 0; i < childCount; i++)
                {
                    string ldapGroupMember = ldapGroup.LdapMembers[i].ToString();
                    LdapUserEntity user = IsValidLdapUser(ldapGroupMember);
                    if (user == null)
                    {
                        LdapGroupEntity groupEntity = IsValidGroup(ldapGroup, ldapGroupMember);
                        
                    }
                    else
                    {
                        LdapMmbers.Add(ldapGroupMember);

                    }

                }
                return LdapMmbers;
            }
        public static LdapGroupEntity IsValidGroup(LdapGroupEntity RootLdapGroup)
        {
            LdapGroupEntity ldapGroupEntity = null;
            string ldapFilter = string.Empty;
            string currentDomain = GetDomain("DC=ad001,DC=siemens,DC=net");
            //2. Get Ldap Query To Fetch Group from LDAP
            //Ldap Filter (&(objectCategory=Group)(CN=GroupName))
            if (!string.IsNullOrEmpty(RootLdapGroup.DistinguishedName))
                ldapFilter = String.Format(CultureInfo.InvariantCulture,
                    Common.LdapFetchGroupQuery,
                    RootLdapGroup.DistinguishedName);
            //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
            //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
            SearchRequest searchRequest = new SearchRequest(currentDomain, ldapFilter, SearchScope.Subtree);
            //This is crucial in getting the request speed you want. 
            //Setting the DomainScope will suppress any refferal creation during the search
            var searchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
            searchRequest.Controls.Add(searchControl);

            searchRequest.DistinguishedName = RootLdapGroup.DistinguishedName;

            if (RootLdapGroup.DistinguishedName != null)
                searchRequest.Filter = String.Format(CultureInfo.InvariantCulture,
                    Common.LdapFetchGroupQuery,
                    RootLdapGroup.DistinguishedName);


            SearchResponse responseLdapUser =
                (SearchResponse)ldap.SendRequest(searchRequest);
            if (responseLdapUser != null && responseLdapUser.Entries.Count > 0)
            {
                SearchResultEntry objUser = responseLdapUser.Entries[0];
                ldapGroupEntity = new LdapGroupEntity(objUser);

            }
            return ldapGroupEntity;
        }

        public static LdapGroupEntity IsValidGroup(LdapGroupEntity RootLdapGroup,string ldapUser)
        {
            LdapGroupEntity ldapGroupEntity = null;
            string ldapFilter = string.Empty;
            string currentDomain = GetDomain("DC=ad001,DC=siemens,DC=net");
            //2. Get Ldap Query To Fetch Group from LDAP
            //Ldap Filter (&(objectCategory=Group)(CN=GroupName))
            if (!string.IsNullOrEmpty(ldapUser))
                ldapFilter = String.Format(CultureInfo.InvariantCulture,
                    Common.LdapFetchGroupQuery,
                    ldapUser);
            //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
            //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
            SearchRequest searchRequest = new SearchRequest(currentDomain, ldapFilter, SearchScope.Subtree);
            //This is crucial in getting the request speed you want. 
            //Setting the DomainScope will suppress any refferal creation during the search
            var searchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
            searchRequest.Controls.Add(searchControl);

            searchRequest.DistinguishedName = ldapUser;

            if (ldapUser != null)
                searchRequest.Filter = String.Format(CultureInfo.InvariantCulture,
                    Common.LdapFetchGroupQuery,
                    ldapUser);


            SearchResponse responseLdapUser =
                (SearchResponse)ldap.SendRequest(searchRequest);
            if (responseLdapUser != null && responseLdapUser.Entries.Count > 0)
            {
                SearchResultEntry objUser = responseLdapUser.Entries[0];
                ldapGroupEntity = new LdapGroupEntity(objUser);
                RootLdapGroup.NestedGroups.Add(ldapGroupEntity);
                RootLdapGroup.HasNestedGroups = true;
            }
            return ldapGroupEntity;
        }
        public static SearchResponse GetLdapUsers(string LdapGroup)
            {
                //set filter for member Of
                string ldapFilter = string.Format(CultureInfo.InvariantCulture, "(&(objectClass=person)(memberOf={0}))",
                    LdapGroup);

                string strDis =
                    @"CN=Joshi\, Akshay,OU=Pune,OU=APAC,OU=Users,OU=_Central,OU=RA026,DC=ad001,DC=siemens,DC=net";

                string strWithoutPatch = strDis.Split('=')[1].Split(',')[0].Replace(@"\", string.Empty);
                string ldapUserFilter = string.Format(CultureInfo.InvariantCulture,
                    "(&(objectClass=person)(distinguishedName={0}))",
                    @"CN=Joshi\, Akshay,OU=Pune,OU=APAC,OU=Users,OU=_Central,OU=RA026,DC=ad001,DC=siemens,DC=net");
                string ldapuserFilterWithoutPatch = string.Format(CultureInfo.InvariantCulture,
                    "(&(objectClass=person)(CN={0}))", strWithoutPatch);
                SearchRequest searchRequestUsers =
                    new SearchRequest("DC=ad001,DC=siemens,DC=net", ldapuserFilterWithoutPatch, SearchScope.Subtree);
                //This is crucial in getting the request speed you want. 
                //Setting the DomainScope will suppress any refferal creation during the search
                var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
                searchRequestUsers.Controls.Add(SearchControl);
                var pageResultRequestControl = new PageResultRequestControl(1000);
                searchRequestUsers.Controls.Add(pageResultRequestControl);
                searchRequestUsers.DistinguishedName = strDis;
                List<string> test = new List<string>();
                string ldapUserFromPrimaryGroupId = string.Empty;
                while (true)
                {
                    SearchResponse responseUsers = (SearchResponse) ldap.SendRequest(searchRequestUsers);
                    foreach (SearchResultEntry response in responseUsers.Entries)
                    {
                        SearchResultEntry objUser = responseUsers.Entries[0];
                        ldapUserFromPrimaryGroupId = response.Attributes["distinguishedName"][0].ToString();
                        string c = response.Attributes["cn"][0].ToString();
                        if (!test.Contains(ldapUserFromPrimaryGroupId))
                            test.Add(ldapUserFromPrimaryGroupId);
                    }
                    PageResultResponseControl pageRes =
                        (PageResultResponseControl) responseUsers.Controls[0];
                    if (pageRes.Cookie.Length == 0)
                    {
                        break;
                    }
                    pageResultRequestControl.Cookie = pageRes.Cookie;
                }

                return null;
            }
            //public static void GetUsers(string strGroupDN)
            //{
            //    // strGroupDN = "TestGroup";

            //    string ldapFilter = string.Format(CultureInfo.InvariantCulture, "(&(objectClass=person)(memberOf={0}))",
            //            obj1.Attributes["distinguishedname"][0]);
            //    //Get the Domain

            //    //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
            //    //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
            //    SearchRequest searchRequestUsers =
            //        new SearchRequest("DC=ad001,DC=siemens,DC=net", ldapFilter, SearchScope.Subtree);
            //    //This is crucial in getting the request speed you want. 
            //    //Setting the DomainScope will suppress any refferal creation during the search
            //    var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
            //    searchRequestUsers.Controls.Add(SearchControl);
            //    var pageResultRequestControl = new PageResultRequestControl(1000);
            //    searchRequestUsers.Controls.Add(pageResultRequestControl);


            //    SearchResponse responseUsers = (SearchResponse)ldap.SendRequest(searchRequestUsers);

            //    if (responseUsers != null && responseUsers.Entries.Count > 0)
            //    {
            //        SearchResultEntry obj = responseUsers.Entries[0];

            //    }
            //    SearchRequest searchRequest = new SearchRequest();
            //    searchRequest.DistinguishedName = strGroupDN;
            //    searchRequest.Filter = String.Format("(&(objectCategory=Group)(CN={0}))", strGroupDN.ToString().Split('=')[1].Split(',')[0]);
            //    SearchResponse response =
            //        (SearchResponse)ldap.SendRequest(searchRequest);
            //    if (response != null && response.Entries.Count > 0)
            //    {
            //        SearchResultEntry obj = response.Entries[0];
            //        string itemgroupName = strGroupDN.ToString().Split('=')[1].Split(',')[0];

            //        if (obj.Attributes["member"] != null)
            //        {
            //            var childCount = ((System.Collections.CollectionBase)(obj.Attributes["member"])).Count;
            //            for (int i = 2; i < childCount; i++)
            //            {

            //                string groupName = obj.Attributes["member"][i].ToString();
            //                List<string> localGroupList = new List<string>();
            //                if (groupName.Contains("OU=Users"))
            //                {
            //                    try
            //                    {
            //                        //var attributes = obj.Attributes.AttributeNames;
            //                        searchRequest.DistinguishedName = groupName;
            //                        searchRequest.Filter = String.Format("(&(objectCategory=user)(CN={0}))",
            //                            groupName.ToString().Split('=')[1].Split(',')[0].Replace(@"\", string.Empty));
            //                        SearchResponse response1 =
            //                            (SearchResponse)ldap.SendRequest(searchRequest);

            //                        if (response1.Entries.Count > 0)
            //                        {

            //                            //string a = response1.Entries[0].Attributes["distinguishedName"][0].ToString();
            //                            ////searchRequest.DistinguishedName = groupName;
            //                            //searchRequest.Filter = "netbiosname=*";
            //                            //SearchResponse response2 =
            //                            //    (SearchResponse)ldap.SendRequest(searchRequest);
            //                            //if (response1.Entries.Count > 0)
            //                            //{
            //                            //}

            //                            //var attributes = response1.Entries[0].Attributes;
            //                            //foreach (var item in attributes.AttributeNames)
            //                            //{
            //                            //    Console.WriteLine(item +" -> "+ response1.Entries[0].Attributes[item.ToString()][0]);
            //                            //}
            //                            //var filter = "(&(objectClass=*))";
            //                            //var searchRequest1 = new SearchRequest(null, LDAP_SEARCH_FILTER_DOMAIN, SearchScope.Subtree, domainObjectPropertiesToLoad);
            //                            //var response12 = ldap.SendRequest(searchRequest1) as SearchResponse;
            //                            //var usn = response12.Entries[0].Attributes["configurationNamingContext"][0];
            //                            //var forest = Forest.GetCurrentForest();
            //                            //var globalCatalog = GlobalCatalog.FindOne(new DirectoryContext(DirectoryContextType.Forest, forest.Name));
            //                            //string sServerName =
            //                            //    ldap.SessionOptions.HostName;
            //                            //string sDomainFqdn = sServerName.Substring(sServerName.IndexOf('.') +
            //                            //                                           1);
            //                            string str = GetDomainNetBIOS(GetFullyQualifiedDomainName(response1.Entries[0].Attributes["distinguishedName"][0].ToString().Replace(',', '.')), null);

            //                        }
            //                    }
            //                    catch (Exception ex)
            //                    {

            //                    }

            //                }

            //            }

            //        }
            //    }

            //}

            public static string GetFullyQualifiedDomainName(string distinguishedName)
            {
                var sFQDN = string.Empty;
                var FullyQualifiedDomainName = distinguishedName.Split(new string[] {"DC="}, StringSplitOptions.None);
                for (int i = 1; i < FullyQualifiedDomainName.Length; i++)
                {
                    sFQDN += FullyQualifiedDomainName[i];
                }
                return sFQDN;
            }

            private static string GetDomainNetBIOS(string sDomainFqdn, NetworkCredential netCred)
            {
                LdapDirectoryIdentifier oLdapDirectory = null;
                LdapConnection oLdapConnection = null;
                try
                {
                    string sNetBIOS = null;
                    oLdapDirectory = new LdapDirectoryIdentifier(sDomainFqdn, 636);

                    oLdapConnection = (netCred == null)

                        ? new LdapConnection(oLdapDirectory)
                        : new LdapConnection(oLdapDirectory, netCred);

                    oLdapConnection.Timeout = TimeSpan.FromSeconds(45);
                    oLdapConnection.SessionOptions.TcpKeepAlive = true;
                    oLdapConnection.SessionOptions.ProtocolVersion = 3;

//prevents ldap connection from connecting to other servers during session
                    oLdapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                    oLdapConnection.AutoBind = false;
                    oLdapConnection.Bind();

                    SearchResponse dirRes = (SearchResponse) ldap.SendRequest(new
                        SearchRequest(
                            null,
                            "configurationNamingContext=*",
                            System.DirectoryServices.Protocols.SearchScope.Base,
                            "configurationNamingContext"
                        ));
                    string sConfPartDN =
                        dirRes.Entries[0].Attributes["configurationNamingContext"][0].ToString();
                    dirRes = (SearchResponse) oLdapConnection.SendRequest(new SearchRequest(
                        sConfPartDN,
                        String.Format("(&(netbiosname=*))", sDomainFqdn),
                        System.DirectoryServices.Protocols.SearchScope.Subtree,
                        "netbiosname"
                    ));
                    if (dirRes.Entries.Count > 0)
                    {
                        sNetBIOS = dirRes.Entries[0].Attributes["netbiosname"][0].ToString();
                    }
                    return sNetBIOS;
                }
                catch (Exception ex)
                {
                    throw new Exception(string.Format("{0}::{1}", new StackFrame(0,
                        true).GetMethod().Name, ex.Message));
                }
                finally
                {
                    oLdapDirectory = null;
                    oLdapConnection.Dispose();
                    oLdapConnection = null;
                }
            }

            private static bool server(LdapConnection connection,
                System.Security.Cryptography.X509Certificates.X509Certificate certificate)
            {
                return true;
            }

            static void getGroup(string strGroupDN)
            {
                var strGroupDn = "DC=ad001,DC=siemens,DC=001";

                var pagedResults = new List<SearchResultEntryCollection>();
                var searchBaseDN = "DC=ad001,DC=siemens,DC=001";
                var searchFilter = String.Format("(&(objectCategory=Group)(CN={0}))",
                    strGroupDN.ToString().Split('=')[1].Split(',')[0]);
                var searchRequestLDAP = new SearchRequest
                (searchBaseDN,
                    searchFilter,
                    SearchScope.Subtree,
                    "distinguishedname");


                var searchOptions = new SearchOptionsControl(SearchOption.DomainScope);
                searchRequestLDAP.Controls.Add(searchOptions);

                var pageResultRequestControl = new PageResultRequestControl(1000);
                searchRequestLDAP.Controls.Add(pageResultRequestControl);

                while (true)
                {
                    var searchResponse = (SearchResponse) ldap.SendRequest(searchRequestLDAP);
                    var pageResponse = (PageResultResponseControl) searchResponse.Controls[0];

                    // yield return searchResponse.Entries;
                    if (pageResponse.Cookie.Length == 0)
                        break;

                    pageResultRequestControl.Cookie = pageResponse.Cookie;
                }

            }

            private static string GetGroupDistinguishedName(LdapConnection ldap, string groupName)
            {
                var distinguishedName = "CN=RA010-U-PUN-CCGMS,OU=GroupsDistribution,DC=ad001,DC=siemens,DC=001";
                ;

                var filter = string.Format("(&(objectClass=group)(name={0}))", groupName);
                var propertiesToLoad = new string[] {"distinguishedName"};
                //var distinguishedName = "CN=RA010-U-PUN-CCGMS,OU=GroupsDistribution,DC=ad001,DC=siemens,DC=001";
                ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.All;
                SearchRequest ldapSearchRequest =
                    new SearchRequest(null, filter, SearchScope.Subtree, propertiesToLoad);
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(ldapSearchRequest);
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];
                    if (obj.Attributes["DistinguishedName"] != null)
                        distinguishedName = obj.Attributes["DistinguishedName"][0].ToString();
                }
                //using (var ds = new DirectorySearcher(directoryEntry, filter, propertiesToLoad))
                //{
                //    SetupDefaultPropertiesOnDirectorySearcher(ds);

                //    var result = ds.FindOne();
                //    if (result != null)
                //    {
                //        distinguishedName = result.Properties["distinguishedName"][0].ToString();
                //    }
                //}

                return distinguishedName;
            }

            public static string GetDomain(string domain)
            {

                StringBuilder strDomain = new StringBuilder();
                if (domain != null && !string.IsNullOrEmpty(domain))
                {
                    var domainArray = domain.Split('.');
                    foreach (var domainComponent in domainArray)
                    {

                        strDomain.Append(string.Format("DC={0},", domainComponent));
                    }
                    strDomain.Length--;
                    return Convert.ToString(strDomain, CultureInfo.InvariantCulture);
                }
                else
                {
                    return null;
                }


            }

            //This link is referred for Ldap Escape filter characters issue
            //http://www.rlmueller.net/CharactersEscaped.htm// Filters
            //https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx Generic characters to escape refer LDAP Filters
            private static string EscapeLdapSearchFilter(string searchFilter)
            {
                StringBuilder escape = new StringBuilder(); // If using JDK >= 1.5 consider using StringBuilder
                for (int i = 0; i < searchFilter.Length; ++i)
                {
                    char current = searchFilter[i];
                    switch (current)
                    {
                        case '\\':
                            escape.Append(@"\5c");
                            break;
                        case '(':
                            escape.Append(@"\28");
                            break;
                        case ')':
                            escape.Append(@"\29");
                            break;
                        case '\u0000':
                            escape.Append(@"\00");
                            break;
                        case '/':
                            escape.Append(@"\2f");
                            break;
                        default:
                            escape.Append(current);
                            break;
                    }
                }

                return escape.ToString();
            }

            public static void GetLdapGroups()
            {
//BT CPS GDT GMS ZUG1-MEM
                string str = "RG IN STS CTDC I BT GMS" + EscapeLdapSearchFilter(LdapQuery) + "*";
                string strTest = "RG IN STS CTDC I BT GMS";
                //str = EscapeLdapSearchFilter(str);
                string str1 = "*zug*";
                string str2 = "(&(objectCategory=Group)(CN=(&)(CN=RG IN STS CTDC I BT GMS))";
                string ldapFilter = String.Format("(&(objectCategory=Group)(CN={0}))", strTest);
                GetDomainNetBIOS("ad001.siemens.net", null);
                string ldapFilter2 = String.Format("(&(objectClass=nTDSDSA)(options:1.2.840.113556.1.4.803:=1))");
                List<LdapGroup> listActiveDirectoryGroups = new List<LdapGroup>();
                var getUserRequest = new SearchRequest(null, ldapFilter, SearchScope.Subtree);
                PageResultRequestControl pg = new PageResultRequestControl(1000);
//This is crucial in getting the request speed you want. 
//Setting the DomainScope will suppress any refferal creation during the search
                var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
                getUserRequest.Controls.Add(SearchControl);
                getUserRequest.Controls.Add(pg);
                PageResultRequestControl pageRequestControl =
                    new
                        PageResultRequestControl(1000);
                while (true)
                {
                    ldap.Timeout = new TimeSpan(0, 0, 12, 0);

                    var response = (SearchResponse) ldap.SendRequest(getUserRequest);

                    string fileName = @"C:\Temp\LDAP.txt";
                    using (FileStream fs = File.Create(fileName))
                    {
                        // Add some text to file
                        Byte[] title = new UTF8Encoding(true).GetBytes("New Text File");
                        fs.Write(title, 0, title.Length);
                        byte[] author = new UTF8Encoding(true).GetBytes("Mahesh Chand");
                        fs.Write(author, 0, author.Length);
                    }
                    if (response != null && response.Entries.Count > 0)

                    {
                        foreach (var LdapGroup in response.Entries)
                        {
                            LdapGroup newLdapgroup = new LdapGroup();
                            SearchResultEntry activeDirectoryGroup = (SearchResultEntry) LdapGroup;
                            newLdapgroup.LdapGroupName = Convert.ToString(activeDirectoryGroup.Attributes["name"][0],
                                CultureInfo.CurrentCulture);
                            newLdapgroup.LdapGroupDescription = activeDirectoryGroup.Attributes["description"] != null
                                ? Convert.ToString(activeDirectoryGroup.Attributes["description"][0],
                                    CultureInfo.CurrentCulture)
                                : string.Empty;
                            newLdapgroup.memberCount = activeDirectoryGroup.Attributes["member"] != null
                                ? Convert.ToInt32((activeDirectoryGroup.Attributes["member"].Count),
                                    CultureInfo.CurrentCulture)
                                : 0;
                            listActiveDirectoryGroups.Add(newLdapgroup);

                        }
                        // Create a new file 
                        using (StreamWriter sw = File.CreateText(fileName))
                        {
                            foreach (var item in listActiveDirectoryGroups)
                            {
                                sw.WriteLine("Name->" + item.LdapGroupName + "Count->" + item.memberCount);
                            }
                        }
                        PageResultResponseControl pageRes = (PageResultResponseControl) response.Controls[0];
                        if (pageRes.Cookie.Length == 0) break;
                        else
                        {
                            pg.Cookie = pageRes.Cookie;
                        }
                    }
                    PageResultResponseControl pageRes1 = (PageResultResponseControl) response.Controls[0];
                    if (pageRes1.Cookie.Length == 0) break;
                    else
                    {
                        pg.Cookie = pageRes1.Cookie;
                    }
                }
                Console.WriteLine("special characters end");
            }

            public static void GtGroups()
            {
                var a = GetGroupDistinguishedName(ldap, "RA010-U-PUN-CCGMS");
                var strGroupDn = "CN=RA010-U-PUN-CCGMS,DC=ad001,DC=siemens,DC=001";
                var distinguishedName = "CN=RA010-U-PUN-CCGMS,OU=GroupsDistribution,DC=ad001,DC=siemens,DC=001";
                var filter = String.Format("(&(objectCategory=Group)(objectClass=group)(CN={0}))",
                    strGroupDn.ToString().Split('=')[1].Split(',')[0]);

                SearchRequest searchRequest = new SearchRequest();
                searchRequest.DistinguishedName = distinguishedName;
                searchRequest.Filter = filter;
                ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.Subordinate;
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                string sConfPartDN = string.Empty;
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];
                    sConfPartDN = obj.Attributes["configurationNamingContext"][0].ToString();
                    if (obj.Attributes["member"] != null)
                    {
                        var childCount = ((System.Collections.CollectionBase) (obj.Attributes["member"])).Count;
                    }
                }
                var srRequest = new SearchRequest(
                    sConfPartDN,
                    filter,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    new string[] {"cn", "objectGUID"}
                );
                var rcPageRequest = new PageResultRequestControl();
                //rcPageRequest.PageSize = 1;
                PageResultResponseControl rcPageResponse;
                srRequest.Controls.Add(rcPageRequest);
                do
                {
                    SearchResponse dirRes = (SearchResponse) ldap.SendRequest(srRequest);
                    rcPageResponse = (PageResultResponseControl) dirRes.Controls[0];
                    if (dirRes.Entries.Count > 0)
                    {
                        foreach (SearchResultEntry srEntry in dirRes.Entries)
                        {
                            string sObjectCN = srEntry.Attributes["cn"][0].ToString();
                            Guid oObjectGuid = new Guid((byte[]) srEntry.Attributes["objectGUID"]
                                .GetValues(Type.GetType("System.Byte[]"))[0]);
                            //this.dicExtAccessRights.Add(oObjectGuid.ToString(), sObjectCN);
                        }
                    }
                    rcPageRequest.Cookie = rcPageResponse.Cookie;
                } while (Convert.ToBoolean(rcPageResponse.Cookie.Length));
                //searchRequest.Filter = String.Format("(&(objectCategory=Group)(CN={0}))", strGroupDn.ToString().Split('=')[1].Split(',')[0]);
            }



            public static void GetChildGroups(string strGroupDN, int Children)
            {
                //GtGroups();
                //getGroup(strGroupDN);
                GetLdapGroups();
                int count_Children = Children;
                var strGroupDn = "DC=ad001,DC=siemens,DC=001";

                var filter = String.Format("(&(objectCategory=Group)(CN={0}))",
                    strGroupDN.ToString().Split('=')[1].Split(',')[0]);
                //SearchRequest searchRequest = new SearchRequest(targetOu, filter,SearchScope.Subtree,null);
                // SearchRequest searchRequest = new SearchRequest(strGroupDn, filter, SearchScope.Subtree, null);
                //searchRequest.DistinguishedName = strGroupDn;
                SearchRequest searchRequest =
                    new SearchRequest() {Scope = SearchScope.Base, Filter = filter, DistinguishedName = null};
                // create a search filter to find all objects
                //string ldapSearchFilter = "(objectClass=*)";
                //  searchRequest.DistinguishedName = strGroupDN;
                // searchRequest.Filter = String.Format("(&(objectCategory=Group))", strGroupDn.ToString().Split('=')[1].Split(',')[0]);
                searchRequest.Filter = String.Format("(&(objectCategory=Group)(CN={0}))",
                    strGroupDN.ToString().Split('=')[1].Split(',')[0]);
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];
                    string itemgroupName = strGroupDN.ToString().Split('=')[1].Split(',')[0];
                    if (!_dictionary.ContainsKey(itemgroupName.ToString()))
                    {
                        //if (obj.Attributes["displayName"] != null)
                        //{
                        //    _dictionary.Add(itemgroupName, obj.Attributes["displayName"][0].ToString());
                        //}
                        //else
                        //{
                        //    _dictionary.Add(itemgroupName, obj.Attributes["name"][0].ToString());
                        //}

                    }
                    if (obj.Attributes["member"] != null)
                    {
                        var childCount = ((System.Collections.CollectionBase) (obj.Attributes["member"])).Count;
                        for (int i = 0; i < childCount; i++)
                        {

                            string groupName = obj.Attributes["member"][i].ToString();
                            StringBuilder st = new StringBuilder(obj.Attributes.Count);
                            foreach (var attribute in obj.Attributes)
                            {
                                st.Append(obj.Attributes[attribute.ToString()][i]);
                            }
                            string fileName = @"C:\Temp\LDAP.txt";
                            using (FileStream fs = File.Create(fileName))
                            {

                            }
                            using (StreamWriter sw = File.CreateText(fileName))
                            {
                                foreach (var item in st.ToString())
                                {
                                    sw.WriteLine(item);
                                }
                            }

                            List<string> localGroupList = new List<string>();
                            if (groupName.Contains("OU=Groups"))
                            {
                                //var attributes = obj.Attributes.AttributeNames;

                                _subGroupList.Add(groupName.ToString().Split('=')[1].Split(',')[0]);
                                count_Children++;
                                GetChildGroups(groupName, count_Children);
                            }
                        }
                    }
                }
            }

            public static void WriteIntoFileDataFromLDAP(List<string> st)
            {
                string fileName = @"C:\Temp\LDAP.txt";
                using (FileStream fs = File.Create(fileName))
                {
                }
                using (StreamWriter sw = File.CreateText(fileName))
                {
                    foreach (var item in st)
                    {
                        sw.WriteLine(item);
                    }
                }

            }

            public static SearchResultEntry GetMembersAccordingToSearchControl(SearchResultEntry obj, int i)
            {
                string ldapFilter = string.Format(CultureInfo.InvariantCulture,
                    "(&(CN={0})(member=*))",
                    "RA010-U-PUN-CCGMS");
                //string ldapFilter = string.Format(CultureInfo.InvariantCulture, "(&(member=*)(CN={0}))", "RA010-U-PUN-CCGMS");
                //Get the Domain
                string currentDomain = "DC=ad001,DC=siemens,DC=net";
                //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
                //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
                SearchRequest searchRequestnew = new SearchRequest(currentDomain, ldapFilter, SearchScope.Subtree);
                //This is crucial in getting the request speed you want. 
                //Setting the DomainScope will suppress any refferal creation during the search
                var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
                searchRequestnew.Controls.Add(SearchControl);
                SearchResponse responsenew = (SearchResponse) ldap.SendRequest(searchRequestnew);
                if (responsenew != null && responsenew.Entries.Count > 0)
                {
                    SearchResultEntry obj1 = responsenew.Entries[0];
                    return obj1;
                }
                return null;
            }

            public static SearchResultEntry GetMemberAccordingTODistinguishedName(SearchResultEntry obj, int i)
            {
                SearchRequest searchRequestForMmbers = new SearchRequest();
                searchRequestForMmbers.DistinguishedName = obj.Attributes["member"][i].ToString();
                searchRequestForMmbers.Filter = String.Format("(&(CN={0})(objectClass=person))",
                    obj.Attributes["member"][i].ToString().Split('=')[1].Split(',')[0]);
                SearchResponse responseMembers =
                    (SearchResponse) ldap.SendRequest(searchRequestForMmbers);
                if (responseMembers != null && responseMembers.Entries.Count > 0)
                {
                    SearchResultEntry obj1 = responseMembers.Entries[0];
                    Console.WriteLine("{0}", obj1.Attributes["cn"][0]);
                    return obj1;
                }
                return null;
            }

            public static void GetMmbersOfGroup(string strGroupDN)
            {
                List<string> members = new List<string>();
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.DistinguishedName = strGroupDN;
                searchRequest.Filter = String.Format("(&(objectClass=Group)(CN=*{0}*))",
                    strGroupDN.Split('=')[1].Split(',')[0]);
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];
                    if (obj.Attributes["member"] != null)
                    {

                        var childCount = obj.Attributes["member"].Count;
                        if (childCount > 0)
                        {
                            for (int i = 0; i < childCount; i++)
                            {
                                if (i > 0 && !obj.Attributes["member"][i].ToString().Split('=')[1].Split(',')[0]
                                        .Equals("CC_Pune_CCadm")) continue;
                                var member = GetMemberAccordingTODistinguishedName(obj, i);
                                if (member != null) members.Add(member.Attributes["samaccountname"][0].ToString());
                                //List<string> st=new List<string>();
                                //if (obj.Attributes.AttributeNames != null)
                                //    foreach (var item in member.Attributes.AttributeNames)
                                //    {
                                //        st.Add(item + ":->" + member.Attributes[item.ToString()][0]);

                                //        if (i > 0)
                                //        {

                                //            File.AppendAllText(@"C:\Temp\LDAP.txt", item + ":->" + member.Attributes[item.ToString()][0] + Environment.NewLine);

                                //        }
                                //    }
                                //if (i > 0)
                                //{
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //}
                                //if (i == 0)
                                //{
                                //    WriteIntoFileDataFromLDAP(st);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //    File.AppendAllText(@"C:\Temp\LDAP.txt", "----------------------------------------------------------------------------------------------------" + Environment.NewLine);
                                //}
                                //if (i > 10) break;
                            }
                        }
                    }
                }
            }

            public static void GetParentGroups(string strGroupDN, int countParent)
            {
                int count_Parent = countParent;
                SearchRequest searchRequest = new SearchRequest();
                List<string> addNew = new List<string>();
                searchRequest.DistinguishedName = strGroupDN;
                //searchRequest.Filter = String.Format("(&(objectCategory=person)(objectClass=user)(objectCategory=Group)(CN=*{0}*))",
                //    strGroupDN.ToString().Split('=')[1].Split(',')[0]);
                searchRequest.Filter = String.Format("(&(objectCategory=Group)(CN=*{0}*))",
                    strGroupDN.ToString().Split('=')[1].Split(',')[0]);
                //searchRequest.Filter = String.Format("(&(objectClass=user)(objectCategory=person)(member=CN=*{0}*))",
                //    strGroupDN.ToString().Split('=')[1].Split(',')[0]);
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];
                    string itemgroupName = strGroupDN.ToString().Split('=')[1].Split(',')[0];
                    if (!_dictionary.ContainsKey(itemgroupName.ToString()))
                    {
                        if (obj.Attributes["displayName"] != null)
                        {
                            _dictionary.Add(itemgroupName, obj.Attributes["displayName"][0].ToString());
                        }
                        else
                        {
                            _dictionary.Add(itemgroupName, obj.Attributes["name"][0].ToString());
                        }
                    }

                    if (obj.Attributes["member"] != null)
                    {
                        var childCount = ((System.Collections.CollectionBase) (obj.Attributes["member"])).Count;
                        if (childCount > 0)
                        {

                            for (int i = 0; i < childCount; i++)
                            {
                                //Ldap Filter (&(objectCategory=Group)(CN=GroupName))
                                string ldapFilter = string.Format(CultureInfo.InvariantCulture,
                                    "(&(objectclass=user)(CN={0}))",
                                    obj.Attributes["member"][i].ToString().Split('=')[1].Split(',')[0]);
                                //Get the Domain
                                string currentDomain = "DC=ad001,DC=siemens,DC=net";
                                //Search request parameters are CurrentDomain(DC=AD001,DC=SIEMENS,DC=NET), Filter and SearchScope 
                                //SearchScope defines under Current Domain , control searches for the given filter(CN is common name is filtered under given Domain)
                                SearchRequest searchRequestnew =
                                    new SearchRequest(currentDomain, ldapFilter, SearchScope.Subtree);
                                //This is crucial in getting the request speed you want. 
                                //Setting the DomainScope will suppress any refferal creation during the search
                                var SearchControl = new SearchOptionsControl(SearchOption.PhantomRoot);
                                searchRequestnew.Controls.Add(SearchControl);
                                SearchResponse responsenew = (SearchResponse) ldap.SendRequest(searchRequestnew);
                                if (responsenew != null && responsenew.Entries.Count > 0)
                                {
                                    SearchResultEntry obj1 = responsenew.Entries[0];
                                    addNew.Add(obj1.Attributes["name"][0].ToString());
                                }




                                SearchRequest searchRequest1 = new SearchRequest();
                                searchRequest1.DistinguishedName = obj.Attributes["member"][i].ToString();
                                //searchRequest1.Filter = String.Format("(&(objectCategory=person)(objectClass=user)(CN={0}))",
                                //    obj.Attributes["member"][i].ToString().Split('=')[1].Split(',')[0]);
                                //searchRequest1.Filter = String.Format("(&(objectCategory=person)(objectClass=user)(&CN={0})(&OU:DN:=Users))",
                                //    obj.Attributes["member"][i].ToString().Split('=')[1].Split(',')[0]);
                                searchRequest1.Filter =
                                    String.Format("(&(CN={0})(objectClass=user)(objectCategory=person))",
                                        obj.Attributes["member"][i].ToString().Split('=')[1].Split(',')[0]);
                                SearchResponse response1 =
                                    (SearchResponse) ldap.SendRequest(searchRequest1);
                                if (response1 != null && response1.Entries.Count > 0)
                                {
                                    SearchResultEntry obj1 = response1.Entries[0];
                                    addNew.Add(obj1.Attributes["name"][0].ToString());
                                }
                                else
                                {

                                }

                            }


                        }

                        if (obj.Attributes["objectClass"].Contains("user"))
                        {
                            string gl = "a";
                        }
                        if (childCount > 0)
                        {
                            List<string> users = new List<string>();
                            for (int i = 0; i < childCount; i++)
                            {
                                string groupName = obj.Attributes["member"][i].ToString();
                                users.Add(groupName);
                            }

                            List<string> st = new List<string>(obj.Attributes.Count);
                            foreach (var attribute in obj.Attributes.AttributeNames)
                            {
                                st.Add(attribute + "\n");
                            }
                            string fileName = @"C:\Temp\LDAP.txt";
                            using (FileStream fs = File.Create(fileName))
                            {
                            }
                            using (StreamWriter sw = File.CreateText(fileName))
                            {
                                foreach (var item in st)
                                {
                                    sw.WriteLine(item);
                                }
                            }
                        }
                        if (obj.Attributes["memberOf"] != null)
                        {
                            var parentCount = ((System.Collections.CollectionBase) (obj.Attributes["memberOf"])).Count;
                            for (int i = 0; i < parentCount; i++)
                            {
                                string groupName = obj.Attributes["memberOf"][i].ToString();


                                if (groupName.Contains("OU=Groups"))
                                {
                                    //var attributes = obj.Attributes.AttributeNames;
                                    //string attributesstr = string.Empty;
                                    //foreach (var item in attributes)
                                    //{
                                    //    attributesstr = attributesstr + "," + item;
                                    //}
                                    _subGroupList.Add(groupName.ToString().Split('=')[1].Split(',')[0]);
                                    count_Parent = count_Parent + 1;
                                    GetParentGroups(groupName, count_Parent);
                                }
                            }
                        }
                    }
                }

            }

            private static ArrayList getNestedGroups(string strGroupDN)
            {


                SearchRequest searchRequest = new SearchRequest();
                searchRequest.DistinguishedName = strGroupDN;
                searchRequest.Filter = String.Format
                    ("(&(memberOf={0})(objectClass=group))", strGroupDN);

                if (strGroupDN.ToString().ToString().Split('=')[1].Split(',')[0].Equals("P-IN002-GMS_CC-G"))
                {

                }
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];

                }

                return groupMembers;
            }

            public static void GetLDAPNestedGroups(string item)
            {
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.DistinguishedName = item;
                searchRequest.Filter =
                    String.Format("(&(objectCategory=Group)(member:1.2.840.113556.1.4.1941:=CN={0}))",
                        item.ToString().Split('=')[1].Split(',')[0]);
                SearchResponse response =
                    (SearchResponse) ldap.SendRequest(searchRequest);
                if (response != null && response.Entries.Count > 0)
                {
                    SearchResultEntry obj = response.Entries[0];
                    var groupName = obj.Attributes["distinguishedName"][0].ToString();
                    ArrayList groupMembers = new ArrayList();
                    groupMembers = getNestedGroups(groupName);


                    if (groupMembers != null && groupMembers.Count > 0)
                    {
                        _subGroupList.AddRange(from object itemSubGroup in groupMembers
                            select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
                        List<string> localsubGroupList = new List<string>();
                        localsubGroupList.AddRange(from object itemSubGroup in groupMembers
                            select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
                        foreach (var itemSubGroups in localsubGroupList)
                        {
                            GetLDAPNestedGroups(itemSubGroups);
                        }
                    }



                }


            }

            public static void GetNestedGroups(string strGroupDN)
            {
                var _currentDomainofLoggedinUser = Domain.GetComputerDomain();

                var currentDomainofLoggedinUser = Domain.GetComputerDomain();
                var currentDomainController =
                    currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller

                var domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                string strPath = "LDAP://" + currentDomainController.Name; //Gets the current domain controller name
                //using (LdapConnection ldap = new LdapConnection(new LdapDirectoryIdentifier(domainName, 636)))
                {
                    //ldap.AuthType = AuthType.Basic;
                    //ldap.SessionOptions.SecureSocketLayer = false;
                    //NetworkCredential nc = new NetworkCredential(Environment.UserName,
                    //            "Ssy2689!", Environment.UserDomainName);

                    //var s = new SecureString();
                    //s.AppendChar('S');
                    //s.AppendChar('s');
                    //s.AppendChar('y');
                    //s.AppendChar('2');
                    //s.AppendChar('6');
                    //s.AppendChar('8');
                    //s.AppendChar('9');
                    //s.AppendChar('@');
                    //NetworkCredential network = new NetworkCredential(WindowsIdentity.GetCurrent().Name, s);

                    //string ldapSearchFilter = String.Format
                    //      ("(&(memberOf={0})(objectClass=group))", strGroupDN);
                    //NetworkCredential cred = CredentialCache.DefaultNetworkCredentials;
                    //ldap.Bind(network);

                    // create the AsqRequestControl object 
                    // and specify the attribute to query
                    //AsqRequestControl asqRequest =
                    //                        new AsqRequestControl("memberOf");

                    // add the AsqRequestControl object to 
                    // searchReuest directory control collection. 
                    //searchRequest.Controls.Add(asqRequest);
                    //var currentLoggedinUser = username.Split('\\');
                    //searchRequest.Filter = String.Format
                    //        ("(&(memberOf={0})(objectClass=group))", strGroupDN);
                    string[] attributesToReturn = new string[] {"distinguishedName"};
                    string ldapSearchFilter = String.Format
                        ("(&(memberOf={0})(objectClass=group))", strGroupDN);
                    SearchRequest searchRequest =
                        new SearchRequest(strGroupDN, ldapSearchFilter, SearchScope.Subtree, attributesToReturn);
                    searchRequest.DistinguishedName =
                        strGroupDN;
                    searchRequest.Filter = String.Format
                        ("(&(memberOf={0})(objectClass=group))", strGroupDN);
                    SearchResponse response =
                        (SearchResponse) ldap.SendRequest(searchRequest);
                    if (response != null && response.Entries.Count > 0)
                    {
                        SearchResultEntry obj = response.Entries[0];

                        var groupCount = ((System.Collections.CollectionBase) (obj.Attributes["member"])).Count;

                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            var groupName = entry.DistinguishedName;
                            _subGroupList.Add(groupName.ToString().Split('=')[1].Split(',')[0]);
                            GetNestedGroups(groupName);
                        }

                    }
                }
            }

            public static string GetCurrentGroup()
            {


                try
                {

                    NTAccount userAccount = new NTAccount("ad001.siemens.net", "RA010-U-PUN-CCGMS");
                    var sid = userAccount.Translate(typeof(SecurityIdentifier));

                    SearchRequest searchRequestDistinguishedName = new SearchRequest
                    {
                        Scope = SearchScope.Subtree,
                        Filter = string.Format(CultureInfo.CurrentCulture, "(&(objectCategory=Group)(objectsid={0}))",
                            sid)
                    };

                    SearchOptionsControl searchOptions = new SearchOptionsControl(SearchOption.DomainScope);
                    if (searchRequestDistinguishedName.Controls != null)
                        searchRequestDistinguishedName.Controls.Add(searchOptions);
                    string distinguishedName = string.Empty;
                    SearchResponse responseToGetDistinguishedName =
                        (SearchResponse) ldap.SendRequest(searchRequestDistinguishedName);
                    if (responseToGetDistinguishedName != null)
                    {
                        var obj = responseToGetDistinguishedName.Entries[0];
                        distinguishedName = obj.Attributes["distinguishedName"][0].ToString();
                    }
                    return distinguishedName;
                }
                catch (Exception ex)
                {
                    // ContextITrace.Interface.Trace4("1", ePrio.Deb, String.Format(CultureInfo.InvariantCulture, "CoHoDirectoryServiceIntegration:GetCurrentUser  cannot establish a connection {0}.", PvssMgrException.ToString(ex)));
                    throw;
                }
            }

            public static LdapConnection GetLDAPConnection(string currentDomainOfALoggedinUser, int DefaultPort)
            {
                return new LdapConnection(new LdapDirectoryIdentifier(currentDomainOfALoggedinUser, DefaultPort));
            }

            public static string GetCurrentUser(LdapConnection ldap, string currentDomainOfALoggedinUser)
            {

                NTAccount userAccount = new NTAccount(currentDomainOfALoggedinUser, Environment.UserName);
                var sid = userAccount.Translate(typeof(SecurityIdentifier));

                SearchRequest searchRequestDistinguishedName = new SearchRequest
                {
                    Scope = SearchScope.Subtree,
                    Filter = string.Format("(&(objectClass=user)(objectsid={0}))", sid)
                };

                SearchOptionsControl searchOptions =
                    new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.PhantomRoot);
                searchRequestDistinguishedName.Controls.Add(searchOptions);
                string distinguishedName = string.Empty;
                SearchResponse responseToGetDistinguishedName =
                    (SearchResponse) ldap.SendRequest(searchRequestDistinguishedName);
                SearchResultEntry obj = null;
                if (responseToGetDistinguishedName != null)
                {
                    obj = responseToGetDistinguishedName.Entries[0];
                    distinguishedName = obj.Attributes["distinguishedName"][0].ToString();
                }
                return distinguishedName;
            }

            public static NetworkCredential GetNetworkCredentials()
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

                NetworkCredential network = new NetworkCredential(WindowsIdentity.GetCurrent().Name, s);
                NetworkCredential cred = CredentialCache.DefaultNetworkCredentials;
                return network;
            }

            public static void GetGroupsUsingLDAP()
            {
                var _currentDomainofLoggedinUser = Domain.GetComputerDomain();
                var currentDomainofLoggedinUser = Domain.GetComputerDomain();
                var currentDomainController =
                    currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller
                var currentDomainOfALoggedinUser =
                    ((System.DirectoryServices.ActiveDirectory.ActiveDirectoryPartition) (Domain.GetComputerDomain()))
                    .Name;
                string strPath = "LDAP://" + currentDomainController.Name; //Gets the current domain controller name
                AppDomain.CurrentDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
                int DefaultPort = 636;
                string t = Environment.UserName;
                ldapForD = new LdapConnection(new LdapDirectoryIdentifier(currentDomainOfALoggedinUser, DefaultPort));
                {
                    NTAccount userAccount = new NTAccount(currentDomainOfALoggedinUser, Environment.UserName);
                    var sid = userAccount.Translate(typeof(SecurityIdentifier));

                    SearchRequest searchRequestDistinguishedName = new SearchRequest
                    {
                        Scope = SearchScope.Subtree,
                        Filter = string.Format("(&(objectClass=user)(objectsid={0}))", sid)
                    };

                    SearchOptionsControl searchOptions =
                        new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.PhantomRoot);
                    searchRequestDistinguishedName.Controls.Add(searchOptions);
                    string distinguishedName;
                    SearchResponse responseToGetDistinguishedName =
                        (SearchResponse) ldapForD.SendRequest(searchRequestDistinguishedName);
                    SearchResultEntry obj = null;
                    if (responseToGetDistinguishedName != null)
                    {
                        obj = responseToGetDistinguishedName.Entries[0];
                        distinguishedName = obj.Attributes["distinguishedName"][0].ToString();
                    }
                    ldap = new LdapConnection(new LdapDirectoryIdentifier(currentDomainOfALoggedinUser, DefaultPort));
                    ldap.AuthType = AuthType.Basic;
                    ldap.SessionOptions.SecureSocketLayer = false;
                    //NetworkCredential nc = new NetworkCredential(Environment.UserName,
                    //            "Ssy2689!", Environment.UserDomainName);
                    //ldap.SessionOptions.SecureSocketLayer = true;
                    //ldap.SessionOptions.ProtocolVersion = 3;
                    //ldap.SessionOptions.VerifyServerCertificate =
                    //      (con, cer) => true;
                    //  networkCredential.Domain = currentDomainofLoggedinUser.ToString();

                    //   string username = WindowsIdentity.GetCurrent().Name;
                    //      var currentLoggedinUser = username.Split('\\');
                    //      networkCredential.UserName = username;
                    // l

                    var s = new SecureString();
                    s.AppendChar('S');
                    s.AppendChar('i');
                    s.AppendChar('m');
                    s.AppendChar('e');
                    s.AppendChar('n');
                    s.AppendChar('s');
                    s.AppendChar('_');
                    s.AppendChar('2');
                    s.AppendChar('0');
                    s.AppendChar('1');
                    s.AppendChar('9');
                    NetworkCredential network = new NetworkCredential(WindowsIdentity.GetCurrent().Name, s);

                    NetworkCredential cred = CredentialCache.DefaultNetworkCredentials;
                    ldap.Bind(network);

                    string targetOU = obj.Attributes["distinguishedName"][0].ToString();
                    ;
                    string username = WindowsIdentity.GetCurrent().Name;
                    var currentLoggedinUser = username.Split('\\');
                    //string ldapSearchFilter =String.Format("(&(member:1.2.840.113556.1.4.1941:={0}))",targetOU);

                    string ldapSearchFilter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName=" +
                                              currentLoggedinUser[1] + "))";
                    SearchRequest searchRequest =
                        new SearchRequest(targetOU, ldapSearchFilter, SearchScope.Subtree, null);
                    //Async Result for tomorrows work   
                    IAsyncResult asyncResult = ldap.BeginSendRequest(
                        searchRequest,
                        PartialResultProcessing.ReturnPartialResultsAndNotifyCallback,
                        RunAsyncSearch,
                        "abc");
                    SearchResponse response =
                        (SearchResponse) ldap.SendRequest(searchRequest);
                    List<string> GroupData = new List<string>();

                    var groupData = string.Empty;

                }




            }

            public static string GetCurrentLoggedInUse()
            {
                string username = WindowsIdentity.GetCurrent().Name;
                var currentLoggedinUser = username.Split('\\');
                return currentLoggedinUser[1];
            }

            private static void RunAsyncSearch(IAsyncResult asyncResult)
            {
                Console.WriteLine("Asynchronous search operation called.");

                if (!asyncResult.IsCompleted)
                {
                    Console.WriteLine("Getting a partial result");
                    PartialResultsCollection result = null;

                    try
                    {
                        result = ldap.GetPartialResults(asyncResult);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                    if (result != null)
                    {
                        for (int i = 0; i < result.Count; i++)
                        {
                            if (result[i] is SearchResultEntry)
                            {
                                Console.WriteLine("A changed just occured to: {0}",
                                    ((SearchResultEntry) result[i]).DistinguishedName);
                            }
                        }
                    }
                    else
                        Console.WriteLine("Search result is null");
                }
                else
                {
                    Console.WriteLine("The search operation has been completed.");
                    try
                    {
                        // end the send request search operation
                        SearchResponse response =
                            (SearchResponse) ldap.EndSendRequest(asyncResult);

                        List<string> GroupData = new List<string>();
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
                                // GetChildGroups(groupData, 0);
                                // GetParentGroups(groupData, 0);
                                //GetLDAPNestedGroups(groupData);
                            }

                            //var attributes = response.Entries[0].Attributes["memberOf"].ToString();
                            //var groups = a["memberOf"].GetValues(Type.GetType("System.Byte[]"));
                            //for (int i = 0; i < groups.Length; i++)
                            //{
                            //   var t= ByteArrayToString((byte[])groups[i]);
                            //}
                            //if (a.AttributeNames != null)
                            //    foreach (var t in a.AttributeNames)
                            //    {
                            //        Console.WriteLine(t.ToString());
                            //    }
                        }
                        GroupData.AddRange(_subGroupList);
                        GroupData = GroupData.Distinct().OrderBy(x => x).ToList();
                        //FileStream ostrm;
                        //StreamWriter writer;
                        //TextWriter oldOut = Console.Out;
                        //try
                        //{
                        //    ostrm = new FileStream("D:/Redirect.txt", FileMode.OpenOrCreate, FileAccess.Write);
                        //    writer = new StreamWriter(ostrm);
                        //}
                        //catch (Exception e)
                        //{
                        //    Console.WriteLine("Cannot open Redirect.txt for writing");
                        //    Console.WriteLine(e.Message);
                        //    return;
                        //}
                        //Console.SetOut(writer);
                        foreach (var item in GroupData)
                        {

                            Console.WriteLine(item);
                        }
                        //writer.Close();
                        //ostrm.Close();
                    }
                    // in case of some directory operation exception
                    // return whatever data has been processed
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

            public static ArrayList groupMembers { get; set; }

            public static LdapConnection ldapForD { get; set; }
        }
    }


