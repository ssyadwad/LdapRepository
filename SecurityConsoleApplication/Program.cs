using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecurityConsoleApplication
{
    public class Program
    {
        static Hashtable searchedGroups = null;
        private static ArrayList getUsersInGroup(string strGroupDN)
        {
            ArrayList groupMembers = new ArrayList();
            searchedGroups.Add(strGroupDN, strGroupDN);

            // find all users in this group
            DirectorySearcher ds = new DirectorySearcher("LDAP://DC=company,DC=com");
            ds.Filter = String.Format
                        ("(&(memberOf={0})(objectClass=person))", strGroupDN);

            ds.PropertiesToLoad.Add("distinguishedName");
            ds.PropertiesToLoad.Add("givenname");
            ds.PropertiesToLoad.Add("samaccountname");
            ds.PropertiesToLoad.Add("sn");

            foreach (SearchResult sr in ds.FindAll())
            {
                groupMembers.Add(sr.Properties["samaccountname"][0].ToString());
            }

            // get nested groups
            ArrayList al = getNestedGroups(strGroupDN);
            foreach (object g in al)
            {
                // only if we haven't searched this group before - avoid endless loops
                if (!searchedGroups.ContainsKey(g))
                {
                    // get members in nested group
                    ArrayList ml = getUsersInGroup(g as string);
                    // add them to result list
                    foreach (object s in ml)
                    {
                        groupMembers.Add(s as string);
                    }
                }
            }

            return groupMembers;
        }

        
        static public int DisplayMenu()
        {
            string ldapUser =
                @"CN = Joshi\, Akshay,OU = Pune,OU = APAC,OU = Users,OU = _Central,OU = RA026,DC = ad001,DC = siemens,DC = net";
            String.Format(CultureInfo.InvariantCulture,
                @"(&(objectClass=person)(CN={0}))",
                ldapUser.Split('=')[1].Split(',')[0].Replace(@"\", string.Empty));

            Console.WriteLine("LDAP Prototype");
            Console.WriteLine();
            Console.WriteLine("1. Connect to active directory using LDAP Class");
            Console.WriteLine("2. Connect to active directory using Directory Entry Class");
            Console.WriteLine("3. Exit");
            var result = Console.ReadLine();
            Console.WriteLine("LDAP Special Characters");
            Console.WriteLine();
            LdapHelper.LdapQuery= Console.ReadLine();
            return Convert.ToInt32(result);
        }

        internal class User
        {
            internal int id { get; set; }
            internal string userName { get; set; }
        }
        public class GenericPropertyFinder<TModel> where TModel : class
        {
            public void PrintTModelPropertyAndValue(TModel tmodelObj)
            {
                //Getting Type of Generic Class Model
                Type tModelType = tmodelObj.GetType();

                //We will be defining a PropertyInfo Object which contains details about the class property 
                PropertyInfo[] arrayPropertyInfos = tModelType.GetProperties();

                //Now we will loop in all properties one by one to get value
                foreach (PropertyInfo property in arrayPropertyInfos)
                {
                    Console.WriteLine("Name of Property is\t:\t" + property.Name);
                    Console.WriteLine("Value of Property is\t:\t" + property.GetValue(tmodelObj).ToString());
                    Console.WriteLine(Environment.NewLine);
                }
            }
        }

        public class FlexClientProfile
        {
             public string Name;
             public string Profile;
        }
        private static void Main(string[] args)
        {
            int result = 0;
            List<FlexClientProfile> flex = new List<FlexClientProfile>()
            {
                
            };
            string name = flex.Where(x => x.Name == "abcd1").Select(x => x.Name).FirstOrDefault();
            do
            {
               var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                machineStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
               var machineCerts = machineStore.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, "CN=Desigo CC ClientCer", false);
               var cntMachineCerts = machineCerts.Count;


                foreach (X509Certificate2 cert in machineCerts)
                {
                    //we are only interested in certificates that have a private key assigned
                    if (cert.HasPrivateKey)
                    {
                       // RSACng rsa =new  RSACng();
                    }
                }
                User u=new User()
                {
                    id=1,userName = "sagar"
                };
                var propertyInfo = u.GetType().GetProperty("userName",BindingFlags.NonPublic | BindingFlags.Instance);
                var propertyInfo1 = u.GetType().GetProperty("id", BindingFlags.NonPublic | BindingFlags.Instance);
                if (propertyInfo != null)
                {
                   var b= propertyInfo.GetValue(u);
                    var a1 = propertyInfo1.GetValue(u);
                    GenericPropertyFinder<User> a=new GenericPropertyFinder<User>();
                    a.PrintTModelPropertyAndValue(u);
                    if (propertyInfo != null)
                    {
                        var o = propertyInfo.GetValue(u, null);
                    }
                }
                Console.Clear();
                var listGroups = new List<string>();
                string[] stringArray = { "text1", "text2", "text3", "text4" };
                string value = "text6";
                int pos = Array.IndexOf(stringArray, value);
                if (pos > -1)
                {
                    // the array contains the string and the pos variable
                    // will have its position in the array
                }
                int userInput = 0;
            
                //do
                //{

                userInput = DisplayMenu();
                switch (userInput)
                {
                    case 1: LDAP ldap = new LDAP();
                    
                        ldap.GetGroupsForCurrentUser();
                      
                        break;
                    case 2: listGroups = LDAPDirectoryEntry.GetGroupsForUser();
                        break;
                }

                //} while (userInput != 3);


                //listGroups = TokenGroups.GetGroupsForCurrentLoggedinUser();
                //listGroups= NestedGroups.GetGroupsForCurrentLoggedinUser();
                //listGroups = LDAPDirectoryEntry.GetGroupsForUser();
                //    //listGroups = GetGroupsForCurrentLoggedinUser();
                //LDAP ldap = new LDAP();
                //ldap.GetGroupsForCurrentUser();

                //LdapHelper.GetGroupsUsingLDAP();

                if(result==2)
                Console.WriteLine("\n");
                foreach (var listGroup in listGroups)
                {
                    Console.WriteLine(listGroup);

                }
                
                result = Convert.ToInt32(Console.ReadLine());
             
            } while (result != 3);
            //LdapHelper.GetLDAPConnection();
        }
        private static ArrayList getNestedGroups(string strGroupDN)
        {
            ArrayList groupMembers = new ArrayList();

            // find all nested groups in this group
            DirectorySearcher ds = new DirectorySearcher("LDAP://DC=company,DC=com");
            ds.Filter = String.Format
                        ("(&(memberOf={0})(objectClass=group))", strGroupDN);

            ds.PropertiesToLoad.Add("distinguishedName");

            foreach (SearchResult sr in ds.FindAll())
            {
                groupMembers.Add(sr.Properties["distinguishedName"][0].ToString());
            }

            return groupMembers;
        }
        public static List<string> GetGroupsForCurrentLoggedinUser()
        {
            Console.WriteLine("Groups under the current logged in user :- ");
            Console.Write("\n");
            string username = WindowsIdentity.GetCurrent().Name; //Gets the current logged in user

            var currentDomainofLoggedinUser = Domain.GetComputerDomain();
            var currentDomainController = currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller

            string strPath = "LDAP://" + currentDomainController.Name; //Gets the current domain controller name
            var currentLoggedinUser = username.Split('\\');
            var currentDirectoryEntry = new DirectoryEntry(strPath);
            var search = new DirectorySearcher(currentDirectoryEntry);
            search.Filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName=" + currentLoggedinUser[1] + "))";
            //search.Filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName=z003kkvy))";
            search.PropertiesToLoad.Add("sAMAccountName");
            search.PropertiesToLoad.Add("mail");
            search.PropertiesToLoad.Add("group");
            search.PropertiesToLoad.Add("displayname"); //first name
            search.PropertiesToLoad.Add("groupType");
   
            //SearchResultCollection resultCol = search.FindAll();
            var userSearchResult = search.FindOne();
            var groupData = new List<string>();
            var userGroups = new List<string>();
            IEnumerable lst;
            IEnumerable<string> distinctList = new List<string>();

            if (userSearchResult != null)
            {
                DirectoryEntry obUser = new DirectoryEntry(userSearchResult.Path);


                //var searchGroups = new DirectorySearcher(obUser);
                //searchGroups.Filter = "(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648))";
                //var result = searchGroups.FindAll();
                //// Invoke Groups method.
                //object obGroups = obUser.Invoke("Groups");
                //foreach (object ob in (IEnumerable)obGroups)
                //{
                //    // Create object for each group.
                //    DirectoryEntry obGpEntry = new DirectoryEntry(ob);
                //    userGroups.Add(obGpEntry.Name);
                //    return userGroups.ToList();
                //}

                //Token Groups Logic../////
                //using (DirectoryEntry user = userSearchResult.GetDirectoryEntry())
                //{
                //   string a= (string)user.Properties["distinguishedName"].Value; 
                    
                //    user.RefreshCache(new string[] { "tokenGroups" });
                //    user.RefreshCache(new string[] { "grouptype" });
                    
                //    for (int i = 0; i < user.Properties["tokenGroups"].Count; i++)
                //    {
                //        SecurityIdentifier sid = new SecurityIdentifier((byte[])user.Properties["tokenGroups"][i], 0);
                   
                //        NTAccount nt = (NTAccount)sid.Translate(typeof(NTAccount));
                //        //do something with the SID or name (nt.Value)
                     
                //        if (nt.Value.IndexOf('\\') > -1)
                //            userGroups.Add(nt.Value.Split('\\')[1]);
                //        else
                //            userGroups.Add(nt.Value);
                //    }
                //}
                //IEnumerable<string> list = userGroups.ToList();
                // distinctList = list.GroupBy(x => x)
                //         .Select(g => g.First())
                //         .ToList();




                //MemerOfLogic
                using (var groupsDirectoryEntry = new DirectoryEntry(userSearchResult.Path))
                {
                    //foreach (var item in groupsDirectoryEntry.Properties.PropertyNames)
                    //{
                    //    Console.WriteLine(item+"--->"+groupsDirectoryEntry.Properties[item.ToString()].Count);
                    //}

                    if (groupsDirectoryEntry.Properties["memberOf"].Value != null)
                    {
                        lst = (IEnumerable)groupsDirectoryEntry.Properties["memberOf"].Value;

                       

                        groupData.AddRange(from object child in (IEnumerable)groupsDirectoryEntry.Properties["memberOf"].Value select child.ToString().Split('=')[1].Split(',')[0]);
                    }
                    //foreach (var item in groupData)
                    //{
                    //    DataTable dt = new DataTable(item);
                    //    searchedGroups = new Hashtable();
                    //    search.Filter = string.Format("(&(objectCategory=Group)(CN={0}))", item);
                    //    SearchResult result = search.FindOne();
                    //   var group = result.GetDirectoryEntry();

                    //  var  groupMembers = getUsersInGroup
                    //                  (group.Properties["distinguishedName"].Value.ToString());
                    //    object members = result.GetDirectoryEntry().Invoke("Members", null);
                    //    //<<< Get members

                    //    //<<< loop through members
                    //    foreach (object member in (IEnumerable)members)
                    //    {
                    //        DirectoryEntry currentMember = new DirectoryEntry(member);
                    //        //<<< Get directoryentry for user
                    //        if (currentMember.SchemaClassName.ToLower() == "user")
                    //        {
                    //            System.DirectoryServices.PropertyCollection props1 = currentMember.Properties;
                    //            var t = props1["MemberOf"].Value;
                    //            //dt.Rows.Add(props1["sAMAccountName"].Value, props1["givenName"].Value, props1["sn"].Value, props1["displayName"].Value, props1["mail"].Value, Convert.ToBoolean(currentMember.InvokeGet("AccountDisabled")), "");
                    //        }
                    //        else if (currentMember.SchemaClassName.ToLower() == "group")
                    //        {
                    //            System.DirectoryServices.PropertyCollection props1 = currentMember.Properties;
                    //            //foreach (var group in result.Properties["member"])
                    //            //{
                    //            //dt.Rows.Add("", "", "", "", "", false, props1["name"].Value);
                    //            //}
                    //        }
                    //    }
                        
                    //}
                    return groupData;
                }




                ////Member Logic
                //using (var groupsDirectoryEntry = new DirectoryEntry(userSearchResult.Path))
                //{
                //    //foreach (var item in groupsDirectoryEntry.Properties.PropertyNames)
                //    //{
                //    //    Console.WriteLine(item+"--->"+groupsDirectoryEntry.Properties[item.ToString()].Count);
                //    //}

                //    if (groupsDirectoryEntry.Properties["member"].Value != null)
                //    {
                //        lst = (IEnumerable)groupsDirectoryEntry.Properties["member"].Value;



                //        groupData.AddRange(from object child in (IEnumerable)groupsDirectoryEntry.Properties["member"].Value select child.ToString().Split('=')[1].Split(',')[0]);
                //    }
                //    return groupData;
                //}
                ////
                
                using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain))
                {
                    // find a user
                    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, currentLoggedinUser[1]);
                    List<string> obj=new List<string>();
                    List<string> a=new List<string>();
                    if (user != null)
                    {
                        
                        // get the user's groups
                        var groups = user.GetAuthorizationGroups();
                        var Groups = user.GetGroups();
                        foreach (GroupPrincipal group in groups)
                        {
                         if(group.IsSecurityGroup==true)
                            obj.Add(group.Name);
                            // do whatever you need to do with those groups
                        }

                        foreach (GroupPrincipal g in Groups)
                        {a.Add(g.Name);
                            
                        }
                        return obj;
                    }

                }
            }
            return distinctList.ToList();
        } 
    }
}
