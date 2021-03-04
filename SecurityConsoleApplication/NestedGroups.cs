using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SecurityConsoleApplication
{
   public class NestedGroups
    {

       


    
        static Hashtable searchedGroups = null;
    public   static List<string> _subGroupList=new List<string>();
       static List<string> _subGroupListParents = new List<string>();
       static List<string> _DisplayNamelist = new List<string>();
       static Dictionary<string, string> _dictionary = new Dictionary<string, string>();
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
       
        private static ArrayList getNestedGroups(string strGroupDN)
        {
            ArrayList groupMembers = new ArrayList();
            string username = WindowsIdentity.GetCurrent().Name; //Gets the current logged in user

            var currentDomainofLoggedinUser = Domain.GetComputerDomain();
            var currentDomainController = currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller

            string strPath = "LDAP://" + currentDomainController.Name; //Gets the current domain controller name
            var currentLoggedinUser = username.Split('\\');
            var currentDirectoryEntry = new DirectoryEntry(strPath);
            var search = new DirectorySearcher(currentDirectoryEntry);
            // find all nested groups in this group
            //DirectorySearcher ds = new DirectorySearcher("LDAP://DC=company,DC=com");
            search.Filter = String.Format
                        ("(&(memberOf={0})(objectClass=group))", strGroupDN);

            search.PropertiesToLoad.Add("distinguishedName");

            foreach (SearchResult sr in search.FindAll())
            {
                groupMembers.Add(sr.Properties["distinguishedName"][0].ToString());
            }

            return groupMembers;
        }

        public static void GetNestedGroupsForParents(string item)
        {
            //string username = WindowsIdentity.GetCurrent().Name; //Gets the current logged in user

            //var currentDomainofLoggedinUser = Domain.GetComputerDomain();
            //var currentDomainController = currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller

            //string strPath = "LDAP://" + currentDomainController.Name; //Gets the current domain controller name
            //var currentLoggedinUser = username.Split('\\');
            //var currentDirectoryEntry = new DirectoryEntry(strPath);
       var search=currentDirectorySearcher;
            search.Filter = string.Format("(&(objectCategory=Group)(CN={0}))", item);
            SearchResult result = search.FindOne();
            var group = result.GetDirectoryEntry();
            
                if (!_dictionary.ContainsKey(item.ToString()))
                {
                    if (group.Properties["displayName"].Value != null)
                    {
                        _dictionary.Add(item, group.Properties["displayName"].Value.ToString());
                    }
                    else
                    {
                        _dictionary.Add(item, group.Properties["name"].Value.ToString());
                    }
                    
                }
            
            
            //var groupMembers = getNestedGroups
            //                (group.Properties["distinguishedName"].Value.ToString());
            ArrayList groupMembers = new ArrayList();

            if (group.Properties["memberOf"] != null && group.Properties["memberOf"].Count > 0)
            {
                if (group.Properties["memberOf"].Value is string)
                {
                    if (group.Properties["memberOf"].Value.ToString().Contains("OU=Groups"))
                    {
                        var currentGroup = GetCurrentGroup(group.Properties["memberOf"].Value.ToString().Split('=')[1].Split(',')[0]);
                        if (group.Properties["displayName"].Value != null)
                        {
                            string groupName = group.Properties["memberOf"].Value.ToString().Split('=')[1].Split(',')[0];
                            if (!_dictionary.ContainsKey(groupName))
                            {
                                _dictionary.Add(groupName, group.Properties["displayName"].Value.ToString());
                            }
                        }
                                    groupMembers.Add(group.Properties["memberOf"].Value);
                    }
                }
                else
                {
                    Array ItemParent = (Array)group.Properties["memberOf"].Value;

                    for (int i = 0; i < group.Properties["memberOf"].Count; i++)
                    {
                        string itemParentGroups = ItemParent.GetValue(i).ToString();
                        if (itemParentGroups.Contains("OU=Groups"))
                        {

                            var currentGroup = GetCurrentGroup(itemParentGroups.ToString().Split('=')[1].Split(',')[0]);
                            if (group.Properties["displayName"].Value != null)
                            {
                                string groupName = itemParentGroups.ToString().Split('=')[1].Split(',')[0];
                                if (!_dictionary.ContainsKey(groupName))
                                {
                                    _dictionary.Add(groupName, group.Properties["displayName"].Value.ToString());
                                }
                            }
                                        groupMembers.Add(itemParentGroups);
                        }
                    }
                }


            }
            if (groupMembers != null && groupMembers.Count > 0)
            {
                _subGroupList.AddRange(from object itemSubGroup in groupMembers select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
            }
            List<string> localsubGroupList = new List<string>();
            localsubGroupList.AddRange(from object itemSubGroup in groupMembers select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
            foreach (var itemSubGroups in localsubGroupList)
            {
                GetNestedGroupsForParents(itemSubGroups);
            }
        }
        public static DirectoryEntry GetCurrentGroup(string item)
        {

            var search = currentDirectorySearcher;
            search.Filter = string.Format("(&(objectCategory=Group)(CN={0}))", item);
            SearchResult resultCurrentGroup = search.FindOne();
            var currentGroup = resultCurrentGroup.GetDirectoryEntry();
            return currentGroup;
        }
       public static void GetNestedGroupsForChildren(string item){
       //{
       //    string username = WindowsIdentity.GetCurrent().Name; //Gets the current logged in user

       //    var currentDomainofLoggedinUser = Domain.GetComputerDomain();
       //    var currentDomainController = currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller

       //    string strPath = "LDAP://" + currentDomainController.Name; //Gets the current domain controller name
       //    var currentLoggedinUser = username.Split('\\');
           //var currentDirectoryEntry = new DirectoryEntry(strPath);
           //var search = new DirectorySearcher(currentDirectoryEntry);
           
           var search=currentDirectorySearcher;
           search.Filter = string.Format("(&(objectCategory=Group)(CN={0}))", item);
           search.PropertiesToLoad.Add("displayName");
           SearchResult result = search.FindOne();
           var group = result.GetDirectoryEntry();
           if (!_dictionary.ContainsKey(item.ToString()))
           {
               if (group.Properties["displayName"].Value != null)
               {
                   _dictionary.Add(item, group.Properties["displayName"].Value.ToString());
               }
               else
               {
                   _dictionary.Add(item, group.Properties["name"].Value.ToString());
               }

           }
           //var groupMembers = getNestedGroups
           //                (group.Properties["distinguishedName"].Value.ToString());
            ArrayList groupMembers=new ArrayList();
            if (group.Properties["member"] != null && group.Properties["member"].Count > 0)
            {
                if (group.Properties["member"].Value is string)
                {
                    if (group.Properties["member"].Value.ToString().Contains("OU=Groups"))
                    {
                        var currentGroup = GetCurrentGroup(group.Properties["member"].Value.ToString().Split('=')[1].Split(',')[0]);
                        if (group.Properties["displayName"].Value != null)
                        {
                            string groupName = group.Properties["member"].Value.ToString().Split('=')[1].Split(',')[0];
                            if (!_dictionary.ContainsKey(groupName))
                            {
                                _dictionary.Add(groupName, group.Properties["displayName"].Value.ToString());
                            }
                        }
                               
                        groupMembers.Add(group.Properties["member"].Value);
                        
                       
                    }
                }
                else
                {
                    Array ItemChildren = (Array)group.Properties["member"].Value;

                    for (int i = 0; i < group.Properties["member"].Count; i++)
                    {
                        string itemChildGroups = ItemChildren.GetValue(i).ToString();
                        if (itemChildGroups.Contains("OU=Groups"))
                        {
                            var currentGroup=GetCurrentGroup(itemChildGroups.ToString().Split('=')[1].Split(',')[0]);
                            if (group.Properties["displayName"].Value != null)
                            {
                                string groupName = itemChildGroups.ToString().Split('=')[1].Split(',')[0];
                                if (!_dictionary.ContainsKey(groupName))
                                {
                                    _dictionary.Add(groupName, group.Properties["displayName"].Value.ToString());
                                }
                            }
                            groupMembers.Add(itemChildGroups);
                            
                            
                        }
                    }
                }
            }
            //if (group.Properties["memberOf"] != null && group.Properties["memberOf"].Count > 0)
            //{
            //    if (group.Properties["memberOf"].Value is string)
            //    {
            //        if (group.Properties["memberOf"].Value.ToString().Contains("OU=Groups"))
            //        {
            //            groupMembers.Add(group.Properties["memberOf"].Value);
            //        }
            //    }
            //    else
            //    {
            //        Array ItemParent = (Array)group.Properties["memberOf"].Value;

            //        for (int i = 0; i < group.Properties["memberOf"].Count; i++)
            //        {
            //            string itemParentGroups = ItemParent.GetValue(i).ToString();
            //            if (itemParentGroups.Contains("OU=Groups"))
            //            {
            //                groupMembers.Add(itemParentGroups);
            //            }
            //        }
            //    }


            //}
           if (groupMembers!=null && groupMembers.Count > 0)
           {
               _subGroupList.AddRange(from object itemSubGroup in groupMembers select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
           }
           List<string> localsubGroupList=new List<string>();
           localsubGroupList.AddRange(from object itemSubGroup in groupMembers select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
           foreach (var itemSubGroups in localsubGroupList)
           {
               GetNestedGroupsForChildren(itemSubGroups);
           }
       }
       public static DirectorySearcher GetDirectorySeracher(DirectoryEntry currentDirectoryEntry){
           return new DirectorySearcher(currentDirectoryEntry);

       }
       public static DirectoryEntry ConnectToActiveDirectoryServer(string strPath){

           return new DirectoryEntry(strPath);
       }
       public static  string currentLoggedInUser{
           get{
               return WindowsIdentity.GetCurrent().Name;
           }
       }
       public static System.DirectoryServices.ActiveDirectory.Domain GetCompterDomain{
           get{
               return Domain.GetComputerDomain();
           }
       }
       public static string currentDomainController{
           get{
               return Domain.GetComputerDomain().FindDomainController().Name;
           }
       }
       public const string LDAP="LDAP://";


       public static string GetActiveDirectoryPath()
       {
           var currentDomainofLoggedinUser = GetCompterDomain;
           var currentDomainController = currentDomainofLoggedinUser.FindDomainController(); //Gets the current Domain controller

           string strPath = LDAP + currentDomainController; //Gets the current domain controller name
           return strPath;
       }
       public static SearchResult GetCurrentlyLoggedinUser()
       {
           Console.WriteLine("Groups under the current logged in user :- ");
           Console.Write("\n");


           string username = currentLoggedInUser; //Gets the current logged in user

           string strPath = GetActiveDirectoryPath();
           var currentLoggedinUser = username.Split('\\');
           var currentDirectoryEntry = ConnectToActiveDirectoryServer(strPath);
           var search = GetDirectorySeracher(currentDirectoryEntry);

           //search.Filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName=" + currentLoggedinUser[1] + "))";
           search.Filter = string.Format(query_GetUser_ActiveDirectory, currentLoggedinUser[1]);
           //search.Filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName=z003kkvy))";
           search.PropertiesToLoad.Add("sAMAccountName");
           search.PropertiesToLoad.Add("mail");
           search.PropertiesToLoad.Add("group");
           search.PropertiesToLoad.Add("displayname"); //first name
           search.PropertiesToLoad.Add("groupType");
           currentDirectorySearcher = search;
           //SearchResultCollection resultCol = search.FindAll();
           var userSearchResult = search.FindOne();
           return userSearchResult;

       }
      
       public static List<string> GetParentGroups(SearchResult userSearchResult)
       {
           var groupData = new List<string>();
           var subGroupList = new List<string>();
           var subSubGroupList = new List<string>();
           var userGroups = new List<string>();
           IEnumerable lst;
           IEnumerable<string> distinctList = new List<string>();
           using (var groupsDirectoryEntry = ConnectToActiveDirectoryServer(userSearchResult.Path))
           {
               //foreach (var item in groupsDirectoryEntry.Properties.PropertyNames)
               //{
               //    Console.WriteLine(item+"--->"+groupsDirectoryEntry.Properties[item.ToString()].Count);
               //}

               if (groupsDirectoryEntry.Properties["memberOf"].Value != null)
               {
                   lst = (IEnumerable)groupsDirectoryEntry.Properties["memberOf"].Value;

                   var rr = (IEnumerable)groupsDirectoryEntry.Properties["distinguishedName"].Value;

                   groupData.AddRange(from object child in (IEnumerable)groupsDirectoryEntry.Properties["memberOf"].Value select child.ToString().Split('=')[1].Split(',')[0]);
               }
           }
           return groupData;

       }
       public static void GetNestedSubgroups(List<string> groupData)
       {
           foreach (var item in groupData)
           {
               GetNestedGroupsForChildren(item);
               GetNestedGroupsForParents(item);
           }
       }
       public static DirectorySearcher currentDirectorySearcher=null ;
public const string query_GetUser_ActiveDirectory="(&(objectClass=user)(objectCategory=person)(sAMAccountName={0}))";

        public static List<string> GetGroupsForCurrentLoggedinUser()
        {
           
           

            if (GetCurrentlyLoggedinUser() != null)
            {

                var userSearchResult = GetCurrentlyLoggedinUser();

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

                List<string> parentGroups = GetParentGroups(userSearchResult);
                    //foreach (var item in groupData)
                    //{
                    //    searchedGroups = new Hashtable();
                    //    search.Filter = string.Format("(&(objectCategory=Group)(CN={0}))", item);

                    //    SearchResult result = search.FindOne();
                    //    var group = result.GetDirectoryEntry();
                    //}
                    
                    //foreach (var item in subGroupList)
                    //{
                    //    DataTable dt = new DataTable(item);
                    //    searchedGroups = new Hashtable();
                    //    search.Filter = string.Format("(&(objectCategory=Group)(CN={0}))", item);
                    //    SearchResult result = search.FindOne();
                    //    var group = result.GetDirectoryEntry();

                    //    var groupMembers = getNestedGroups
                    //                    (group.Properties["distinguishedName"].Value.ToString());
                    //    if (groupMembers.Count > 0)
                    //    {
                    //        subSubGroupList.AddRange(from object itemSubGroup in groupMembers select itemSubGroup.ToString().Split('=')[1].Split(',')[0]);
                    //    }

                    ////}
                    //subGroupList.AddRange(subSubGroupList);
                GetNestedSubgroups(parentGroups);
                parentGroups.AddRange(_subGroupList);
                parentGroups = parentGroups.Distinct().OrderBy(x => x).ToList();
                return parentGroups;
                




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
                
                //using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain))
                //{
                //    // find a user
                //    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, currentLoggedinUser[1]);
                //    List<string> obj=new List<string>();
                //    List<string> a=new List<string>();
                //    if (user != null)
                //    {
                        
                //        // get the user's groups
                //        var groups = user.GetAuthorizationGroups();
                //        var Groups = user.GetGroups();
                //        foreach (GroupPrincipal group in groups)
                //        {
                //         if(group.IsSecurityGroup==true)
                //            obj.Add(group.Name);
                //            // do whatever you need to do with those groups
                //        }

                //        foreach (GroupPrincipal g in Groups)
                //        {a.Add(g.Name);
                            
                //        }
                //        return obj;
                //    }

                //}
            }
            return new List<string>();
            //return distinctList.ToList();
        }

        public static string groupMembers { get; set; }
    }



}
