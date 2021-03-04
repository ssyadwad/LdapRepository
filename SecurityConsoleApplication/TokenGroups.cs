using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;

namespace SecurityConsoleApplication
{
    public class TokenGroups
    {
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
                //DirectoryEntry obUser = new DirectoryEntry(userSearchResult.Path);


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
                using (DirectoryEntry user = userSearchResult.GetDirectoryEntry())
                {
                   string a= (string)user.Properties["distinguishedName"].Value; 

                    user.RefreshCache(new string[] { "tokenGroups" });
                    user.RefreshCache(new string[] { "grouptype" });

                    for (int i = 0; i < user.Properties["tokenGroups"].Count; i++)
                    {
                        SecurityIdentifier sid = new SecurityIdentifier((byte[])user.Properties["tokenGroups"][i], 0);

                        NTAccount nt = (NTAccount)sid.Translate(typeof(NTAccount));
                        //do something with the SID or name (nt.Value)

                        if (nt.Value.IndexOf('\\') > -1)
                            userGroups.Add(nt.Value.Split('\\')[1]);
                        else
                            userGroups.Add(nt.Value);
                    }
                }
                IEnumerable<string> list = userGroups.ToList();
                 distinctList = list.GroupBy(x => x)
                         .Select(g => g.First())
                         .ToList();
                
            }
            return distinctList.ToList();
        }
    }
}