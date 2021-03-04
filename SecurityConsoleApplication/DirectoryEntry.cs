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
   public  class LDAPDirectoryEntry
    {
       public static List<string> GetGroupsForUser()
       {
           var watch = System.Diagnostics.Stopwatch.StartNew();
           SearchResult userSearchResult = NestedGroups.GetCurrentlyLoggedinUser();
           watch.Stop();
           var elapsedMsForLoggedInUser = watch.ElapsedMilliseconds;
           Console.WriteLine(" Logged In User and Connection Binding time :-  "+":"+elapsedMsForLoggedInUser);
               List<string> parentGroups=new List<string>();
           if (userSearchResult != null)
           {
               var watchForParentGrops = System.Diagnostics.Stopwatch.StartNew();
               parentGroups = NestedGroups.GetParentGroups(userSearchResult);
               watchForParentGrops.Stop();
               var elapsedMsForParentGrops = watchForParentGrops.ElapsedMilliseconds;
               Console.WriteLine(" Parent Groups :-  " + ":" + elapsedMsForLoggedInUser);
               var watchForNestedSubgroups = System.Diagnostics.Stopwatch.StartNew();
               NestedGroups.GetNestedSubgroups(parentGroups);
               watchForNestedSubgroups.Stop();
               var elapsedMsForNestedSubgroups = watchForNestedSubgroups.ElapsedMilliseconds;
               Console.WriteLine(" Nested Groups :-  " + ":" + elapsedMsForNestedSubgroups);
               parentGroups.AddRange(NestedGroups._subGroupList);
               parentGroups = parentGroups.Distinct().OrderBy(x => x).ToList();
              
           }

           return parentGroups;
       }
    }
}
