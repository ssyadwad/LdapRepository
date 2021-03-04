using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityConsoleApplication
{
    public static class Common
    {
        #region LDAPAttributes

        //public static string LdapMemberOf = "memberOf";
        //public static string LdapGetUserQuery = "(&(objectClass=user)(objectsid={0}))";
        public static string LdapDistinguishedName = "distinguishedName";

        internal static string LdapObjectSid = "objectsid";
        internal static string LdapUserName = "samaccountname";
        internal static string LdapUID = "uid";
        internal static string LdapCommonName = "cn";
        internal static string LdapFetchUserQuery = "(&(objectClass=user)(CN={0}))";
        internal static string LdapFetchUserValidationQuery = "(&(objectClass=person)(distinguishedName={0}))";

        internal static string LdapFetchUserValidationQueryPrimaryGroupID =
            "(&(objectClass=person)(primarygroupid={0}))";

        internal static string LdapFetchGroupQuery = "(&(objectClass=Group)(distinguishedName={0}))";
        internal static string LdapMember = "member";
        internal static int LdapNetBiosPort = 389;
        internal static int PageSize = 1000;
        internal static int RenewLockCountLimit = 100;
        internal static int LdapUserLimit = 1000;
        internal static int TotalGlobalUserLimit = 4500;
        internal static int TotalLocalUserLimit = 4500;

        #endregion
    }

    public class LdapGroupEntity
    {
        public string DistinguishedName;
        public List<string> LdapMembers;
        public List<string> LdapMembersUsingPrimaryGroupId;
        public string LdapObjectSid;
        public bool IsMemberAttributePresent { get; set; }
        public bool IsObjectSidAttributePresent { get; set; }
        public string PrimaryGroupId { get; set; }
        public SearchResultEntry LdapEntry;
        public bool IsPrimaryGroupIdUserFetchFailed { get; set; }

        public bool HasNestedGroups { get; set; }

        public List<LdapGroupEntity> NestedGroups;
        public string GetDistinguishedName(SearchResultEntry ldapEntity)
        {
            return ldapEntity != null
                ? (ldapEntity.Attributes[Common.LdapDistinguishedName] != null
                    ? Convert.ToString(ldapEntity.Attributes[Common.LdapDistinguishedName][0],
                        CultureInfo.CurrentCulture)
                    : null)
                : null;
        }

        public string GetSamaccountName(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapUserName] != null
                ? ldapEntity.Attributes[Common.LdapUserName][0].ToString()
                : null;
        }

        public byte[] GetObjectSid(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapObjectSid] != null
                ? (byte[]) ldapEntity.Attributes[Common.LdapObjectSid][0]
                : null;
        }

        public string GetLdapUid(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapUID] != null
                ? ldapEntity.Attributes[Common.LdapUID][0].ToString()
                : null;
        }

        public string GetCommonName(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapCommonName] != null
                ? ldapEntity.Attributes[Common.LdapCommonName][0].ToString()
                : null;
        }

        public LdapGroupEntity(SearchResultEntry ldapGroup)
        {
            if (ldapGroup != null)
            {
                LdapMembers = new List<string>();
                LdapMembersUsingPrimaryGroupId = new List<string>();
                NestedGroups=new List<LdapGroupEntity>();
                DistinguishedName = GetDistinguishedName(ldapGroup);
                LdapEntry = ldapGroup;
                IsPrimaryGroupIdUserFetchFailed = false;
                if (ldapGroup.Attributes[Common.LdapMember] != null)
                {
                    IsMemberAttributePresent = true;
                    int childCount = ldapGroup.Attributes[Common.LdapMember].Count;

                    for (int i = 0; i < childCount; i++)
                    {
                        string ldapGroupMember = ldapGroup.Attributes[Common.LdapMember][i].ToString();
                        LdapMembers.Add(ldapGroupMember);
                    }
                }
                else
                {
                    IsMemberAttributePresent = false;

                }
                IsObjectSidAttributePresent = ldapGroup.Attributes[Common.LdapObjectSid] != null;
                if (IsObjectSidAttributePresent)
                {
                    try
                    {

                    }
                    catch (Exception ex)
                    {
                        IsPrimaryGroupIdUserFetchFailed = true;

                    }
                }
            }

        }

    }
    public class LdapUserEntity
    {
        public string DistinguishedName { get; set; }
        public string SamaccountName { get; set; }
        public string LdapUid { get; set; }
        public string LdapCommonName { get; set; }
        public string NetBiosName { get; set; }
        public string SFqdnLdapUser { get; set; }

        public LdapUserEntity(SearchResultEntry ldapUser)
        {
            if (ldapUser != null)
            {
                DistinguishedName = GetDistinguishedName(ldapUser);
                SFqdnLdapUser = GetFullyQualifiedDomainName(DistinguishedName.Replace(',', '.'));
                SamaccountName = GetSamaccountName(ldapUser);
                LdapUid = GetLdapUid(ldapUser);
                LdapCommonName = GetCommonName(ldapUser);
            }
        }
        internal string GetFullyQualifiedDomainName(string distinguishedName)
        {
            var sFqdn = string.Empty;
            var fullyQualifiedDomainName = distinguishedName.Split(new[] { "DC=" }, StringSplitOptions.None);
            for (int i = 1; i < fullyQualifiedDomainName.Length; i++)
            {
                sFqdn += fullyQualifiedDomainName[i];
            }
            return sFqdn;
        }
        public string GetDistinguishedName(SearchResultEntry ldapEntity)
        {
            return ldapEntity != null
                ? (ldapEntity.Attributes[Common.LdapDistinguishedName] != null
                    ? Convert.ToString(ldapEntity.Attributes[Common.LdapDistinguishedName][0],
                        CultureInfo.CurrentCulture)
                    : null)
                : null;
        }

        public string GetSamaccountName(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapUserName] != null
                ? ldapEntity.Attributes[Common.LdapUserName][0].ToString()
                : null;
        }

        public byte[] GetObjectSid(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapObjectSid] != null
                ? (byte[])ldapEntity.Attributes[Common.LdapObjectSid][0]
                : null;
        }

        public string GetLdapUid(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapUID] != null
                ? ldapEntity.Attributes[Common.LdapUID][0].ToString()
                : null;
        }

        public string GetCommonName(SearchResultEntry ldapEntity)
        {
            if (ldapEntity == null) throw new ArgumentNullException("ldapEntity");
            return ldapEntity.Attributes[Common.LdapCommonName] != null
                ? ldapEntity.Attributes[Common.LdapCommonName][0].ToString()
                : null;
        }
    }
}
