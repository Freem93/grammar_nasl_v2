#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66415);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-1336", "CVE-2013-1337");
  script_bugtraq_id(59789, 59790);
  script_osvdb_id(93301, 93302);
  script_xref(name:"MSFT", value:"MS13-040");

  script_name(english:"MS13-040: Vulnerabilities in .NET Framework Could Allow Spoofing (2836440)");
  script_summary(english:"Checks version of System.Security.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Microsoft .NET
Framework that is affected by multiple vulnerabilities :

  - A spoofing vulnerability exists that could allow an
    attacker to modify the contents of an XML file without
    invalidating the signature associated with the file.
    (CVE-2013-1336)

  - An authentication bypass vulnerability exists because of
    the way the Microsoft .NET framework improperly creates
    policy requirements for authentication when setting up
    WCF endpoint authentication.  A remote attacker who
    exploited this vulnerability may be able to steal
    information or take actions in the context of an
    authenticated user. (CVE-2013-1337)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-040");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 2.0 SP2,
3.5.1, 4.0, and 4.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

# Windows Embedded is not supported by Nessus
# There are cases where this plugin is flagging embedded
# hosts improperly since this update does not apply
# to those machines
productname = get_kb_item("SMB/ProductName");
if ("Windows Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-040';
kbs = make_list(
  '2804576',
  '2804577',
  '2804579',
  '2804580',
  '2804582',
  '2804583',
  '2804584'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

########## KB2804576 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2 SP1  #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Security.dll", version:"4.0.30319.1004", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Security.dll", version:"4.0.30319.2006", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"4.0.30319.1004", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"4.0.30319.2006", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.1004", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.2006", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.1004", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.2006", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804576");
vuln += missing;

######### KB2804577 ############
#  .NET Framework 2.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Security.dll", version:"2.0.50727.7019", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Security.dll", version:"2.0.50727.3646", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"2.0.50727.7019", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"2.0.50727.3646", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804577");
vuln += missing;

########## KB2804579 ############
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"2.0.50727.7018", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"2.0.50727.5469", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804579");
vuln += missing;

########## KB2804580 ############
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"2.0.50727.7018", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"2.0.50727.4237", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804580");
vuln += missing;

########### KB2804582 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.18038", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.19057", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.18038", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.19057", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804582");
vuln += missing;

########### KB2804583 ###########
#  .NET Framework 4.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"4.0.30319.18039", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"4.0.30319.19058", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804583");
vuln += missing;

########## KB2804584 ############
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"2.0.50727.6404", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"2.0.50727.7018", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2804584");
vuln += missing;

if(vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
