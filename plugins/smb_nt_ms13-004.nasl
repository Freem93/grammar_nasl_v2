#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63422);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id(
    "CVE-2013-0001",
    "CVE-2013-0002",
    "CVE-2013-0003",
    "CVE-2013-0004"
  );
  script_bugtraq_id(57113, 57114, 57124, 57126);
  script_osvdb_id(88962, 88963, 88964, 88965);
  script_xref(name:"MSFT", value:"MS13-004");
  script_xref(name:"IAVA", value:"2013-A-0006");

  script_name(english:"MS13-004: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2769324)");
  script_summary(english:"Checks file versions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft .NET
Framework that is affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    way the Windows Forms in .NET Framework handle pointers
    to unmanaged memory locations. (CVE-2013-0001)

  - A buffer overflow vulnerability in a Windows Form method
    in the .NET Framework exists that could be exploited to
    gain elevated privileges. (CVE-2013-0002)

  - A method in the S.DS.P namespace of the .NET Framework is
    affected by a buffer overflow vulnerability which could
    be exploited to gain elevated privileges.
    (CVE-2013-0003)

  - The way the .NET Framework validates permissions of
    certain objects in memory has a flaw that could be
    exploited to gain elevated privileges. (CVE-2013-0004)."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-004/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-005/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jan/51");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-004");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, 2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-004';
kbs = make_list(
  '2742595', # verify min versions
  '2742596',
  '2742597',
  '2742598',
  '2742599',
  '2742601',
  '2742604',
  #'2742607', # Not checked
              # Media Center Edition 2005 Service Pack 3 and Tablet PC Edition 2005 Service Pack 3 only
  '2742613',
  '2742614',
  '2742616',
  '2756918',
  '2756919',
  '2756920',
  '2756921',
  '2756923'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
assembly_dir_30 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0\All Assemblies In");
assembly_dir_35 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.5\All Assemblies In");
RegCloseKey(handle:hklm);
close_registry();

vuln = 0;

########## KB2742595 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"4.0.30319.1001", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"4.0.30319.2001", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.1001", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.2001", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.1001", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.2001", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Windows.Forms.dll", version:"4.0.30319.1001", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Windows.Forms.dll", version:"4.0.30319.2001", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742595");
vuln += missing;

######### KB2742596 ###########
#  .NET Framework 2.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"2.0.50727.5740", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"2.0.50727.3644", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.5740", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.3644", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742596");
vuln += missing;

########## KB2742597 ###########
#  .NET Framework 1.1 SP 1     #
#  Windows XP,                 #
#  Windows Server 2003 64-bit, #
#  Vista SP2,                  #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"System.Web.dll", version:"1.1.4322.2502", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"System.Web.dll", version:"1.1.4322.2502", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"1.1.4322.2502", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2742597');
vuln += missing;

########## KB2742598 ###########
#  .NET Framework 3.5.1        #
#  Windows 7,                  #
#  Server 2008 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.5740", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.4985", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742598");
vuln += missing;

########## KB2742599 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"2.0.50727.5740", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"2.0.50727.5467", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742599");
vuln += missing;

########## KB2742601 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.5740", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.4235", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742601");
vuln += missing;

########## KB2742604 ###########
#  .NET Framework 1.1 SP 1     #
#  Windows Server 2003 SP2     #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2502", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2742604');
vuln += missing;

########## KB2742613 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.18021", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.19029", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.18021", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.19029", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742613");
vuln += missing;

########## KB2742614 ###########
#  .NET Framework 4.0          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.dll", version:"4.0.30319.18022", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.dll", version:"4.0.30319.19030", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742614");
vuln += missing;

########## KB2742616 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.dll", version:"2.0.50727.6401", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.dll", version:"2.0.50727.7005", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2742616");
vuln += missing;

######### KB2756918 ###########
#  .NET Framework 3.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.ServiceModel.dll", version:"3.0.4506.4037", min_version:"3.0.4506.4000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.ServiceModel.dll", version:"3.0.4506.5845", min_version:"3.0.4506.5600", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.ServiceModel.dll", version:"3.0.4506.4037", min_version:"3.0.4506.4000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.ServiceModel.dll", version:"3.0.4506.5845", min_version:"3.0.4506.5600", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2756918");
  vuln += missing;
}

######### KB2756919 ###########
#  .NET Framework 3.0 SP2     #
#  Windows Vista SP2,         #
#  Server 2008 SP2            #
###############################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.ServiceModel.dll", version:"3.0.4506.4214", min_version:"3.0.4506.4000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.ServiceModel.dll", version:"3.0.4506.5847", min_version:"3.0.4506.5600", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2756919");
  vuln += missing;
}

######### KB2756920 ###########
#  .NET Framework 3.5.1       #
#  Windows 7,                 #
#  Server 2008 R2             #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.ServiceModel.dll", version:"3.0.4506.5007", min_version:"3.0.4506.4000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.ServiceModel.dll", version:"3.0.4506.5846", min_version:"3.0.4506.5600", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2756920");
  vuln += missing;
}

######### KB2756921 ###########
#  .NET Framework 3.5.1       #
#  Windows 7 SP1,             #
#  Server 2008 R2 SP1         #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.ServiceModel.dll", version:"3.0.4506.5452", min_version:"3.0.4506.4000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.ServiceModel.dll", version:"3.0.4506.5846", min_version:"3.0.4506.5600", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2756921");
  vuln += missing;
}

######### KB2756923 ###########
#  .NET Framework 3.5         #
#  Windows 8,                 #
#  Server 2012                #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.ServiceModel.dll", version:"3.0.4506.6401", min_version:"3.0.4506.6000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.ServiceModel.dll", version:"3.0.4506.7005", min_version:"3.0.4506.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2756923");
  vuln += missing;
}

if(vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
