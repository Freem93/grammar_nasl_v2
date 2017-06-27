#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63425);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-0005");
  script_bugtraq_id(57141);
  script_osvdb_id(88968);
  script_xref(name:"MSFT", value:"MS13-007");
  script_xref(name:"IAVB", value:"2013-B-0001");

  script_name(english:"MS13-007: Vulnerability in Open Data Protocol Could Allow Denial of Service (2769327)");
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
"The remote Windows host is running a version of the Microsoft .NET
Framework that is affected by a denial of service vulnerability in the
Open Data (OData) protocol.  An unauthenticated attacker could exploit
this vulnerability by sending a specially crafted HTTP request to the
affected site.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-007");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, 2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-007';
kbs = make_list(
  '2736416',
  '2736418',
  '2736422',
  '2736428',
  '2736693',
  '2753596'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

########## KB2736428 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
if (
# Windows XP SP3
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"DataSvcUtil.exe", version:"4.0.30319.297", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319", bulletin:bulletin, kb:"2736428")  ||
# Windows XP SP2 x64 / Server 2003 SP2
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"DataSvcUtil.exe", version:"4.0.30319.297", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319", bulletin:bulletin, kb:"2736428")  ||
# Windows Vista SP2 / Server 2008 SP2
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"DataSvcUtil.exe", version:"4.0.30319.297", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319", bulletin:bulletin, kb:"2736428") ||
# Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"DataSvcUtil.exe", version:"4.0.30319.297", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319", bulletin:bulletin, kb:"2736428")
) vuln++;

########## KB2736418 ###########
#  .NET Framework 3.5.1        #
#  Windows 7,                  #
#  Server 2008 R2              #
################################
if (
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"DataSvcUtil.exe", version:"3.5.30729.5006", min_version:"3.5.30729.4600", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736418") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"DataSvcUtil.exe", version:"3.5.30729.5831", min_version:"3.5.30729.5400", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736418")
) vuln++;

########## KB2736422 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
if (
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"DataSvcUtil.exe", version:"3.5.30729.5451", min_version:"3.5.30729.5000", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736422") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"DataSvcUtil.exe", version:"3.5.30729.5831", min_version:"3.5.30729.5500", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736422")
) vuln++;

########## KB2736693 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
if (
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"DataSvcUtil.exe", version:"3.5.30729.6400", min_version:"3.5.30729.6000", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736693") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"DataSvcUtil.exe", version:"3.5.30729.7004", min_version:"3.5.30729.6600", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736693")
) vuln++;

########## KB2736416 ###########
#  .NET Framework 3.5 SP1      #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows Server 2008 SP2,    #
################################
if (
# Windows XP SP3
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"DataSvcUtil.exe", version:"3.5.30729.4039", min_version:"3.5.30729.3600", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736416") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"DataSvcUtil.exe", version:"3.5.30729.5851", min_version:"3.5.30729.5400", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736416") ||
# Windows XP SP2 x64 / Server 2003 SP2
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"DataSvcUtil.exe", version:"3.5.30729.4039", min_version:"3.5.30729.3600", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736416") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"DataSvcUtil.exe", version:"3.5.30729.5851", min_version:"3.5.30729.5400", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736416") ||
# Windows Vista SP2 / Server 2008 SP2
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"DataSvcUtil.exe", version:"3.5.30729.4039", min_version:"3.5.30729.3600", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736416") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"DataSvcUtil.exe", version:"3.5.30729.5851", min_version:"3.5.30729.5400", dir:"\Microsoft.NET\Framework\v3.5", bulletin:bulletin, kb:"2736416") ) vuln++;

########## KB2753596 ###########
# OData IIS Extension          #
#  Windows Server 2012         #
################################
if(winver == '6.2')
{
   hotfix_check_fversion_end();
   registry_init();
   val = NULL;
   odata_installed = FALSE;
   hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE);
   if(!isnull(hklm))
   {
     key = "SOFTWARE\Microsoft\.NETFramework\Fusion\References";
     dotNetKeys = get_registry_subkeys(handle:hklm, key:key);
     RegCloseKey(handle:hklm);
     foreach subkey (dotNetKeys)
     {
       if(subkey =~ "^Microsoft\.Management\.Odata\.Resources")
       {
         odata_installed = TRUE;
         break;
       }
     }
   }

   if(odata_installed)
   {
     close_registry(close:FALSE);

     rc = NetUseAdd(share:share);
     if (rc != 1)
     {
       NetUseDel();
       audit(AUDIT_SHARE_FAIL, share);
     }

     winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:rootfile);
     patched = FALSE;
     files = list_dir(basedir:winsxs, level:0, dir_pat:'msil_microsoft.management.odata', file_pat:'^Microsoft\\.Management\\.OData\\.dll', max_recurse:1);

     vuln += hotfix_check_winsxs(os:'6.2', files:files, versions:make_list('6.2.9200.18975', '6.2.9200.23261'), max_versions:make_list('6.2.2900.20000', '6.2.9200.99999'), bulletin:bulletin, kb:'2753596');
   }
   else close_registry();
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
