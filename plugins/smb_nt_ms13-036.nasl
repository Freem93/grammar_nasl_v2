#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65883);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id(
    "CVE-2013-1283",
    "CVE-2013-1291",
    "CVE-2013-1292",
    "CVE-2013-1293"
  );
  script_bugtraq_id(58853, 58858, 58859, 58860);
  script_osvdb_id(92130, 92131, 92132, 92133);
  script_xref(name:"MSFT", value:"MS13-036");

  script_name(english:"MS13-036: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2829996)");
  script_summary(english:"Checks file version of Win32k.sys and Ntfs.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Windows kernel on the remote host has the following
vulnerabilities :

  - Multiple race condition vulnerabilities exist.
    (CVE-2013-1283, CVE-2013-1292)

  - A font parsing vulnerability exists. (CVE-2013-1291)

  - An NTFS NULL pointer dereference vulnerability exists.
    (CVE-2013-1293)

A local attacker could exploit any of these vulnerabilities to elevate
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-036");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-036';

# nb: Microsoft pulled 2823324.replaced with 2840149
kbs = make_list('2808735', '2840149');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
########## KB2808735 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.20663", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.16559", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.22271", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.18105", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.21482", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.17266", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.23071", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18800", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'2808735') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5134",  dir:"\system32", bulletin:bulletin, kb:'2808735') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Win32k.sys", version:"5.1.2600.6364", dir:"\system32", bulletin:bulletin, kb:'2808735')
) vuln++;

########## KB2840149 ###########
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
if(
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntfs.sys", version:"6.1.7601.22297", min_version:"6.1.7601.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2840149') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntfs.sys", version:"6.1.7601.18127", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2840149') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Ntfs.sys", version:"6.1.7600.21499", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2840149') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Ntfs.sys", version:"6.1.7600.17281", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2840149') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntfs.sys", version:"6.0.6002.23070", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2840149') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntfs.sys", version:"6.0.6002.18799", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2840149')
) vuln++;

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
  audit(AUDIT_HOST_NOT, 'affected');
}
