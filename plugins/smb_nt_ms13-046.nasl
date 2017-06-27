#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66422);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-1332", "CVE-2013-1333", "CVE-2013-1334");
  script_bugtraq_id(59749, 59750, 59782);
  script_osvdb_id(93318, 93319, 93320);
  script_xref(name:"MSFT", value:"MS13-046");

  script_name(english:"MS13-046: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2840221)");
  script_summary(english:"Checks file version of Win32k.sys, Ntoskrnl.exe, and Dxgkrnl.sys");

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

  - A privilege escalation vulnerability exists in the
    Microsoft DirectX graphics kernel subsystem.
    (CVE-2013-1332)

  - A privilege escalation vulnerability exists in the
    Windows kernel-mode driver. (CVE-2013-1333,
    CVE-2013-1334)

A local attacker could exploit any of these vulnerabilities to elevate
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-046");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

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

bulletin = 'MS13-046';

kbs = make_list('2829361', '2830290');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
########## KB2829361 ###########
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
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ntoskrnl.exe", version:"6.2.9200.20685", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'2829361') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ntoskrnl.exe", version:"6.2.9200.16581", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2829361') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.22296", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:'2829361') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.18126", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:'2829361') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.23094", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:'2829361') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18817", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'2829361') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5148",  dir:"\system32", bulletin:bulletin, kb:'2829361') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Win32k.sys", version:"5.1.2600.6379", dir:"\system32", bulletin:bulletin, kb:'2829361')
) vuln++;

########## KB2830290 ###########
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if(
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Dxgkrnl.sys", version:"6.2.9200.20687", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2830290') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Dxgkrnl.sys", version:"6.2.9200.16583", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2830290') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dxgkrnl.sys", version:"6.1.7601.22296", min_version:"6.1.7601.21000", dir:"\system32\drivers", bulletin:bulletin, kb:'2830290') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dxgkrnl.sys", version:"6.1.7601.18126", min_version:"6.1.7600.17000", dir:"\system32\drivers", bulletin:bulletin, kb:'2830290') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dxgkrnl.sys", version:"6.0.6002.22296", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2830290') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dxgkrnl.sys", version:"6.0.6002.18126", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2830290')
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
