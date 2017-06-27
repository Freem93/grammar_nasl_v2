#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71316);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id(
    "CVE-2013-3899",
    "CVE-2013-3902",
    "CVE-2013-3903",
    "CVE-2013-3907",
    "CVE-2013-5058"
  );
  script_bugtraq_id(64080, 64084, 64087, 64090, 64091);
  script_osvdb_id(100759, 100760, 100761, 100762, 100763);
  script_xref(name:"EDB-ID", value:"30397");
  script_xref(name:"MSFT", value:"MS13-101");

  script_name(english:"MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430)");
  script_summary(english:"Checks file version of the affected files.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel drivers on the remote host are affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has the following vulnerabilities :

  - Multiple errors exist in the Windows kernel-mode
    drivers that could allow privilege escalation and
    arbitrary code execution. (CVE-2013-3899, CVE-2013-3902,
    CVE-2013-5058)

  - An error exists in the way the Windows kernel-mode
    driver parses TrueType fonts that could allow denial
    of service attacks. (CVE-2013-3903)

  - An error exists in the Windows audio port-class driver
    that could allow privilege escalation and arbitrary
    code execution. (CVE-2013-3907)

An attacker who successfully exploited these vulnerabilities could read
arbitrary amounts of kernel memory or gain elevated privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/advisories/divide-error-windows-kernel");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530273/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-101");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, 2012, 8.1, and 2012 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

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

# Main begins
get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-101';

kbs = make_list('2887069', '2893984');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

########## KB2893984 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 8.1          #
#  Windows Server 2012         #
#  Windows Server 2012 R2      #
################################
if (
  # Windows 8.1 and Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.16457", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.20871", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.16758", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.22496", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.18300", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23261", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.18974", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'2893984') ||

  # Windows 2003 / XP
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"win32k.sys", version:"5.2.3790.5250",  dir:"\system32", bulletin:bulletin, kb:'2893984') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"win32k.sys", version:"5.1.2600.6473", dir:"\system32", bulletin:bulletin, kb:'2893984')
) vuln++;

########## KB2887069 ###########
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') > 0
)
{
  kb = '2887069';
  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
  files = list_dir(basedir:winsxs, level:0, dir_pat:"wdmaudio.inf", file_pat:"^drmk\.sys$", max_recurse:1);

  vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:make_list('6.0.6002.18975', '6.0.6002.23261'), max_versions:make_list('6.0.6002.20000', '6.0.6002.99999'), bulletin:bulletin, kb:kb);
  vuln += hotfix_check_winsxs(os:'6.1', sp:1, files:files, versions:make_list('6.1.7601.18276', '6.1.7601.22472'), max_versions:make_list('6.1.7601.20000', '6.1.7601.99999'), bulletin:bulletin, kb:kb);
  vuln += hotfix_check_winsxs(os:'6.2', sp:0, files:files, versions:make_list('6.2.9200.16433', '6.2.9200.20534'), max_versions:make_list('6.2.9200.20000', '6.2.9200.99999'), bulletin:bulletin, kb:kb);
}

if (vuln > 0)
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
