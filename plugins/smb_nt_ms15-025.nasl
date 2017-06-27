#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81739);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-0073", "CVE-2015-0075");
  script_bugtraq_id(72908, 72915);
  script_osvdb_id(119375, 119376);
  script_xref(name:"MSFT", value:"MS15-025");
  script_xref(name:"IAVA", value:"2015-A-0048");

  script_name(english:"MS15-025: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (3038680)");
  script_summary(english:"Checks the file version of ntoskrnl.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple privilege escalation
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple privilege escalation
vulnerabilities :

  - An elevation of privilege vulnerability exists due to
    Windows Registry Virtualization improperly allowing a
    user to modify the virtual store of another user. A
    local attacker, with a specially crafted application,
    can exploit this vulnerability to take control of the
    account of another user who is logged on to the affected
    system. (CVE-2015-0073)

  - An elevation of privilege vulnerability exists due to
    a failure to properly validate and enforce impersonation
    levels. A local attacker, with a specially crafted
    application, can exploit this vulnerability to bypass
    user account checks. (CVE-2015-0075)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-025");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.

KB3035131 (MS15-025) has affected binaries in common with Security
Advisory 3033929, which was released simultaneously. If you download
and install updates manually, you should first install KB3035131
(MS15-025) before installing KB3033929. See the MS15-025 bulletin
Update FAQ for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-025';
kb = '3038680';

kbs = make_list(kb, '3035131', '3033929', '3033395');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntoskrnl.exe", version:"6.3.9600.17668", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntoskrnl.exe", version:"6.2.9200.21369", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntoskrnl.exe", version:"6.2.9200.17251", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.22943", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.18738", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.23636", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19327", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'3035131') ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntoskrnl.exe", version:"5.2.3790.5580", dir:"\system32", bulletin:bulletin, kb:'3033395')
)
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
