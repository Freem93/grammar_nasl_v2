#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77163);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/23 21:44:07 $");

  script_cve_id("CVE-2014-0318", "CVE-2014-1819", "CVE-2014-4064");
  script_bugtraq_id(69142, 69143, 69144);
  script_osvdb_id(109934, 109935, 109936);
  script_xref(name:"MSFT", value:"MS14-045");
  script_xref(name:"IAVA", value:"2014-A-0124");

  script_name(english:"MS14-045: Vulnerabilities in Kernel-Mode Drivers Could Allow Elevation of Privilege (2984615)");
  script_summary(english:"Checks the versions of d3d11.dll / dxgkrnl.sys / gdi32.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in the
    Windows kernel-mode driver due to improper usage of
    window handle thread-owned objects. A local attacker
    could execute a specially crafted application in kernel
    mode to take control of the system. (CVE-2014-0318).

  - A privilege escalation vulnerability exists in the
    Windows kernel-mode driver due to improper handling of
    objects in memory while processing font files. A local
    attacker could execute a specially crafted font file to
    escalate privileges. (CVE-2014-1819)

  - An information disclosure vulnerability exists in the
    Windows kernel-mode driver due to improper handling of
    objects in memory. An attacker could exploit this issue
    to disclose information from kernel memory on the local
    system. (CVE-2014-4064).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-045");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-045';
kbs = make_list("2976897", "2993651");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2 with KB2919355 applied
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"d3d11.dll", version:"6.3.9600.17041", min_version:"6.3.9600.17000", dir:"\system32", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"gdi32.dll", version:"6.3.9600.17246", min_version:"6.3.9600.17000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"dxgkrnl.sys", version:"6.2.9200.21148", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"dxgkrnl.sys", version:"6.2.9200.17031", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"gdi32.dll", version:"6.2.9200.21172", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"gdi32.dll", version:"6.2.9200.17053", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"dxgkrnl.sys", version:"6.1.7601.22720", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"dxgkrnl.sys", version:"6.1.7601.18510", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"gdi32.dll", version:"6.1.7601.22783", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"gdi32.dll", version:"6.1.7601.18577", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"dxgkrnl.sys", version:"7.0.6002.23427", min_version:"7.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"dxgkrnl.sys", version:"7.0.6002.19126", min_version:"7.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"2976897") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.23476", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.19171", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2993651") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"gdi32.dll", version:"5.2.3790.5418", dir:"\system32", bulletin:bulletin, kb:"2993651")
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
