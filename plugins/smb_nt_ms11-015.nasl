#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52583);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2011-0032", "CVE-2011-0042");
  script_bugtraq_id(46680, 46682);
  script_osvdb_id(71015, 71016);
  script_xref(name:"IAVA", value:"2011-A-0031");
  script_xref(name:"MSFT", value:"MS11-015");

  script_name(english:"MS11-015: Vulnerabilities in Windows Media Could Allow Remote Code Execution (2510030)");
  script_summary(english:"Checks the version of Sbe.dll / mpg2splt.ax");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Windows Media installed on the remote host has multiple
code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has at least one of the following
vulnerabilities in Media Player or Media Center :

  - DirectShow does not adequately restrict the path used
    for loading external libraries.  A remote attacker could
    exploit this by tricking a user into opening a specially
    crafted file, resulting in arbitrary code execution.
    (CVE-2011-0032)

  - There is an unspecified code execution vulnerability
    when Media Player and Media Center attempt to open
    specially crafted .dvr-ms files."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-015");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, Vista, 7, 2008
R2, and Media Center TV Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-015';
kbs = make_list("2479943", "2494132");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Media Center TV Pack 2008 for Windows Vista
  #hotfix_is_vulnerable(os:"6.0", file:"Sbe.dll", version:"6.6.1000.18309",  min_version:"6.6.1000.0", dir:"\system32", bulletin:bulletin, kb:"2494132") ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mpg2splt.ax", version:"6.6.7601.21626", min_version:"6.6.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mpg2splt.ax", version:"6.6.7601.17528", min_version:"6.6.7600.17000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"mpg2splt.ax", version:"6.6.7600.20865", min_version:"6.6.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"mpg2splt.ax", version:"6.6.7600.16724", min_version:"6.6.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||

  # Vista
  hotfix_is_vulnerable(os:"6.0", file:"Sbe.dll", version:"6.6.6002.22558", min_version:"6.6.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||
  hotfix_is_vulnerable(os:"6.0", file:"Sbe.dll", version:"6.6.6002.18363", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||
  hotfix_is_vulnerable(os:"6.0", file:"Sbe.dll", version:"6.6.6001.22822", min_version:"6.6.6001.22000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||
  hotfix_is_vulnerable(os:"6.0", file:"Sbe.dll", version:"6.6.6001.18571", min_version:"6.6.6001.18000", dir:"\system32", bulletin:bulletin, kb:"2479943") ||

  # Windows XP x64 (looks like windows 2003)
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"Sbe.dll", version:"6.5.3790.4826", dir:"\SysWOW64", bulletin:bulletin, kb:"2479943") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Sbe.dll", version:"6.5.2600.6076", dir:"\system32", bulletin:bulletin, kb:"2479943")
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
