#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51454);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/07 12:06:04 $");

  script_cve_id("CVE-2010-3145");
  script_bugtraq_id(42763);
  script_osvdb_id(67548);
  script_xref(name:"MSFT", value:"MS11-001");
  script_xref(name:"EDB-ID", value:"14751");
  script_xref(name:"IAVB", value:"2011-B-0007");

  script_name(english:"MS11-001: Vulnerability in Windows Backup Manager Could Allow Remote Code Execution (2478935)");
  script_summary(english:"Checks version of sdclt.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a code execution vulnerability
in the Windows Backup Manager.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Windows Backup
Manager that incorrectly restricts the path used for loading external
libraries.

If an attacker can trick a user into opening a specially crafted
Windows Backup manager file that is located in the same network
directory as a specially crafted dynamic link library file, he may be
able to leverage this issue to execute arbitrary code subject to the
user's privileges.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-001");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS11-001';
kbs = make_list("2478935");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Vista - KB2478935
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"sdclt.exe", version:"6.0.6002.22547", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2478935") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"sdclt.exe", version:"6.0.6002.18353", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2478935") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"sdclt.exe", version:"6.0.6001.22812", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"2478935") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"sdclt.exe", version:"6.0.6001.18561", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"2478935")
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
