#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36153);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2015/04/23 21:11:57 $");

  script_cve_id("CVE-2008-2540");
  script_bugtraq_id(29445);
  script_osvdb_id(53623);
  script_xref(name:"MSFT", value:"MS09-015");

  script_name(english:"MS09-015: Blended Threat Vulnerability in SearchPath Could Allow Elevation of Privilege (959426)");
  script_summary(english:"Checks version of Secur32.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote host may allow remote code execution.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the way the Windows SearchPath function locates and
opens files on the remote host could allow an attacker to execute
arbitrary remote code if he can trick a user into downloading a
specially crafted file into a specific location, such as the Windows
Desktop.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms09-015");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS09-015';
kb = "959426";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Vista and Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Secur32.dll", version:"6.0.6001.22376", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Secur32.dll", version:"6.0.6001.18215", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Secur32.dll", version:"6.0.6000.21010", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Secur32.dll", version:"6.0.6000.16820", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Secur32.dll", version:"5.2.3790.4455", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Secur32.dll", version:"5.2.3790.3290", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1",       arch:"x64", file:"Secur32.dll", version:"5.2.3790.4455", min_version:"5.2.3790.4000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1",       arch:"x64", file:"Secur32.dll", version:"5.2.3790.3290", min_version:"5.2.0.0", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Secur32.dll", version:"5.1.2600.5753", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Secur32.dll", version:"5.1.2600.3518", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Secur32.dll", version:"5.0.2195.7244", dir:"\System32", bulletin:bulletin, kb:kb)
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
