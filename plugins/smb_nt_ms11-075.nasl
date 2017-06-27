#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56449);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-1247");
  script_bugtraq_id(49976);
  script_osvdb_id(76231);
  script_xref(name:"IAVA", value:"2011-A-0138");
  script_xref(name:"MSFT", value:"MS11-075");

  script_name(english:"MS11-075: Vulnerability in Microsoft Active Accessibility Could Allow Remote Code Execution (2623699)");
  script_summary(english:"Checks version of Oleaut32.dll / Oleacc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a component that could allow remote
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of the Microsoft Active
Accessibility component that fails to properly restrict the path used
for loading external libraries.

If an attacker can trick a user into opening a file that resides in the
same directory as a specially crafted DLL file, he can leverage this
issue to execute arbitrary code in that DLL file subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-075");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-075';
kb = "2564958";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.21802", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.17676", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Oleaut32.dll", version:"6.1.7600.21036", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Oleaut32.dll", version:"6.1.7600.16872", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.22706", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.18508", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Oleacc.dll",   version:"7.0.3790.4909",                                dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Oleacc.dll",   version:"7.0.2600.6153",                                dir:"\system32", bulletin:bulletin, kb:kb)
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
