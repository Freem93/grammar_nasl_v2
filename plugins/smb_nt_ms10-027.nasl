#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45514);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2010-0268");
  script_bugtraq_id(39351);
  script_osvdb_id(63765);
  script_xref(name:"MSFT", value:"MS10-027");

  script_name(english:"MS10-027: Vulnerability in Windows Media Player Could Allow Remote Code Execution (979402)");
  script_summary(english:"Checks the version of wmp.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Windows Media Player 9 ActiveX control has an unspecified code
execution vulnerability.

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted web page, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-027");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000 and XP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS10-027';
kbs = make_list("979402");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "979402";

if (
  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmp.dll", version:"9.0.0.4508", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmp.dll", version:"9.0.0.3367", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Wmp.dll", version:"9.0.0.3367", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
