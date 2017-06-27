#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42113);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2009-2507");
  script_bugtraq_id(36629);
  script_osvdb_id(58854);
  script_xref(name:"MSFT", value:"MS09-057");
  script_xref(name:"IAVB", value:"2009-B-0053");

  script_name(english:"MS09-057: Vulnerability in Indexing Service Could Allow Remote Code Execution (969059)");
  script_summary(english:"Checks the version of query.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the ixsso.dll ActiveX control.

This control is included with the Indexing Service.  The version of this
control installed on the remote host reportedly has an arbitrary code
execution vulnerability.  A remote attacker could exploit this by
tricking a user into requesting a maliciously crafted web page.

This vulnerability only affects systems that have the Indexing Service
enabled.  It is disabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-057';
kb = '969059';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 2k3
  hotfix_is_vulnerable(os:"5.2", file:"query.dll", version:"5.2.3790.4554", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"query.dll",                 version:"5.1.2600.5847",   min_version:"5.1.2600.5000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"query.dll",                 version:"5.2.3790.4554", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"query.dll",                 version:"5.1.2600.3602",   dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 2000
  hotfix_is_vulnerable(os:"5.0", file:"query.dll", version:"5.0.2195.7320",   dir:"\system32", bulletin:bulletin, kb:kb)
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
