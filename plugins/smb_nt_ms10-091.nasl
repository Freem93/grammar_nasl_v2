#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51163);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3956", "CVE-2010-3957", "CVE-2010-3959");
  script_bugtraq_id(45311, 45315, 45316);
  script_osvdb_id(69820, 69821, 69822);
  script_xref(name:"MSFT", value:"MS10-091");

  script_name(english:"MS10-091: Vulnerabilities in the OpenType Font (OTF) Driver Could Allow Remote Code Execution (2296199)");
  script_summary(english:"Checks the version of Atmfd.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a font driver that allows arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of the OpenType Font (OTF)
Format Driver that is affected by two vulnerabilities :

  - The driver does not properly index an array when
    parsing OpenType fonts, which could allow a remote
    attacker to run arbitrary code in kernel mode.
    (CVE-2010-3956)

  - The driver does not properly reset a pointer when
    freeing memory, resulting in a 'double free' condition,
    which could allow a remote attacker to run arbitrary
    code in kernel mode. (CVE-2010-3957)

  - The driver does not properly parse the CMAP table when
    rendering a specially crafted OpenType font, which
    could allow a local attacker to run arbitrary code in
    kernel mode. (CVE-2010-3959)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-091");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-091';
kbs = make_list("2296199");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2296199";
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"Atmfd.dll", version:"5.1.2.230", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0",                   file:"Atmfd.dll", version:"5.1.2.230", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Atmfd.dll", version:"5.2.2.230", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1",       arch:"x86", file:"Atmfd.dll", version:"5.1.2.230", dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-091", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
