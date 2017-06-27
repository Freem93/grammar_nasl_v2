#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43065);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/12/01 15:02:06 $");

  script_cve_id("CVE-2009-2506");
  script_bugtraq_id(37216);
  script_osvdb_id(60834);
  script_xref(name:"IAVA", value:"2009-A-0128");
  script_xref(name:"MSFT", value:"MS09-073");

  script_name(english:"MS09-073: Vulnerability in WordPad and Office Text Converters Could Allow Remote Code Execution (975539)");
  script_summary(english:"Checks version of Mswrd832.cnv / Mswrd632.wpc");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through opening a
Microsoft Word file.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a vulnerable version of Microsoft WordPad,
Office, or Office Converter Pack. Opening a specially crafted Word 97
file can result in the execution of arbitrary code. A remote attacker
could exploit this by tricking a user into opening a malicious Word
file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-073");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Microsoft Office XP, 2003, and Office Converter Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_converter_pack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-073';
kbs = make_list("973904");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

arch = get_kb_item_or_exit("SMB/ARCH");
if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

office_versions = hotfix_check_office_version();
x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x86_path += "\Microsoft Shared\TextConv";

x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');
if (x64_path) x64_path += "\Common Files\Microsoft Shared\TextConv";
officexp_sp = get_kb_item("SMB/Office/XP/SP");
office2k3_sp = get_kb_item("SMB/Office/2003/SP");

if (
  # Windows 2003 / XP SP2 x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Mswrd632.wpc", path:x64_path, version:"2009.10.31.10", bulletin:bulletin, kb:'973904') ||

  # Windows 2003 x86
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Mswrd632.wpc", path:x86_path, version:"2009.10.31.10", bulletin:bulletin, kb:'973904') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mswrd632.wpc", path:x86_path, version:"2009.10.31.10", bulletin:bulletin, kb:'973904') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mswrd632.wpc", path:x86_path, version:"2009.10.31.10", bulletin:bulletin, kb:'973904') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Mswrd632.wpc", path:x86_path,    version:"2009.10.31.10", bulletin:bulletin, kb:'973904') ||

  # Office XP SP3
  (
    (office_versions["10.0"] &&
    (!isnull(officexp_sp) && officexp_sp == 3)) &&
    (
      hotfix_is_vulnerable(file:"Mswrd832.cnv", version:"2003.1100.8313.0", path:x86_path, bulletin:bulletin, kb:'975008') ||
      hotfix_is_vulnerable(file:"Mswrd832.cnv", arch:"x64", version:"2003.1100.8313.0", path:x64_path, bulletin:bulletin, kb:'975008')
    )
  ) ||


  # Office 2003 SP3
  (
    (office_versions["11.0"] &&
    (!isnull(office2k3_sp) && office2k3_sp == 3)) &&
    (
      hotfix_is_vulnerable(file:"Mswrd832.cnv", version:"2003.1100.8313.0", path:x86_path, bulletin:bulletin, kb:'975051') ||
      hotfix_is_vulnerable(file:"Mswrd832.cnv", arch:"x64", version:"2003.1100.8313.0", path:x64_path, bulletin:bulletin, kb:'975051')
    )
  )
)
{
  set_kb_item(name:"SMB/Missing/MS09-073", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
