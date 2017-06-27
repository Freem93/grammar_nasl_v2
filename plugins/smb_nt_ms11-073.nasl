#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56176);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2011-1980", "CVE-2011-1982");
  script_bugtraq_id(49513, 49519);
  script_osvdb_id(75379, 75380);
  script_xref(name:"CERT", value:"909022");
  script_xref(name:"MSFT", value:"MS11-073");

  script_name(english:"MS11-073: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2587634)");
  script_summary(english:"Checks version of mso.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office that
is potentially affected by two vulnerabilities :

  - The application insecurely restricts the path used for
    loading external libraries when opening documents that
    use the .doc, .xls, or .ppt Office binary format and
    when the Office File Validation Add-in is not
    installed. This could lead to arbitrary code execution.
    (CVE-2011-1980)

  - The application may use an uninitialized object pointer
    when opening a Word document, which could lead to
    arbitrary code execution. (CVE-2011-1982)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-073");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, 2007, and
2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-494");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Mantisbt < 1.2.8 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-073';
kbs = make_list("2584052", "2584063", "2584066");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

arch = get_kb_item_or_exit("SMB/ARCH");
office_vers = hotfix_check_office_version();
if (isnull(office_vers)) exit(0, "The host is not affected since Microsoft Office is not installed.");
office_sp = get_kb_list_or_exit("SMB/Office/*/SP");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");
x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

vuln = FALSE;
# Office 2010
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp <= 1)
  {
    kb = '2584066';
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"14.0.6106.5005", min_version:'14.0.0.0', path:x86_path+"\Microsoft Shared\Office14", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"14.0.6106.5005", min_version:'14.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office14", bulletin:bulletin, kb:kb)
    ) vuln = TRUE;
  }
}
# Office 2007
else if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    kb = '2584063';
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"12.0.6562.5003", min_version:'12.0.0.0', path:x86_path+"\Microsoft Shared\Office14", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"12.0.6562.5003", min_version:'12.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:kb)
    ) vuln = TRUE;
  }
}
# Office 2003
else if (office_vers["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    kb = '2584052';
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"11.0.8341.0", min_version:'11.0.0.0', path:x86_path+"\Microsoft Shared\Office11", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"11.0.8341.0", min_version:'11.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office11", bulletin:bulletin, kb:kb)
    ) vuln = TRUE;
  }
}

if (vuln)
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
