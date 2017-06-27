#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73983);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1809");
  script_bugtraq_id(67273);
  script_osvdb_id(106896);
  script_xref(name:"MSFT", value:"MS14-024");
  script_xref(name:"IAVB", value:"2014-B-0057");

  script_name(english:"MS14-024: Vulnerability in a Microsoft Common Control Could Allow Security Feature Bypass (2961033)");
  script_summary(english:"Checks version of mscomctl.ocx");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office that
contains a shared component (MSCOMCTL common controls library) that is
affected by a security feature bypass. Successful exploitation of the
issue could allow an attacker to bypass the Address Space Layout
Randomization (ASLR) security feature. An attacker would need to
entice a victim to visit a specially crafted web page with a browser
capable of instantiating COM components in order to exploit the issue.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-024");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS14-024';
kbs = make_list("2961033", "2880508", "2880507", "2880502", "2817330", "2760272", "2880971", "2810073", "2596804", "2589288");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_ver = hotfix_check_office_version();
if (isnull(office_ver)) audit(AUDIT_NOT_INST, "Microsoft Office");

project2007 = FALSE;
project2010 = FALSE;
project2013 = FALSE;
project_installs = get_kb_list("SMB/Office/Project/*/ProductPath");
if (project_installs && max_index(keys(project_installs)) > 0)
{
  foreach install (keys(project_installs))
  {
    version = install - 'SMB/Office/Project/' - '/ProductPath';
    if (version =~ '^12\\.') project2007 = TRUE;
    else if (version =~ '^14\\.') project2010 = TRUE;
    else if (version =~ '^15\\.') project2013 = TRUE;
  }
}

vuln = 0;

# Office 2013 SP0 or SP1
if (office_ver['15.0'])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
  {
    bitness = get_kb_item("SMB/Office/15.0/Bitness");
    if (!isnull(bitness) && bitness == 'x86')
    {
      if (
        hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2880502") ||
        hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2880502")
      ) vuln++;
    }
    if (
      project2013 &&
      (
        hotfix_is_vulnerable(file:"mscomct2.ocx", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2760272") ||
        hotfix_is_vulnerable(file:"mscomct2.ocx", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2760272")
      )
    ) vuln++;
  }
}

x86_path = hotfix_get_commonfilesdir();
x64_path = hotfix_get_programfilesdirx86();
# Office 2010 SP1 or SP2
if (office_ver['14.0'])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    # KB 2810073 only applies to Office 2010 32-bit
    bitness = get_kb_item("SMB/Office/14.0/Bitness");
    if (!isnull(bitness) && bitness == 'x86')
    {
      if (
        hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2810073") ||
        hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2810073")
      ) vuln++;
    }
    if (
      project2010 &&
      (
        hotfix_is_vulnerable(file:"mscomct2.ocx", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2589288") ||
        hotfix_is_vulnerable(file:"mscomct2.ocx", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2589288")
      )
    ) vuln++;
    if (
      (x86_path && hotfix_is_vulnerable(file:"msaddndr.dll", version:"6.1.98.39", path:x86_path + "\DESIGNER", bulletin:bulletin, kb:"2880971")) ||
      (x64_path && hotfix_is_vulnerable(file:"msaddndr.dll", arch:"x64", version:"6.1.98.39", path:x64_path + "\DESIGNER", bulletin:bulletin, kb:"2880971"))
    ) vuln++;
  }
}

# Office 2007 SP3
if (office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    if (
      hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2817330") ||
      hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2817330")
    ) vuln++;
    if (
      project2007 &&
      (
        hotfix_is_vulnerable(file:"mscomct2.ocx", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2596804") ||
        hotfix_is_vulnerable(file:"mscomct2.ocx", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2596804")
      )
    ) vuln++;
    if (
      hotfix_is_vulnerable(file:"msstdfmt.dll", version:"6.1.98.39", dir:"\System32", bulletin:bulletin, kb:"2880507") ||
      hotfix_is_vulnerable(file:"msstdfmt.dll", version:"6.1.98.39", dir:"\SysWOW64", bulletin:bulletin, kb:"2880507")
    ) vuln++;
    if (
      (x86_path && hotfix_is_vulnerable(file:"msaddndr.dll", version:"6.1.98.39", path:x86_path + "\DESIGNER", bulletin:bulletin, kb:"2880508")) ||
      (x64_path && hotfix_is_vulnerable(file:"msaddndr.dll", arch:"x64", version:"6.1.98.39", path:x64_path + "\DESIGNER", bulletin:bulletin, kb:"2880508"))
    ) vuln++;
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
