#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79831);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-6364");
  script_bugtraq_id(71474);
  script_osvdb_id(115583);
  script_xref(name:"MSFT", value:"MS14-082");
  script_xref(name:"IAVA", value:"2014-A-0187");

  script_name(english:"MS14-082: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3017349)");
  script_summary(english:"Checks the version of FM20.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office that
is affected by a remote code execution vulnerability due to a
use-after-free memory issue caused by Microsoft Word not properly
handling objects in memory. A remote attacker can exploit this
vulnerability by convincing a user to open a specially crafted Office
file, resulting in execution of arbitrary code in the context of the
current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-082");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

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

bulletin = 'MS14-082';
kbs = make_list("2596927", "2553154", "2726958");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_ver = hotfix_check_office_version();
if (isnull(office_ver)) audit(AUDIT_NOT_INST, "Microsoft Office");

vuln = 0;

# Office 2013 SP0 or SP1
if (office_ver['15.0'])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  bitness = get_kb_item("SMB/Office/15.0/Bitness");
  if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
  {
    if (!isnull(bitness) && bitness == 'x64')
    {
      if (
        hotfix_is_vulnerable(file:"FM20.DLL", version:"15.0.4675.1001", dir:"\System32", bulletin:bulletin, kb:"2726958")
      ) vuln++;
    }
    else if (!isnull(bitness) && bitness == 'x86')
    {
      if (
        hotfix_is_vulnerable(file:"FM20.DLL", arch:"x64", version:"15.0.4675.1001", dir:"\SysWOW64", bulletin:bulletin, kb:"2726958") ||
        hotfix_is_vulnerable(file:"FM20.DLL", arch:"x86", version:"15.0.4675.1001", dir:"\System32", bulletin:bulletin, kb:"2726958")
      ) vuln++;
    }
  }
}

# Office 2010 SP2
if (office_ver['14.0'])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  bitness = get_kb_item("SMB/Office/14.0/Bitness");
  if (!isnull(office_sp) && office_sp == 2)
  {
    if (!isnull(bitness) && bitness == 'x64')
    {
      if (
        hotfix_is_vulnerable(file:"FM20.DLL", version:"14.0.7140.5001", dir:"\System32", bulletin:bulletin, kb:"2553154")
      ) vuln++;
    }
    else if (!isnull(bitness) && bitness == 'x86')
    {
      if (
        hotfix_is_vulnerable(file:"FM20.DLL", arch:"x64", version:"14.0.7140.5001", dir:"\SysWOW64", bulletin:bulletin, kb:"2553154") ||
        hotfix_is_vulnerable(file:"FM20.DLL", arch:"x86", version:"14.0.7140.5001", dir:"\System32", bulletin:bulletin, kb:"2553154")
      ) vuln++;
    }
  }
}

# Office 2007 SP3
if (office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    if (
      hotfix_is_vulnerable(file:"FM20.dll", arch:"x86", version:"12.0.6713.5000", dir:"\System32", bulletin:bulletin, kb:"2596927") ||
      hotfix_is_vulnerable(file:"FM20.dll", arch:"x64", version:"12.0.6713.5000", dir:"\SysWOW64", bulletin:bulletin, kb:"2596927")
    ) vuln++;
  }
}

if (vuln)
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
