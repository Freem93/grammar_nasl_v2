#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50528);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2010-2573",
    "CVE-2010-3333",
    "CVE-2010-3334",
    "CVE-2010-3335",
    "CVE-2010-3336",
    "CVE-2010-3337"
  );
  script_bugtraq_id(42628, 44628, 44652, 44656, 44659, 44660);
  script_osvdb_id(69085, 69086, 69087, 69088, 69089, 69091);
  script_xref(name:"EDB-ID", value:"17474");
  script_xref(name:"MSFT", value:"MS10-087");

  script_name(english:"MS10-087: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2423930)");
  script_summary(english:"Checks version of mso.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office that
is affected by several vulnerabilities :

  - An integer underflow exists in the way the application
    parses the PowerPoint file format, which could lead to
    heap corruption and allow for arbitrary code execution
    when opening a specially crafted PowerPoint file.
    (CVE-2010-2573)

  - A stack-based buffer overflow can be triggered when
    parsing specially crafted RTF files, leading to
    arbitrary code execution. (CVE-2010-3333)

  - A memory corruption vulnerability exists in the way
    the application parses specially crafted Office files
    containing Office Art Drawing records. (CVE-2010-3334)

  - A memory corruption vulnerability exists in the way
    drawing exceptions are handled when opening specially
    crafted Office files. (CVE-2010-3335)

  - A memory corruption vulnerability exists in the way
    the application parses specially crafted Office files.
    (CVE-2010-3336)

  - A DLL preloading (aka binary planting) vulnerability
    exists because the application insecurely looks in
    its current working directory when resolving DLL
    dependencies. (CVE-2010-3337)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-087");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office XP, 2003, 2007, and
2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-087 Microsoft Word RTF pFragments Stack Buffer Overflow (File Format)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS10-087';
kbs = make_list("2289158", "2289161", "2289169", "2289187");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

arch = get_kb_item_or_exit("SMB/ARCH");
office_vers = hotfix_check_office_version();
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");
vuln = FALSE;

x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

# Office 2010
if (office_vers["14.0"])
{
  if (
    hotfix_is_vulnerable(file:"Mso.dll", version:"14.0.5128.5000", min_version:'14.0.0.0', path:x86_path+"\Microsoft Shared\Office14", bulletin:bulletin, kb:"2289161") ||
    hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"14.0.5128.5000", min_version:'14.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office14", bulletin:bulletin, kb:"2289161")
  ) vuln = TRUE;
}
# Office 2007
if (office_vers["12.0"])
{
  sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(sp) && sp == 2)
  {
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"12.0.6545.5004", min_version:'12.0.0.0', path:x86_path+"\Microsoft Shared\Office12", bulletin:bulletin, kb:"2289158") ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"12.0.6545.5004", min_version:'12.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:"2289158")
    ) vuln = TRUE;
  }
}
# Office 2003
if (office_vers["11.0"])
{
  sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(sp) && sp == 3)
  {
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"11.0.8329.0", min_version:'11.0.0.0', path:x86_path+"\Microsoft Shared\Office11", bulletin:bulletin, kb:"2289187") ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"11.0.8329.0", min_version:'11.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office11", bulletin:bulletin, kb:"2289187")
    ) vuln = TRUE;
  }
}
# Office XP
if (office_vers["10.0"])
{
  sp = get_kb_item("SMB/Office/XP/SP");
  if (!isnull(sp) && sp == 3)
  {
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"10.0.6867.0", path:x86_path+"\Microsoft Shared\Office10", bulletin:bulletin, kb:"2289169") ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"10.0.6867.0", path:x64_path+"\Common Files\Microsoft Shared\Office10", bulletin:bulletin, kb:"2289169")
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
