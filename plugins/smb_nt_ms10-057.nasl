#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48294);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/07/14 14:10:24 $");

  script_cve_id("CVE-2010-2562");
  script_bugtraq_id(42199);
  script_osvdb_id(66991);
  script_xref(name:"MSFT", value:"MS10-057");

  script_name(english:"MS10-057: Vulnerability in Microsoft Office Excel Could Allow Remote Code Execution (2269707)");
  script_summary(english:"Checks version of Excel");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Excel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Microsoft Office Excel 2002 or
2003 that is affected by a memory corruption vulnerability.

If an attacker can trick a user on the affected system into opening a
specially crafted Excel file using the affected application, he may be
able to leverage this issue to execute arbitrary code subject to the
user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-057");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office Excel 2002 and
Office Excel 2003."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-057';
kbs = make_list("2264397", "2264403");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

info = "";

vuln = 0;
kb = "";
# Excel.
installs = get_kb_list_or_exit("SMB/Office/Excel/*/ProductPath", exit_code:1);
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Excel/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Excel 2003.
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (
    (!isnull(office_sp) && office_sp == 3) &&
    (ver[0] == 11 && ver[1] == 0 && ver[2] < 8326)
  )
  {
    vuln++;
    info =
      '\n  Product           : Excel 2003' +
      '\n  File              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.0.8326.0\n';
    kb = '2264403';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
  # Excel 2002.
  office_sp = get_kb_item("SMB/Office/XP/SP");
  if (
    (!isnull(office_sp) && office_sp == 3) &&
    (ver[0] == 10 && ver[1] == 0 && ver[2] < 6864)
  )
  {
    vuln++;
    info =
      '\n  Product           : Excel 2002' +
      '\n  File              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.0.6864.0\n';
    kb = '2264397';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-057", value:TRUE);

  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
