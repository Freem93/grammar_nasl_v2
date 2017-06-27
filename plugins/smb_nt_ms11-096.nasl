#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57282);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-3403");
  script_bugtraq_id(50954);
  script_osvdb_id(77661);
  script_xref(name:"MSFT", value:"MS11-096");

  script_name(english:"MS11-096: Vulnerability in Microsoft Excel Could Allow Remote Code Execution (2640241)");
  script_summary(english:"Checks version of Excel");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Office 2003
that contains a remote code execution vulnerability in Excel.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, he could leverage this issue to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-096");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = "MS11-096";
kb = "2596954";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

# Excel.
installs = get_kb_list_or_exit("SMB/Office/Excel/*/ProductPath");
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Excel/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';

  ver = split(version, sep:".", keep:FALSE);
  for (i = 0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Excel 2003.
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if ((!isnull(office_sp) && office_sp == 3) && (ver[0] == 11 && ver[1] == 0 && ver[2] < 8342))
  {
    info =
      '\n  Product           : Excel 2003' +
      '\n  File              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.0.8342.0' +
      '\n';

    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_security_hole();
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, 'affected');
