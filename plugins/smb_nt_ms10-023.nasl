#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45510);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-0479");
  script_bugtraq_id(39347);
  script_osvdb_id(63748);
  script_xref(name:"MSFT", value:"MS10-023");

  script_name(english:"MS10-023: Vulnerability in Microsoft Office Publisher Could Allow Remote Code Execution (981160)");
  script_summary(english:"Checks the version of Publisher");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote host has a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Publisher component of Microsoft Office installed on the remote
host has a buffer overflow vulnerability.

A remote attacker could exploit this by tricking a user into opening a
specially crafted Publisher file, resulting in remote code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-023");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Microsoft Office XP,
2003, and 2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-023';
kbs = make_list("980466", "980469", "980470");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;
get_kb_item_or_exit("SMB/WindowsVersion");
installs = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Publisher/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';

  v = split(version, sep:'.', keep:FALSE);
  for (i = 0; i < max_index(v); i++)
    v[i] = int(v[i]);

  # Office XP SP3
  if (v[0] == 10 && v[1] == 0 && v[2] < 6861)
  {
    vuln++;
    kb = "980466";
    info = '\n  Product           : Publisher 2002'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 10.0.6861.0\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
  # Office 2003 SP3
  else if (v[0] == 11 && v[1] == 0 && v[2] < 8321)
  {
    vuln++;
    kb = "980469";
    info = '\n  Product           : Publisher 2003'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 11.0.8321.0\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
  # Office 2007 SP1/SP2
  else if (v[0] == 12 && v[1] == 0 && (v[2] < 6527 || (v[2] == 6527 && v[3] < 5000)))
  {
    vuln++;
    kb = "980470";
    info = '\n  Product           : Publisher 2007'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 12.0.6527.5000\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
}
if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
