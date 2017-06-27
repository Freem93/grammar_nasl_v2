#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57277);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2011-1508", "CVE-2011-3410", "CVE-2011-3411", "CVE-2011-3412");
  script_bugtraq_id(50090, 50943, 50949, 50955);
  script_osvdb_id(76460, 77670, 77671, 77672);
  script_xref(name:"CERT", value:"361441");
  script_xref(name:"MSFT", value:"MS11-091");

  script_name(english:"MS11-091: Vulnerabilities in Microsoft Publisher Could Allow Remote Code Execution (2607702)");
  script_summary(english:"Checks the version of Publisher");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Publisher component of Microsoft Office installed on the remote
host is affected by multiple vulnerabilities :

  - The application could allow overwriting function
    pointers in memory. (CVE-2011-1508)

  - The application could allow indexing an out-of-bounds
    array in memory. (CVE-2011-3410)

  - The application has an invalid pointer vulnerability.
    (CVE-2011-3411)

  - The application has a memory corruption vulnerability.
    (CVE-2011-3412)

A remote attacker could exploit these by tricking a user into opening
a specially crafted Publisher file, resulting in remote code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-091");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Microsoft Office 2003
and 2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");


bulletin = 'MS11-091';
kbs = make_list("2553084", "2596705");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

installs = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
vuln = FALSE;
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Publisher/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';

  v = split(version, sep:'.', keep:FALSE);
  for (i = 0; i < max_index(v); i++)
    v[i] = int(v[i]);


  kb = "";
  # Office 2003 SP3
  if (v[0] == 11 && v[1] == 0 && v[2] < 8342)
  {
    vuln = TRUE;
    info = '\n  Product           : Publisher 2003'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 11.0.8342.0\n';
    kb = "2553084";
  }
  # Office 2007 SP2/SP3
  else if (v[0] == 12 && v[1] == 0 && (v[2] < 6652 || (v[2] == 6652 && v[3] < 5000)))
  {
    vuln = TRUE;
    info = '\n  Product           : Publisher 2007'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 12.0.6652.5000\n';
    kb = "2596705";
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_add_report(info, bulletin:bulletin, kb:kb);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
