#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51175);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/07/07 15:05:40 $");

  script_cve_id("CVE-2010-2569", "CVE-2010-2570", "CVE-2010-2571", "CVE-2010-3954", "CVE-2010-3955");
  script_bugtraq_id(45277, 45279, 45280, 45281, 45282);
  script_osvdb_id(69811, 69812, 69813, 69814, 69815);
  script_xref(name:"IAVA", value:"2010-A-0171");
  script_xref(name:"MSFT", value:"MS10-103");

  script_name(english:"MS10-103: Vulnerabilities in Microsoft Publisher Could Allow Remote Code Execution (2292970)");
  script_summary(english:"Checks the version of publisher");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote host has
multiple memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Publisher component of Microsoft Office installed on the remote
host has multiple memory corruption vulnerabilities.

A remote attacker could exploit these by tricking a user into opening
a specially crafted Publisher file, resulting in remote code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-103");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Microsoft Office XP, 2003,
2007, and 2010."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-103';
kbs = make_list("2284692", "2284695", "2284697", "2409055");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

installs = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Publisher/' - '/ProductPath';
  path = installs[install];

  v = split(version, sep:'.', keep:FALSE);
  for (i = 0; i < max_index(v); i++)
    v[i] = int(v[i]);


  kb = "";
  info = NULL;
  # Office XP SP3
  if (v[0] == 10 && v[1] == 0 && v[2] < 6867)
  {
    info = '\n  Product           : Publisher 2002'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 10.0.6867.0\n';
    kb = "2284692";
  }
  # Office 2003 SP3
  else if (v[0] == 11 && v[1] == 0 && v[2] < 8329)
  {
    info = '\n  Product           : Publisher 2003'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 11.0.8329.0\n';
    kb = "2284695";
  }
  # Office 2007 SP1/SP2
  else if (v[0] == 12 && v[1] == 0 && (v[2] < 6546 || (v[2] == 6546 && v[3] < 5000)))
  {
    info = '\n  Product           : Publisher 2007'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 12.0.6546.5000\n';
    kb = "2284697";
  }
  # Office 2010
  else if (v[0] == 14 && v[1] == 0 && (v[2] < 5126 || (v[2] == 5126 && v[3] < 5000)))
  {
    info = '\n  Product           : Publisher 2010'+
           '\n  File              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 14.0.5126.5000\n';
    kb = "2409055";
  }
  if (info)
  {
    vuln++;
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-103', value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
