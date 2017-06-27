#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51908);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2011-0092", "CVE-2011-0093");
  script_bugtraq_id(46137, 46138);
  script_osvdb_id(70828, 70829);
  script_xref(name:"MSFT", value:"MS11-008");

  script_name(english:"MS11-008: Vulnerabilities in Microsoft Visio Could Allow Remote Code Execution (2451879)");
  script_summary(english:"Checks version of Ormelems.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through
Visio.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that is
affected by multiple memory corruption vulnerabilities.

A remote attacker could exploit these by tricking a user into opening a
specially crafted Visio file, resulting in arbitrary code execution.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-008");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-063/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visio 2002, 2003, and
2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-008';
kbs = make_list("2434737");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;
share = '';
lastshare = '';
accessibleshare = FALSE;
installs = get_kb_list_or_exit("SMB/Office/Visio/*/ProductPath");

foreach install (keys(installs))
{
  version = install - 'SMB/Office/Visio/' - '/ProductPath';
  if ("10.0" >< version)
    path = hotfix_get_programfilesdir() + "\Common Files\Microsoft Shared\Modeling";
  else path = installs[install];

  share = hotfix_path2share(path:path);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (!is_accessible_share(share:share))
      accessibleshare = FALSE;
    else accessibleshare = TRUE;
  }

  if (accessibleshare)
  {
    if (
      # Visio 2007 - KB2434737
      (
        "12.0" >< version &&
      hotfix_is_vulnerable(path:path, file:"Ormelems.dll", version:"12.0.6548.5001", bulletin:bulletin, kb:"2434737")
      ) ||

      # Visio 2003 - KB2434733
      (
        "11.0" >< version &&
        hotfix_is_vulnerable(path:path, file:"Visio11\DLL\Ormelems.dll", version:"11.0.8321.0", bulletin:bulletin, kb:"2434733")
      ) ||

      # Visio 2002 - KB2434711
      (
        "10.0" >< version &&
        hotfix_is_vulnerable(path:path, file:"Ormelems.dll", version:"10.0.6890.4", bulletin:bulletin, kb:"2434711")
      )
    )
    {
      vuln++;
    }
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
