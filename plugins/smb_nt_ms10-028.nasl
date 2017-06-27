#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45515);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0254", "CVE-2010-0256", "CVE-2010-1681");
  script_bugtraq_id(39300, 39302, 39836);
  script_osvdb_id(63741, 63742, 64446);
  script_xref(name:"EDB-ID", value:"17451");
  script_xref(name:"MSFT", value:"MS10-028");

  script_name(english:"MS10-028: Vulnerabilities in Microsoft Visio Could Allow Remote Code Execution (980094)");
  script_summary(english:"Checks Visio version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote Windows host through
Visio."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Microsoft Visio that is
affected by multiple memory corruption vulnerabilities.

A remote attacker could exploit this by tricking a user into opening a
specially crafted Visio file, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-028");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Visio 2002, 2003, and
2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Office Visio VISIODWG.DLL DXF File Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-028';
kbs = make_list("979365");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");


version = get_kb_item_or_exit("SMB/Office/Visio");
if (!eregmatch(pattern:"^1[0-2]\.0[^0-9]", string:version))
  exit(0, "The installed version of Visio is not one of those affected.");

vuln = 0;
share = '';
lastshare = '';
accessibleshare = FALSE;

installs = get_kb_list_or_exit("SMB/Office/Visio/*/VisioPath");
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Visio/' - '/VisioPath';
  path = installs[install];
  share = hotfix_path2share(path:path);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (!is_accessible_share())
    {
      accessibleshare = FALSE;
    }
    else accessibleshare = TRUE;
  }

  if (accessibleshare)
  {
    if (
      # Visio 2007
      ("12.0" >< version &&
       hotfix_is_vulnerable(path:path, file:"Vislib.dll", version:"12.0.6524.5003", bulletin:bulletin, kb:"979365")) ||

      # Visio 2003
      ("11.0" >< version &&
       hotfix_is_vulnerable(path:path, file:"Visio11\Vislib.dll", version:"11.0.8321.0", bulletin:bulletin, kb:"979356")) ||

      # Visio 2002
      ("10.0" >< version &&
       hotfix_is_vulnerable(path:path, file:"Visio10\Vislib.dll", version:"10.0.6890.4", bulletin:bulletin, kb:"979364"))
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
