#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55790);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/26 19:18:37 $");

  script_cve_id("CVE-2011-1972", "CVE-2011-1979");
  script_bugtraq_id(49021, 49024);
  script_osvdb_id(74397, 74398);
  script_xref(name:"MSFT", value:"MS11-060");

  script_name(english:"MS11-060: Vulnerabilities in Microsoft Visio Could Allow Remote Code Execution (2560978)");
  script_summary(english:"Checks version of Visio.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through
Visio.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that is
affected by multiple remote code execution vulnerabilities.

A remote attacker could exploit these issues by tricking a user into
opening a specially crafted Microsoft Visio file, resulting in
arbitrary code execution.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-060");
  script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Visio 2003, 2007, and 2010.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS11-060';
kbs = make_list("2553008");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

installs = get_kb_list_or_exit("SMB/Office/Visio/*/VisioPath");
share = '';
lastshare = '';
accessibleshare = FALSE;
vuln = 0;
foreach install (keys(installs))
{
  if ("14.0" >< install || "12.0" >< install || "11.0" >< install)
  {
    version = install - 'SMB/Office/Visio/' - '/VisioPath';
    path = installs[install];

    share = hotfix_path2share(path:path);
    if (lastshare != share)
    {
      lastshare = share;
      if (is_accessible_share(share:share)) accessibleshare = TRUE;
      else accessibleshare = FALSE;
    }

    if (accessibleshare)
    {
      if (
        # Visio 2010
        (
          "14.0" >< version &&
          hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.6106.5000", bulletin:bulletin, kb:"2553008")
        ) ||

        # Visio 2007
        (
          "12.0" >< version &&
          hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6556.5000", bulletin:bulletin, kb:"2553010")
        ) ||

        # Visio 2003
        (
          "11.0" >< version &&
          hotfix_is_vulnerable(path:path, file:"Visio11\Visio.exe", version:"11.0.8207.0", bulletin:bulletin, kb:"2553009")
        )
      )
      {
        vuln++;
      }
    }
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
