#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35633);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/11/20 22:07:59 $");

  script_cve_id("CVE-2009-0095", "CVE-2009-0096", "CVE-2009-0097");
  script_bugtraq_id(33659, 33660, 33661);
  script_osvdb_id(51834, 51835, 51836);
  script_xref(name:"MSFT", value:"MS09-005");

  script_name(english:"MS09-005: Vulnerabilities in Microsoft Office Visio Could Allow Remote Code Execution (957634)");
  script_summary(english:"Determines the presence of update 957634");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visio.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that is affected
by memory corruption and memory validation vulnerabilities triggered
when parsing specially crafted Visio files that could be be abused to
execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to send a
specially crafted Visio document to a user on the remote host and
trick him into opening it.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-005");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio 2002, 2003
and 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-005';
kbs = make_list("955654", "955655", "957381");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;
share = '';
lastshare = '';
accessibleshare = FALSE;
visioinstalls = get_kb_list_or_exit("SMB/Office/Visio/*/VisioPath");
foreach install (keys(visioinstalls))
{
  if ("12.0" >< install || "11.0" >< install || "10.0" >< install)
  {
    path = visioinstalls[install];
  }
  else continue;

  share = hotfix_path2share(path:path);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (is_accessible_share(share:share))
    {
      accessibleshare = TRUE;
    }
    else accessibleshare = FALSE;
  }
  if (accessibleshare)
  {
    if ("12.0" >< install)  # Visio 2007
    {
      if (hotfix_check_fversion(path:path, file:"Vislib.dll", version:"12.0.6336.5001", bulletin:bulletin, kb:"957381") == HCF_OLDER) vuln++;
    }
    else if ("11.0" >< install)  # Visio 2003
    {
      if (hotfix_check_fversion(path:path, file:"Visio11\Vislib.dll", version:"11.0.8223.0", bulletin:bulletin, kb:"955655") == HCF_OLDER) vuln++;
    }
    else if ("10.0" >< install)  # Visio 2002
    {
      if ( hotfix_check_fversion(path:path, file:"Visio10\Vislib.dll", version:"10.0.6885.4", bulletin:bulletin, kb:"955654") == HCF_OLDER) vuln++;
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
