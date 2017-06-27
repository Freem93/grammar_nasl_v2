#
# Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(31792);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2008-1089", "CVE-2008-1090");
 script_bugtraq_id(28555, 28556);
 script_osvdb_id(44169, 44170);
 script_xref(name:"MSFT", value:"MS08-019");

 script_name(english:"MS08-019: Vulnerabilities in Microsoft Visio Could Allow Remote Code Execution (949032)");
 script_summary(english:"Determines the presence of update 949032");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visio.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that has a vulnerability
in the way it handles object headers and validates memory which could be used
by an attacker to execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to spend a specially
crafted visio document to a user on the remote host and lure him into opening
it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-019");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio 2002, 2003
and 2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS08-019';
kbs = make_list("947590", "947650", "947896");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

list = get_kb_list_or_exit("SMB/Office/Visio/*/VisioPath");
share = '';
lastshare = '';
accessibleshare = FALSE;
vuln = 0;
foreach item (keys(list))
{
  path = list[item];
  share = hotfix_path2share(path:path);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (!is_accessible_share(share:share))
    {
      accessibleshare = FALSE;
      continue;
    }
    accessibleshare = TRUE;
  }

  if (accessibleshare)
  {
    if ("12.0" >< item) # Visio 2007
    {
      if (hotfix_check_fversion(path:path, file:"Vislib.dll", version:"12.0.6300.5000", bulletin:bulletin, kb:"947590") == HCF_OLDER)
      {
        vuln++;
      }
    }
    else if ("11.0" >< item) # Visio 2003
    {
      if ( hotfix_check_fversion(path:path, file:"Visio11\Vislib.dll", version:"11.0.8207.0", bulletin:bulletin, kb:"947650") == HCF_OLDER )
      {
        vuln++;
      }
    }
    else if ("10.0" >< item) # Visio 2002
    {
      if ( hotfix_check_fversion(path:path, file:"Visio10\Vislib.dll", version:"10.0.6871.4", bulletin:bulletin, kb:"947650") == HCF_OLDER )
      {
        vuln++;
      }
    }
  }
}
hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS08-019", value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
