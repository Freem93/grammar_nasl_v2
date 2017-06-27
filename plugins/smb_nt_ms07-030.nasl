#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25489);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/11/20 22:07:59 $");

 script_cve_id("CVE-2007-0934", "CVE-2007-0936");
 script_bugtraq_id(24349, 24384);
 script_osvdb_id(35342, 35343);
 script_xref(name:"MSFT", value:"MS07-030");

 script_name(english:"MS07-030: Vulnerabilities in Microsoft Visio Could Allow Remote Code Execution (927051)");
 script_summary(english:"Determines the presence of update 927051");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visio.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that has a
vulnerability in the way it handles packed objects and version numbers
that could be abused by an attacker to execute arbitrary code on the
remote host.

To exploit this vulnerability, an attacker would need to spend a
specially crafted visio document to a user on the remote host and lure
him into opening it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-030");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio 2002 and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-030';
kbs = make_list("931280", "931281");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


list = get_kb_list_or_exit("SMB/Office/Visio/*/VisioPath");

e = 0;
share = '';
lastshare = '';
accessible_share = FALSE;
errors = make_list();
foreach item (keys(list))
{
  share = hotfix_path2share(path:list[item]);
  if (share != lastshare || !accessible_share)
  {
    lastshare = share;
    if (!is_accessible_share(share:share))
    {
      accessible_share = FALSE;
      errors = make_list(errors, 'Failed to access \''+share+'\' / can\'t verify Visio install in \''+list[item]+'.');
      continue;
    }
    accessible_share = TRUE;
  }
  if (accessible_share)
  {
    vers = item - 'SMB/Office/Visio/' - '/VisioPath';
    if ( "11.0" >< vers )  # Visio 2003
    {
      path = list[item];
      if ( hotfix_check_fversion(path:path, file:"Visio11\Vislib.dll", version:"11.0.7218.0", bulletin:bulletin, kb:'931281') == HCF_OLDER ) e ++;
    }
    else if ( "10.0" >< vers )  # Vision 2002
    {
      path = list[item];
      if ( hotfix_check_fversion(path:path, file:"Visio10\Vislib.dll", version:"10.0.6865.4", bulletin:bulletin, kb:'931280') == HCF_OLDER ) e ++;
    }
  }
}
hotfix_check_fversion_end();
if ( e )
{
  set_kb_item(name:"SMB/Missing/MS07-030", value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
