#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16333);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2004-0847");
 script_bugtraq_id(11342);
 script_osvdb_id(10557, 10670);
 script_xref(name:"MSFT", value:"MS05-004");
 script_xref(name:"CERT", value:"283646");
 script_xref(name:"EDB-ID", value:"24666");

 script_name(english:"MS05-004: ASP.NET Path Validation Vulnerability (887219)");
 script_summary(english:"Determines the version of the ASP.Net DLLs");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to access confidential documents on the remote web
server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ASP.NET framework that could
allow an attacker to bypass the security of an ASP.NET website and
obtain unauthorized access.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-004");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-004';
kbs = make_list("886905");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


if (hotfix_check_sp(win2k:6, xp:3, win2003:3) <= 0) exit(0, "The Host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  hotfix_is_vulnerable(file:"System.web.dll", min_version:"1.0.0.0", version:"1.0.3705.0", dir:"\Microsoft.Net\Framework\v1.0.3705", bulletin:bulletin, kb:'886905') ||
  hotfix_is_vulnerable(file:"System.web.dll", min_version:"1.0.3705.0", version:"1.0.3705.556", dir:"\Microsoft.Net\Framework\v1.0.3705", bulletin:bulletin, kb:'886905') ||
  hotfix_is_vulnerable(file:"System.web.dll", min_version:"1.0.3705.1001", version:"1.0.3705.6021", dir:"\Microsoft.Net\Framework\v1.0.3705", bulletin:bulletin,kb:'886906') ||

  hotfix_is_vulnerable(file:"System.web.dll", min_version:"1.1.0.0", version:"1.1.4322.0", dir:"\Microsoft.Net\Framework\v1.1.4322", bulletin:bulletin, kb:'886904') ||
  hotfix_is_vulnerable(file:"System.web.dll", min_version:"1.1.4322.0", version:"1.1.4322.1085", dir:"\Microsoft.Net\Framework\v1.1.4322", bulletin:bulletin, kb:'886904') ||
  hotfix_is_vulnerable(file:"System.web.dll", min_version:"1.1.4322.2001", version:"1.1.4322.2037", dir:"\Microsoft.Net\Framework\v1.1.4322", bulletin:bulletin, kb:'886903')
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}
