#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25692);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-4360");
 script_bugtraq_id(15921);
 script_osvdb_id(21805);
 script_xref(name:"MSFT", value:"MS07-041");
 script_xref(name:"EDB-ID", value:"1376");

 script_name(english:"MS07-041: Vulnerability in Microsoft Internet Information Services Could Allow Remote Code Execution (939373)");
 script_summary(english:"Checks for ms07-041 over the registry");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote web server.");
 script_set_attribute(attribute:"description", value:
"The remote host has a version of IIS that is vulnerable to a remote
flaw that could allow an attacker to take the control of the remote web
server and execute arbitrary commands on the remote host with the SYSTEM
privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-041");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 5.1 on Windows XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/16");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-041';
kb = "939373";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(os:"5.1", sp:2, file:"w3svc.dll", version:"5.1.2600.3163", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb))
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
