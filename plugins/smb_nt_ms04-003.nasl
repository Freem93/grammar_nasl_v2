#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11990);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2003-0903");
 script_bugtraq_id(9407);
 script_osvdb_id(3457);
 script_xref(name:"MSFT", value:"MS04-003");

 script_name(english:"MS04-003: MDAC Buffer Overflow (832483)");
 script_summary(english:"Checks the version of MDAC");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through MDAC server.");
 script_set_attribute(attribute:"description", value:
"The remote Microsoft Data Access Component (MDAC) server is vulnerable
to a flaw that could allow an attacker to execute arbitrary code on this
host, provided he can simulate responses from a SQL server.

To exploit this flaw, an attacker would need to wait for a host running
a vulnerable MDAC implementation to send a broadcast query.  He would
then need to send a malicious packet pretending to come from a SQL
server.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-003");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_access_components");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS04-003';
kb = '832483';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");
if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0, "Host is not affected based on its version / service pack.");

if ( ( version =  hotfix_data_access_version()) == NULL ) exit(0, "hotfix_data_access_version() failed.");
if(ereg(pattern:"^2\.6[3-9].*", string:version))exit(0, "SP3 applied"); # SP3 applied

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"3.0.0.0", version:"3.70.11.46", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.80.0.0", version:"2000.80.747.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.81.0.0", version:"2000.81.9002.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.81.9030.0", version:"2000.81.9042.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.85.0.0", version:"2000.85.1025.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS04-003", value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}
