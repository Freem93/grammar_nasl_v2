#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21077);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-0023");
 script_bugtraq_id(16484);
 script_osvdb_id(23044, 23045, 23046, 23047);
 script_xref(name:"CERT", value:"953860");
 script_xref(name:"MSFT", value:"MS06-011");

 script_name(english:"MS06-011: Permissive Windows Services DACLs Could Allow Elevation of Privilege (914798)");
 script_summary(english:"Determines the presence of update 914798");

 script_set_attribute(attribute:"synopsis", value:
"Local users may be able to elevate their privileges on the remote
host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains services whose permissions are
set to such a way that low-privileged local users may be able to
change properties associated to each service and therefore manage to
elevate their privileges.

To exploit this flaw, an attacker would need credentials to log into
the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-011");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/31");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/03/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-011';
kb = '914798';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);


if ( hotfix_missing(name:kb) > 0 )
	 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }
