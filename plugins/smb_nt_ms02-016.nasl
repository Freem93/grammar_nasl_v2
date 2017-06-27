#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10945);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2002-0051");
 script_bugtraq_id(4438);
 script_osvdb_id(773);
 script_xref(name:"MSFT", value:"MS02-016");
 script_xref(name:"MSKB", value:"318593");

 script_name(english:"MS02-016: Opening Group Policy Files (318089)");
 script_summary(english:"Determines whether the Group Policy patch (Q318593) is installed");

 script_set_attribute(attribute:"synopsis", value:"A user can block access to GPO deployment.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Group Policy
Object (GPO) access right of Active Directory that could allow a user to
prevent the GPO to be applied to other users.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-016");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/04/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-016';
kb = '318593';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);


if ( hotfix_missing(name:"Q318593") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }


