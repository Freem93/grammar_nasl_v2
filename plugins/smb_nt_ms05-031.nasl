#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18492);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2005-1212");
 script_bugtraq_id(13944);
 script_osvdb_id(17304);
 script_xref(name:"MSFT", value:"MS05-031");

 script_name(english:"MS05-031: Vulnerability in Step-by-Step Interactive Training (898458)");
 script_summary(english:"Determines the version of MRUN32.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the training
software.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Step-by-Step
Interactive Training that contains a flaw that could lead to remote
code execution.

To exploit this flaw, an attacker would need to trick a user on the
remote host into opening a malformed file with the affected
application.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-031");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS05-031';
kb = '898458';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

if ( hotfix_check_fversion(file:"mrun32.exe", version:"3.4.1.101", bulletin:bulletin, kb:kb) == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS05-031", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();
