#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33107);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2007-0216","CVE-2008-0105","CVE-2008-0108");
 script_bugtraq_id(27657,27658,27659);
 script_osvdb_id(41457, 41458, 41459);
 script_xref(name:"MSFT", value:"MS08-011");

 script_name(english:"MS08-011: Vulnerabilities in Microsoft Works File Converter Could Allow Remote Code Execution (947081)");
 script_summary(english:"Determines the version of Works Converter");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office Works
Converter that may allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it.  Then a bug in the wps
header handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-011");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, Works 8.0
and Works 2005.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(20, 119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS08-011';
kbs = make_list("943973");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = kb_smb_transport();
if (!is_accessible_share()) exit(0);

commonfiles = hotfix_get_officecommonfilesdir(officever:"11.0");
if  ( ! commonfiles ) exit(0);

if (hotfix_check_fversion(file:"works632.cnv", path:commonfiles +"\Microsoft Shared\TextConv", version:"7.3.1005.0", min_version:"7.0.0.0") == HCF_OLDER)
 {
 set_kb_item(name:"SMB/Missing/MS08-011", value:TRUE);
 hotfix_add_report(bulletin:'MS08-011', kb:'943973');
 hotfix_security_hole();
 }

hotfix_check_fversion_end();
