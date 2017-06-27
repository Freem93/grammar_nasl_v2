#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33870);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2008-2463");
 script_bugtraq_id(30114);
 script_osvdb_id(46749);
 script_xref(name:"CERT", value:"837785");
 script_xref(name:"MSFT", value:"MS08-041");

 script_name(english:"MS08-041: Vulnerability in the ActiveX Control for the Snapshot Viewer for Microsoft Access Could Allow Remote Code Execution (955617)");
 script_summary(english:"Determines the presence of update 955617");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the ActiveX control for the
Snapshot Viewer for Microsoft Access which is vulnerable to a security
flaw that could allow an attacker to execute arbitrary code on the
remote host by constructing a malicious web page and entice a victim to
visit it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-041");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2000, XP
and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Snapshot Viewer for Microsoft Access ActiveX Control Arbitrary File Download');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
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


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-041';
kbs = make_list("955617");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);



kb = '955617';

if (is_accessible_share())
{
 path1 = hotfix_get_commonfilesdir() + "\Microsoft Shared\Snapshot Viewer";
 path2 = hotfix_get_commonfilesdir() + "\System";
 if ( hotfix_check_fversion (path:path1, file:"snapview.ocx", version:"11.0.8228.0", bulletin:bulletin, kb:kb )  == HCF_OLDER ||
      hotfix_check_fversion (path:path2, file:"snapview.ocx", version:"11.0.8228.0", bulletin:bulletin, kb:kb )  == HCF_OLDER )
 {
 set_kb_item(name:"SMB/Missing/MS08-041", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
 exit (0);
}
