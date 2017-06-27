#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18682);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-2087");
 script_bugtraq_id(14087);
 script_osvdb_id(17680);
 script_xref(name:"MSFT", value:"MS05-037");
 script_xref(name:"CERT", value:"939605");
 script_xref(name:"EDB-ID", value:"1079");

 script_name(english:"MS05-037: Vulnerability in JView Profiler Could Allow Code Execution (903235)");
 script_summary(english:"Determines the presence of update 903235");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the JView Profiler module that
is vulnerable to a security flaw that may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and enticing a victim to visit this web page.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-037");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl","smb_nt_ms05-038.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-037';
kb = '903235';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);


if ( hotfix_ie_gt(7) != 0 ) exit(0);
if ( hotfix_missing(name:"896727") <= 0 ) exit(0);
if ( hotfix_missing(name:"896688") <= 0 ) exit(0);
if ( hotfix_missing(name:"905915") <= 0 ) exit(0);
if ( hotfix_missing(name:"903235") > 0 )
{
 if (get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{03D9F3F2-B0E3-11D2-B081-006008039BF0}"))
   exit (0);

 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
 if ( "903235" >!< minorversion ) {
 set_kb_item(name:"SMB/Missing/MS05-037", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
}
