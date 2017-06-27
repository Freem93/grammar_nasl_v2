#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12205);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
  "CVE-2003-0533", "CVE-2003-0663", "CVE-2003-0719", "CVE-2003-0806",
  "CVE-2003-0906", "CVE-2003-0907", "CVE-2003-0908", "CVE-2003-0909",
  "CVE-2003-0910", "CVE-2004-0117", "CVE-2004-0118", "CVE-2004-0119",
  "CVE-2004-0121"
 );
 script_bugtraq_id(10111, 10113, 10117, 10119, 10122, 10124, 10125);
 script_osvdb_id(
  4168,
  5248,
  5249,
  5250,
  5251,
  5252,
  5253,
  5254,
  5255,
  5256,
  5257,
  5258,
  5259
 );
 script_xref(name:"CERT", value:"305206");
 script_xref(name:"CERT", value:"753212");
 script_xref(name:"CERT", value:"639428");
 script_xref(name:"CERT", value:"471260");
 script_xref(name:"CERT", value:"547028");
 script_xref(name:"CERT", value:"260588");
 script_xref(name:"CERT", value:"526084");
 script_xref(name:"CERT", value:"206468");
 script_xref(name:"CERT", value:"353956");
 script_xref(name:"CERT", value:"122076");
 script_xref(name:"CERT", value:"783748");
 script_xref(name:"CERT", value:"638548");
 script_xref(name:"MSFT", value:"MS04-011");

 script_name(english:"MS04-011: Microsoft Hotfix (credentialed check) (835732)");
 script_summary(english:"Checks for ms04-011");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a critical Microsoft Windows Security Update
(835732).

This update fixes various flaws that could allow an attacker to execute
arbitrary code on the remote host.

A series of worms (Sasser) are known to exploit this vulnerability in
the wild.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-011");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS04-011 Microsoft Private Communications Transport Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/04/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS04-011';
kb = '835732';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,4', xp:'0,1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Lsasrv.dll", version:"5.2.3790.134", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Lsasrv.dll", version:"5.1.2600.1361", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Lsasrv.dll", version:"5.1.2600.134", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Lsasrv.dll", version:"5.0.2195.6902", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Winsrv.dll", version:"4.0.1381.7260", dir:"\system32", bulletin:bulletin, kb:kb)
)
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
