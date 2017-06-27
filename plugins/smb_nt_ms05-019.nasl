#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18023);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2016/05/06 17:11:37 $");

 script_cve_id(
  "CVE-2004-0230",
  "CVE-2004-0790",
  "CVE-2004-1060",
  "CVE-2005-0048",
  "CVE-2005-0065",
  "CVE-2005-0066",
  "CVE-2005-0067",
  "CVE-2005-0068",
  "CVE-2005-0688"
 );
 script_bugtraq_id(13116, 13124, 13658);
 script_osvdb_id(
  4030,
  14578,
  15457,
  15463,
  15619,
  15620,
  15621,
  15622,
  15623
 );
 script_xref(name:"MSFT", value:"MS05-019");
 script_xref(name:"CERT", value:"222750");
 script_xref(name:"CERT", value:"233754");
 script_xref(name:"CERT", value:"396645");
 script_xref(name:"CERT", value:"415294");
 script_xref(name:"EDB-ID", value:"276");
 script_xref(name:"EDB-ID", value:"291");
 script_xref(name:"EDB-ID", value:"861");
 script_xref(name:"EDB-ID", value:"948");
 script_xref(name:"EDB-ID", value:"24030");
 script_xref(name:"EDB-ID", value:"24031");
 script_xref(name:"EDB-ID", value:"24032");
 script_xref(name:"EDB-ID", value:"24033");
 script_xref(name:"EDB-ID", value:"25383");
 script_xref(name:"EDB-ID", value:"25388");
 script_xref(name:"EDB-ID", value:"25389");

 script_name(english:"MS05-019: Vulnerabilities in TCP/IP Could Allow Remote Code Execution (893066)");
 script_summary(english:"Checks the remote registry for 893066");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
TCP/IP stack.");
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows that has a flaw in its TCP/IP
stack.

The flaw could allow an attacker to execute arbitrary code with SYSTEM
privileges on the remote host, or to perform a denial of service attack
against the remote host.

Proof of concept code is available to perform a Denial of Service
against a vulnerable system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-019");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-019';
kb = '893066';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'3,4', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Tcpip.sys", version:"5.2.3790.336", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Tcpip.sys", version:"5.1.2600.1693", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Tcpip.sys", version:"5.1.2600.2685", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Tcpip.sys", version:"5.0.2195.7049", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
