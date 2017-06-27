#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20172);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-2123", "CVE-2005-2124", "CVE-2005-0803");
 script_bugtraq_id (15352,15356);
 script_osvdb_id(14862, 18820, 20579, 20580);
 script_xref(name:"MSFT", value:"MS05-053");
 script_xref(name:"CERT", value:"134756");
 script_xref(name:"CERT", value:"300549");
 script_xref(name:"CERT", value:"433341");
 script_xref(name:"EDB-ID", value:"1343");
 script_xref(name:"EDB-ID", value:"25231");

 script_name(english:"MS05-053: Vulnerabilities in Graphics Rendering Engine Could Allow Code Execution (896424)");
 script_summary(english:"Determines the presence of update 896424");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host by sending a
malformed file to a victim.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows missing a
critical security update to fix several vulnerabilities in the Graphic
Rendering Engine, and in the way Windows handles Metafiles.

An attacker could exploit these flaws to execute arbitrary code on the
remote host by sending a specially crafted Windows Metafile (WMF) or
Enhanced Metafile (EMF) to a victim on the remote host.  When viewing
the malformed file, a buffer overflow condition occurs that may allow
the execution of arbitrary code with the privileges of the user.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-053");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP SP2 and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Interleaved document.write/appendChild Memory Corruption');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/11/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/08");

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


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-053';
kb = '896424';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"gdi32.dll", version:"5.2.3790.419", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"gdi32.dll", version:"5.2.3790.2542", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"gdi32.dll", version:"5.1.2600.1755", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"gdi32.dll", version:"5.1.2600.2770", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"gdi32.dll", version:"5.0.2195.7069", dir:"\system32", bulletin:bulletin, kb:kb)
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
