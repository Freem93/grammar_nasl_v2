#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45509);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0483");
  script_bugtraq_id(38463);
  script_osvdb_id(62632);
  script_xref(name:"CERT", value:"612021");
  script_xref(name:"MSFT", value:"MS10-022");

  script_name(english:"MS10-022: Vulnerability in VBScript Scripting Engine Could Allow Remote Code Execution (981169)");
  script_summary(english:"Checks version of Vbscript.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the
installed VBScript Scripting Engine."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of the VBScript Scripting Engine allows an
attacker to specify a Help file location when displaying a dialog box
on a web page.  If a user can be tricked into pressing the F1 key
while such a dialog box is being displayed, an attacker can leverage
this to cause the Windows Help System to load a specially crafted Help
file, resulting in execution of arbitrary code subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-022");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-022 Microsoft Internet Explorer Winhlp32.exe MsgBox Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-022';
kbs = make_list("981332", "981349", "981350");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7600.20662", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:"981332") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7600.16546", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:"981332") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.8.6001.23000", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:"981332") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.8.6001.18909", min_version:"5.8.0.0",        dir:"\System32", bulletin:bulletin, kb:"981332") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.6002.22354", min_version:"5.7.6002.22000", dir:"\System32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.6002.18222", min_version:"5.7.6002.0",     dir:"\System32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.0.22648",    min_version:"5.7.0.22000",    dir:"\System32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.0.18440",    min_version:"5.7.0.18000",    dir:"\System32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.0.21238",    min_version:"5.7.0.20000",    dir:"\system32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.0.17033",    min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"981349") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vbscript.dll", version:"5.8.6001.23000", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"981332") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vbscript.dll", version:"5.7.6002.22354", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vbscript.dll", version:"5.6.0.8838",     min_version:"5.6.0.0",        dir:"\system32", bulletin:bulletin, kb:"981350") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Vbscript.dll", version:"5.8.6001.23000", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"981332") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Vbscript.dll", version:"5.7.6002.22354", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Vbscript.dll", version:"5.8.6001.23000", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"981332") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Vbscript.dll", version:"5.7.6002.22354", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Vbscript.dll", version:"5.6.0.8838",                                   dir:"\system32", bulletin:bulletin, kb:"981350") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Vbscript.dll", version:"5.7.6002.22354", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"981349") ||
  hotfix_is_vulnerable(os:"5.0",                   file:"Vbscript.dll", version:"5.6.0.8838",     min_version:"5.1.0.0",        dir:"\system32", bulletin:bulletin, kb:"981350")
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
