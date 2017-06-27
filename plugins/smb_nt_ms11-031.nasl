#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53388);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/16 21:12:00 $");

  script_cve_id("CVE-2011-0663");
  script_bugtraq_id(47249);
  script_osvdb_id(71774);
  script_xref(name:"MSFT", value:"MS11-031");

  script_name(english:"MS11-031: Vulnerability in JScript and VBScript Scripting Engines Could Allow Remote Code Execution (2514666)");
  script_summary(english:"Checks versions of Jscript.dll / Vbscript.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the installed
JScript and VBScript scripting engines."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of the JScript and VBScript scripting engines
contains an integer overflow vulnerability that can occur when the
scripting engines process a script in a web page and attempt to
reallocate memory while decoding the script.

If an attacker can trick a user on the affected system into visiting a
malicious website, this issue could be leveraged to execute arbitrary
code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-031");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS11-031';
kbs = make_list("2510531", "2510581", "2510587");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


ie = get_kb_item_or_exit("SMB/IE/Version");

if (
  # Windows 7 and Windows Server 2008 R2
  (
    ie =~ "^[0-8]\." &&
    (
      hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll",  version:"5.8.7601.21663", min_version:"5.8.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7601.21663", min_version:"5.8.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll",  version:"5.8.7601.17562", min_version:"5.8.7601.17000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7601.17562", min_version:"5.8.7601.17000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll",  version:"5.8.7600.20904", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7600.20904", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Jscript.dll",  version:"5.8.7600.16762", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.1",                   file:"Vbscript.dll", version:"5.8.7600.16762", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2510531")
    )
  ) ||

  # Vista / Windows 2008
  (
    ie =~ "^[0-8]\." &&
    (
      hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll",  version:"5.8.6001.23141", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.8.6001.23141", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll",  version:"5.8.6001.19046", min_version:"5.8.0.0",        dir:"\System32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.8.6001.19046", min_version:"5.8.0.0",        dir:"\System32", bulletin:bulletin, kb:"2510531")
    )
  ) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll",  version:"5.7.6002.22589", min_version:"5.7.6002.22000", dir:"\System32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.6002.22589", min_version:"5.7.6002.22000", dir:"\System32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll",  version:"5.7.6002.18405", min_version:"5.7.6002.0",     dir:"\System32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.6002.18405", min_version:"5.7.6002.0",     dir:"\System32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll",  version:"5.7.0.22854",    min_version:"5.7.0.22000",    dir:"\system32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.0.22854",    min_version:"5.7.0.22000",    dir:"\system32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Jscript.dll",  version:"5.7.0.18599",    min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vbscript.dll", version:"5.7.0.18599",    min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510581") ||

  # Windows 2003 / XP x64
  (
    ie =~ "^[0-8]\." &&
    (
      hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Jscript.dll",  version:"5.8.6001.23141", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510531") ||
      hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vbscript.dll", version:"5.8.6001.23141", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510531")
    )
  ) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Jscript.dll",  version:"5.7.6002.22589", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vbscript.dll", version:"5.7.6002.22589", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Jscript.dll",  version:"5.6.0.8850",     min_version:"5.6.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510587") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vbscript.dll", version:"5.6.0.8850",     min_version:"5.6.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510587") ||

  # Windows XP x86
  (
    ie =~ "^[0-8]\." &&
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Jscript.dll",  version:"5.8.6001.23141", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510531")
  ) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Vbscript.dll", version:"5.8.6001.23141", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510531") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Jscript.dll",  version:"5.7.6002.22589", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510581") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Vbscript.dll", version:"5.7.6002.22589", min_version:"5.7.0.0",        dir:"\system32", bulletin:bulletin, kb:"2510581")
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
