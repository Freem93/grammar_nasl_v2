#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61531);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2012-2523");
  script_bugtraq_id(54945);
  script_osvdb_id(84604);
  script_xref(name:"MSFT", value:"MS12-056");
  script_xref(name:"IAVA", value:"2012-A-0130");

  script_name(english:"MS12-056: Vulnerability in JScript and VBScript Scripting Engines Could Allow Remote Code Execution (2706045)");
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
"The installed versions of the JScript and VBScript scripting engines
contain an integer overflow vulnerability that can occur when the
scripting engines process a script in a web page and attempt to
calculate the size of an object in memory during a copy operation.

By tricking a user on the affected system into visiting a malicious web
site, an attacker may be able to exploit this issue to execute arbitrary
code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-056");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for 64-bit editions of Windows
XP, 2003, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_nt_ms12-052.nasl");
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

bulletin = 'MS12-056';
kb = "2706045";
kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Only x64 is affected
arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);
if (arch != 'x64') exit(0, "The host is not affected since it is not running a 64-bit version of Windows.");

ie_ver = get_kb_item_or_exit("SMB/IE/Version");

if (
  (ie_ver =~ "^8\.") &&
  (
    # Windows 7 x64 and Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Jscript.dll",  version:"5.8.7601.22024", min_version:"5.8.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Vbscript.dll", version:"5.8.7601.22024", min_version:"5.8.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Jscript.dll",  version:"5.8.7601.17866", min_version:"5.8.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Vbscript.dll", version:"5.8.7601.17866", min_version:"5.8.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

    hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"Jscript.dll",  version:"5.8.7600.21238", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"Vbscript.dll", version:"5.8.7600.21238", min_version:"5.8.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"Jscript.dll",  version:"5.8.7600.17045", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"Vbscript.dll", version:"5.8.7600.17045", min_version:"5.8.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Vista x64 / Windows 2008 x64
    hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Jscript.dll",  version:"5.8.6001.23380", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Vbscript.dll",  version:"5.8.6001.23380", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Jscript.dll",  version:"5.8.6001.19293", min_version:"5.8.6001.18000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Vbscript.dll",  version:"5.8.6001.19293", min_version:"5.8.6001.18000", dir:"\System32", bulletin:bulletin, kb:kb) ||

    # Windows 2003 x64 / XP x64
    hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vbscript.dll", version:"5.8.6001.23380", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Jscript.dll",  version:"5.8.6001.23380", min_version:"5.8.0.0",        dir:"\system32", bulletin:bulletin, kb:kb)
  )
) vuln = TRUE;


#######################
# KB2722913           #
#######################
if (ie_ver =~ "^9\.")
{
  if (!isnull(get_kb_item("SMB/Missing/MS12-052")))
  {
    report =
    '\nThis bulletin corrects the vulnerability in Internet' +
    '\nExplorer 8, however Internet Explorer 9 is installed and' +
    '\nits fix, KB2722913, is missing. To obtain protection from' +
    '\nthe vulnerability noted in CVE-2012-2523, you must install' +
    '\nKB2722913 which is described in MS12-052.';

    hotfix_add_report(report, bulletin:bulletin, kb:"2722913");
    vuln = TRUE;
  }
}

if (vuln)
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
