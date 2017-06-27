#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(79833);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/09 14:23:24 $");

  script_cve_id("CVE-2014-6363");
  script_bugtraq_id(71504);
  script_osvdb_id(115586);
  script_xref(name:"MSFT", value:"MS14-084");

  script_name(english:"MS14-084: Vulnerability in VBScript Scripting Engine Could Allow Remote Code Execution (3016711)");
  script_summary(english:"Checks the version of Vbscript.dll.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
installed VBScript Scripting Engine.");
  script_set_attribute(attribute:"description", value:
"The installed version of the VBScript Scripting Engine is affected by
a remote code execution vulnerability due to improper handling of
objects in memory. By tricking a user into viewing or opening
malicious content, an attacker can exploit this to execute arbitrary
code on the affected system, subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-084");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
2008 R2, and 7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS14-084';
kbs = make_list(
  "3012168",
  "3012172",
  "3012176"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
# nb: Microsoft regards this a defense-in-depth update for Server Core so
#     we won't flag it on that if report_paranoia < 2.
if (report_paranoia < 2 && hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# if IE isn't installed we must still check the vbscript version
ie_ver = get_kb_item("SMB/IE/Version");
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# VBScript 5.8
kb = "3012176";
# - with IE 8
if (
  !isnull(ie_ver) && ie_ver =~ "^8\." &&
  (
    # Windows 7 and Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.7601.22856", min_version:"5.8.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.7601.18648", min_version:"5.8.7601.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.8.6001.23642", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.8.6001.19587", min_version:"5.8.6001.0",     dir:"\System32", bulletin:bulletin, kb:kb)
  )
) vuln++;

# VBScript 5.8 generally
if (
  # ie_ver < IE9
  (isnull(ie_ver) || (ver_compare(ver:ie_ver, fix:"9.0.0.0") < 0)) &&
  (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Vbscript.dll", version:"5.8.6001.23642", min_version:"5.8.6001.0",     dir:"\system32", bulletin:bulletin, kb:kb)
  )
) vuln++;

# VBScript 5.7
kb = "3012172";
if (
  # ie_ver < IE9
  (isnull(ie_ver) || (ver_compare(ver:ie_ver, fix:"9.0.0.0") < 0)) &&
  (
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.23528", min_version:"5.7.6002.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.19221", min_version:"5.7.6002.0",     dir:"\System32", bulletin:bulletin, kb:kb) ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Vbscript.dll", version:"5.7.6002.23528", min_version:"5.7.0.0",     dir:"\system32", bulletin:bulletin, kb:kb)
  )
) vuln++;

# VBScript 5.6
kb = "3012168";
if (
  # ie_ver < IE9
  (isnull(ie_ver) || (ver_compare(ver:ie_ver, fix:"9.0.0.0") < 0)) &&
  (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Vbscript.dll", version:"5.6.0.8853", min_version:"5.6.0.0",     dir:"\system32", bulletin:bulletin, kb:kb)
  )
) vuln++;

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
