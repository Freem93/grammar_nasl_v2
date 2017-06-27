#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72434);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_cve_id("CVE-2014-0271");
  script_bugtraq_id(65395);
  script_osvdb_id(103166);
  script_xref(name:"MSFT", value:"MS14-011");

  script_name(english:"MS14-011: Vulnerability in VBScript Scripting Engine Could Allow Remote Code Execution (2928390)");
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
"The installed version of the VBScript Scripting Engine has a memory
corruption vulnerability due to improper handling of objects in memory.
If an attacker can trick a user on the system into viewing or opening
malicious content, this issue could be leveraged to execute arbitrary
code on the affected system, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-011");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 2008 R2, 7, 8, 8.1, 2012, and 2012 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

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

bulletin = 'MS14-011';
kbs = make_list(
  "2909210",
  "2909212",
  "2909213"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
# nb: Microsoft regards this a defense-in-depth update for Server Core so
#     we won't flag it on that if report_paranoia < 2.
if (report_paranoia < 2 && hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

ie_ver = get_kb_item_or_exit("SMB/IE/Version");
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;


# VBScript 5.8
kb = "2909210";
# - with specific versions of IE.
if (
  (
    ie_ver =~ "^11\." &&
    (
      # Windows 8.1 and Windows Server 2012 R2
      hotfix_is_vulnerable(os:"6.3", sp:0, file:"Vbscript.dll", version:"5.8.9600.16483", min_version:"5.8.9600.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

      # Windows 7 and Windows Server 2008 R2
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.9600.16497", min_version:"5.8.9600.0",     dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||
  (
    ie_ver =~ "^10\." &&
    (
      # Windows 8 and Windows Server 2012
      hotfix_is_vulnerable(os:"6.2", sp:0, file:"Vbscript.dll", version:"5.8.9200.20893", min_version:"5.8.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.2", sp:0, file:"Vbscript.dll", version:"5.8.9200.16775", min_version:"5.8.9200.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

      # Windows 7 and Windows Server 2008 R2
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.9200.20901", min_version:"5.8.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.9200.16783", min_version:"5.8.9200.0",     dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||
  (
    ie_ver =~ "^8\." &&
    (
      # Windows 7 and Windows Server 2008 R2
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.7601.22535", min_version:"5.8.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vbscript.dll", version:"5.8.7601.18337", min_version:"5.8.7601.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

      # Vista / Windows 2008
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.8.6001.23552", min_version:"5.8.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.8.6001.19498", min_version:"5.8.6001.0",     dir:"\System32", bulletin:bulletin, kb:kb) ||

      # Windows 2003 / XP x64
      hotfix_is_vulnerable(os:"5.2", sp:2, file:"Vbscript.dll", version:"5.8.6001.23552", min_version:"5.8.6001.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

      # Windows XP x86
      hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vbscript.dll", version:"5.8.6001.23552", min_version:"5.8.6001.0",     dir:"\system32", bulletin:bulletin, kb:kb)
    )
  )
) vuln++;

# - on Windows 8.1 without IE 11.
if (
  ie_ver !~ "^11\." &&
  ie_ver !~ "^9\." &&
  "Windows 8.1" >< productname &&
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Vbscript.dll", version:"5.8.9600.16483", min_version:"5.8.9600.0",     dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

# - on Windows Server 2008 R2, Windows Server 2012, and Windows Server 2012 R2 generally.
if (
  ie_ver !~ "^9\." &&
  (
    "Server 2012" >< productname ||
    "Server 2008 R2" >< productname ||
    "Small Business Server 2011" >< productname
  ) &&
  (
    # Windows Server 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"Vbscript.dll", version:"5.8.7601.22535", min_version:"5.8.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"Vbscript.dll", version:"5.8.7601.18337", min_version:"5.8.7601.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"Vbscript.dll", version:"5.8.7601.22535", min_version:"5.8.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"Vbscript.dll", version:"5.8.7601.18337", min_version:"5.8.7601.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.8.7601.22535", min_version:"5.8.7601.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.8.7601.18337", min_version:"5.8.7601.0",     dir:"\System32", bulletin:bulletin, kb:kb)
  )
) vuln++;


# VBScript 5.7
kb = "2909212";
if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.23292", min_version:"5.7.6002.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Vbscript.dll", version:"5.7.6002.19005", min_version:"5.7.6002.0",     dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Vbscript.dll", version:"5.7.6002.23292", min_version:"5.7.6002.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vbscript.dll", version:"5.7.6002.23292", min_version:"5.7.6002.0",     dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;


# VBScript 5.6
kb = "2909213";
if (
  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Vbscript.dll", version:"5.6.0.8852", min_version:"5.6.0.0",     dir:"\system32", bulletin:bulletin, kb:kb)
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
