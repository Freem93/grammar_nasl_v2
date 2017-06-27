#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57472);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2012-0003", "CVE-2012-0004");
  script_bugtraq_id(51292, 51295);
  script_osvdb_id(78210, 78211);
  script_xref(name:"EDB-ID", value:"18426");
  script_xref(name:"MSFT", value:"MS12-004");
  script_xref(name:"IAVA", value:"2012-A-0005");

  script_name(english:"MS12-004: Vulnerabilities in Windows Media Could Allow Remote Code Execution (2636391)");
  script_summary(english:"Checks version of Winmm.dll / Quartz.dll / Mstvcapn.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Opening a specially crafted media file could result in arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows Media installed on the remote host is affected
by one or both of the following vulnerabilities :

  - The Winmm.dll library as used by Windows Media Player
    does not properly handle specially crafted MIDI files.
    (CVE-2012-0003)

  - A DirectShow component of DirectX does not properly
    handle specially crafted media files. (CVE-2012-0004)

An attacker who tricked a user on the affected host into opening a
specially crafted MIDI or media file could leverage these issues to
execute arbitrary code in the context of the current user."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-004");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2 as well as Windows XP Media Center Edition 2005
and Windows Media Center TV Pack 2008."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS12-004 midiOutPlayNextPolyEvent Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS12-004';
kbs = make_list("2598479", "2628259", "2628642", "2631813");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


# Test each component.
vuln = FALSE;

# - Windows Multimedia Library (Winmm.dll)
kb = "2598479";                                            # nb: except for XP MCE 2005
if (
  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Winmm.dll", version:"6.0.6002.22726", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Winmm.dll", version:"6.0.6002.18528", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Winmm.dll",   version:"5.2.3790.4916",                              dir:"\system32", bulletin:bulletin, kb:kb) ||

  # # - Windows XP Media Center Edition 2005
  # hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mstvcapn.dll", version:"5.1.2715.5512", min_version:"5.1.0.0",       dir:"\system32", bulletin:bulletin, kb:"2628259") ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Winmm.dll",   version:"5.1.2600.6160",                              dir:"\system32", bulletin:bulletin, kb:kb)
) vuln = TRUE;

# - DirectShow (Quartz.dll)
kb = "2631813";
if (
  # Windows 7 / 2008 R2
  (
    hotfix_check_server_core() == 0 &&
    (
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Quartz.dll", version:"6.6.7601.21847", min_version:"6.6.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Quartz.dll", version:"6.6.7601.17713", min_version:"6.6.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:0, file:"Quartz.dll", version:"6.6.7600.21077", min_version:"6.6.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:0, file:"Quartz.dll", version:"6.6.7600.16905", min_version:"6.6.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Quartz.dll", version:"6.6.6002.22732", min_version:"6.6.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Quartz.dll", version:"6.6.6002.18533", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Quartz.dll",   version:"6.5.3790.4928",                              dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Quartz.dll",   version:"6.5.2600.6169",                              dir:"\system32", bulletin:bulletin, kb:kb)
) vuln = TRUE;

# - Windows Vista Media Center TV Pack 2008 (Mstvcapn.dll)
kb = "2628642";
if (
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mstvcapn.dll", version:"6.1.1000.18311", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln = TRUE;


# Issue a report if we're affected.
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
