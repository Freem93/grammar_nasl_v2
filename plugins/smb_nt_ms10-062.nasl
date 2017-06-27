#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49220);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2010-0818");
  script_bugtraq_id(43039);
  script_osvdb_id(67985);
  script_xref(name:"IAVA", value:"2010-A-0122");
  script_xref(name:"MSFT", value:"MS10-062");

  script_name(english:"MS10-062: Vulnerability in MPEG-4 Codec Could Allow Remote Code Execution (975558)");
  script_summary(english:"Checks the version of mpg4ds32.ax / mp4sds32.ax / mp4sdmod.dll / mp4sdecd.dll / mp4sdecd.dll");

  script_set_attribute(attribute:"synopsis", value:
"A video codec on the remote Windows host has a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The MPEG-4 codec, which is included with Windows Media codecs,
contains a buffer overflow vulnerability that can be triggered by a
specially crafted media file that uses MPEG-4 video encoding.

If an attacker can trick a user on the affected system into opening a
specially crafted media file or receiving specially crafted web
content, this issue could be leveraged to execute arbitrary code
subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-062");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-062';
kbs = make_list("975558");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '975558';

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Mp4sdecd.dll", version:"11.0.6002.22377", min_version:"11.0.6002.22000", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Mp4sdecd.dll", version:"11.0.6002.18236",                                dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Mp4sdecd.dll", version:"11.0.6001.7117",  min_version:"11.0.6001.7100",  dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Mp4sdecd.dll", version:"11.0.6001.7009",                                 dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mp4sdecd.dll", version:"11.0.6002.22377", min_version:"11.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mp4sdecd.dll", version:"11.0.6002.18236",                                dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mp4sdecd.dll", version:"11.0.6001.7117",  min_version:"11.0.6001.7100",  dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mp4sdecd.dll", version:"11.0.6001.7009",                                 dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x64 / XP x64
  # - Codec Pack 6.4, Codec Pack 8, Codec Server
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"mp4sds32.ax",  version:"8.0.0.406",                                      dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  # - In-band
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"mpg4ds32.ax",  version:"8.0.0.4504",                                     dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  # - In-band
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"mp4sdmod.dll", version:"10.0.0.3706",     min_version:"10.0.0.0",        dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  # - Windows Media Player 11, Windows Media Format 11
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"mp4sdecd.dll", version:"11.0.5721.5274",  min_version:"11.0.0.0",        dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x86
  # - Codec Pack 6.4, Codec Pack 8, Codec Server
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"mp4sds32.ax",  version:"8.0.0.406",                                      dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - In-band
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"mpg4ds32.ax",  version:"8.0.0.4504",                                     dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - In-band
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"mp4sdmod.dll", version:"10.0.0.4007",     min_version:"10.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  # - In-band
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"mpg4ds32.ax",  version:"8.0.0.4504",                                     dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Codec Pack 6.4, Codec Pack 8, Codec Server
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"mp4sds32.ax",  version:"8.0.0.406",                                      dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - In-band
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"mp4sdmod.dll", version:"9.0.0.4509",                                     dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Codec Server
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"mp4sdmod.dll", version:"10.0.0.3706",     min_version:"10.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Windows Media Player 11, FSDK 11
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"mp4sdecd.dll", version:"11.0.5721.5274",  min_version:"11.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-062", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
