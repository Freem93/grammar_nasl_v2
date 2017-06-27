#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55132);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-1266");
  script_bugtraq_id(48173);
  script_osvdb_id(72954);
  script_xref(name:"MSFT", value:"MS11-052");

  script_name(english:"MS11-052: Vulnerability in Vector Markup Language Could Allow Remote Code Execution (2544521)");
  script_summary(english:"Checks version of Vgx.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a web
browser.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Internet Explorer (IE) Security Update
2497640.

The installed version of IE is affected by a vulnerability in the
implementation of the Vector Markup Language (VML) that could allow an
attacker to execute arbitrary code on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-197/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-052");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-052';
kb = '2544521';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

arch = get_kb_item_or_exit('SMB/ARCH');
rootfile = hotfix_get_systemroot();
if (!rootfile) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x86_path += "\Microsoft Shared\VGX";

x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');
if (x64_path) path += "\Common Files\Microsoft Shared\VGX";

if (
  # Windows 7 and Windows Server 2008 R2
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vgx.dll", version:"8.0.7601.21718", min_version:"8.0.7601.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vgx.dll", version:"8.0.7601.17608", min_version:"8.0.7600.17000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Vgx.dll", version:"8.0.7600.20957", min_version:"8.0.7600.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Vgx.dll", version:"8.0.7600.16806", min_version:"8.0.7600.16000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vgx.dll", version:"8.0.7601.21718", min_version:"8.0.7601.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Vgx.dll", version:"8.0.7601.17608", min_version:"8.0.7600.17000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Vgx.dll", version:"8.0.7600.20957", min_version:"8.0.7600.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Vgx.dll", version:"8.0.7600.16806", min_version:"8.0.7600.16000", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"8.0.6001.23169", min_version:"8.0.6001.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"8.0.6001.19076", min_version:"8.0.6001.18000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"8.0.6001.23169", min_version:"8.0.6001.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"8.0.6001.19076", min_version:"8.0.6001.18000", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Vgx.dll", version:"7.0.6002.22634", min_version:"7.0.6002.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Vgx.dll", version:"7.0.6002.18463", min_version:"7.0.6001.18000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Vgx.dll", version:"7.0.6001.22911", min_version:"7.0.6001.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Vgx.dll", version:"7.0.6001.18645", min_version:"7.0.6001.18000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Vgx.dll", version:"7.0.6002.22634", min_version:"7.0.6002.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Vgx.dll", version:"7.0.6002.18463", min_version:"7.0.6001.18000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Vgx.dll", version:"7.0.6001.22911", min_version:"7.0.6001.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Vgx.dll", version:"7.0.6001.18645", min_version:"7.0.6001.18000", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vgx.dll", version:"8.0.6001.23167", min_version:"8.0.6001.0", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vgx.dll", version:"8.0.6001.23167", min_version:"8.0.6001.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vgx.dll", version:"7.0.6000.21301", min_version:"7.0.6000.0", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vgx.dll", version:"7.0.6000.21301", min_version:"7.0.6000.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vgx.dll", version:"6.0.3790.4861", min_version:"6.0.3790.0", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vgx.dll", version:"6.0.3790.4861", min_version:"6.0.3790.0", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vgx.dll", version:"8.0.6001.23167", min_version:"8.0.6001.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vgx.dll", version:"7.0.6000.21301", min_version:"7.0.6000.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vgx.dll", version:"6.0.2900.6108", min_version:"6.0.2900.0", path:x86_path, bulletin:bulletin, kb:kb)
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
