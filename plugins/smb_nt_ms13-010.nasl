#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64571);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2013-0030");
  script_bugtraq_id(57852);
  script_osvdb_id(90127);
  script_xref(name:"MSFT", value:"MS13-010");

  script_name(english:"MS13-010: Vulnerability in Vector Markup Language Could Allow Remote Code Execution (2797052)");
  script_summary(english:"Checks version of Vgx.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a web
browser.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Internet Explorer (IE) Security Update
2797052.

The installed version of IE is affected by a vulnerability in the
implementation of the Vector Markup Language (VML) that could allow an
attacker to execute arbitrary code on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-010");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS13-010';
kb = '2797052';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

arch = get_kb_item_or_exit("SMB/ARCH");
rootfile = hotfix_get_systemroot();
if (!rootfile) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

x86_path = hotfix_get_commonfilesdir();
if (x86_path) x86_path += "\Microsoft Shared\VGX";
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

x64_path = hotfix_get_programfilesdirx86();
if (x64_path) x64_path += "\Common Files\Microsoft Shared\VGX";
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

if (
  # Windows 8 and Windows Server 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2",       arch:"x64", file:"Vgx.dll", version:"10.0.9200.20595", min_version:"10.0.9200.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2",       arch:"x64", file:"Vgx.dll", version:"10.0.9200.16490", min_version:"10.0.9200.16000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2",                   file:"Vgx.dll", version:"10.0.9200.20595", min_version:"10.0.9200.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2",                   file:"Vgx.dll", version:"10.0.9200.16490", min_version:"10.0.9200.16000", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Vgx.dll", version:"9.0.8112.20573", min_version:"9.0.8112.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Vgx.dll", version:"9.0.8112.16464", min_version:"9.0.8112.16000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Vgx.dll", version:"9.0.8112.20573", min_version:"9.0.8112.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Vgx.dll", version:"9.0.8112.16464", min_version:"9.0.8112.16000", path:x86_path, bulletin:bulletin, kb:kb) ||

  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Vgx.dll", version:"8.0.7601.22204", min_version:"8.0.7601.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Vgx.dll", version:"8.0.7601.18038", min_version:"8.0.7600.17000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Vgx.dll", version:"8.0.7600.21411", min_version:"8.0.7600.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Vgx.dll", version:"8.0.7600.17201", min_version:"8.0.7600.16000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",             sp:1, file:"Vgx.dll", version:"8.0.7601.22204", min_version:"8.0.7601.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",             sp:1, file:"Vgx.dll", version:"8.0.7601.18038", min_version:"8.0.7600.17000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",             sp:0, file:"Vgx.dll", version:"8.0.7600.21411", min_version:"8.0.7600.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",             sp:0, file:"Vgx.dll", version:"8.0.7600.17201", min_version:"8.0.7600.16000", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"9.0.8112.20573", min_version:"9.0.8112.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"9.0.8112.16464", min_version:"9.0.8112.16000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"9.0.8112.20573", min_version:"9.0.8112.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"9.0.8112.16464", min_version:"9.0.8112.16000", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"8.0.6001.23467", min_version:"8.0.6001.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"8.0.6001.19399", min_version:"8.0.6001.18000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"8.0.6001.23467", min_version:"8.0.6001.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"8.0.6001.19399", min_version:"8.0.6001.18000", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"7.0.6002.23011", min_version:"7.0.6002.20000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       arch:"x64", file:"Vgx.dll", version:"7.0.6002.18762", min_version:"7.0.6001.18000", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"7.0.6002.23011", min_version:"7.0.6002.20000", path:x86_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Vgx.dll", version:"7.0.6002.18762", min_version:"7.0.6001.18000", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vgx.dll", version:"8.0.6001.23468", min_version:"8.0.6001.0", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vgx.dll", version:"8.0.6001.23468", min_version:"8.0.6001.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vgx.dll", version:"7.0.6000.21324", min_version:"7.0.6000.0", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vgx.dll", version:"7.0.6000.21324", min_version:"7.0.6000.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Vgx.dll", version:"6.0.3790.5105", min_version:"6.0.3790.0", path:x64_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Vgx.dll", version:"6.0.3790.5105", min_version:"6.0.3790.0", path:x86_path, bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vgx.dll", version:"8.0.6001.23468", min_version:"8.0.6001.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vgx.dll", version:"7.0.6000.21324", min_version:"7.0.6000.0", path:x86_path, bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Vgx.dll", version:"6.0.2900.6333", min_version:"6.0.2900.0", path:x86_path, bulletin:bulletin, kb:kb)
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
