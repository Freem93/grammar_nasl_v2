#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46840);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2010-1879", "CVE-2010-1880");
  script_bugtraq_id(40432, 40464);
  script_osvdb_id(65221, 65222);
  script_xref(name:"IAVA", value:"2010-A-0078");
  script_xref(name:"MSFT", value:"MS10-033");

  script_name(english:"MS10-033: Vulnerabilities in Media Decompression Could Allow Remote Code Execution (979902)");
  script_summary(english:"Checks if multiple vulnerable apps are installed");

  script_set_attribute(attribute:"synopsis", value:
"Opening a specially crafted media file can result in arbitrary code
execution.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has multiple unspecified code execution
vulnerabilities related to media decompression. A remote attacker
could exploit this by tricking a user into opening a specially crafted
media file, resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for DirectX 9, Windows Media
Format Runtime, Windows Media Encoder, and Asycfilt.dll (COM
component).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-033';
kbs = make_list("975562", "978695", "979332", "979482");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Locate the Windows Media Encoder install.
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

wme_path = "";
key = "Software\Microsoft\Windows Media\Encoder";
item = "InstallDir";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull(value)) wme_path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = FALSE;

# - Asycfilt.dll (COM component)
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"Asycfilt.dll", version:"6.1.7600.20660", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:'979482') ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Asycfilt.dll", version:"6.1.7600.16544", min_version:"6.1.0.0",        dir:"\system32", bulletin:bulletin, kb:'979482') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Asycfilt.dll", version:"6.0.6002.22377", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:'979482') ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Asycfilt.dll", version:"6.0.6002.18236", min_version:"6.0.0.0",        dir:"\system32", bulletin:bulletin, kb:'979842') ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Asycfilt.dll", version:"6.0.6001.22665", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:'979842') ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Asycfilt.dll", version:"6.0.6001.18454", min_version:"6.0.0.0",        dir:"\system32", bulletin:bulletin, kb:'979842') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Asycfilt.dll", version:"5.2.3790.4676",                                dir:"\system32", bulletin:bulletin, kb:'979842') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Asycfilt.dll", version:"5.1.2600.5949",                                dir:"\system32", bulletin:bulletin, kb:'979842') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Asycfilt.dll", version:"5.1.2600.3680",                                dir:"\system32", bulletin:bulletin, kb:'979842') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Asycfilt.dll", version:"2.40.4534.0",                                  dir:"\system32", bulletin:bulletin, kb:'979842')
) vuln = TRUE;

# - Quartz.dll (DirectShow)
if (hotfix_check_server_core() == 0)
{
  if (
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0",                   file:"Quartz.dll",   version:"6.6.6001.22672", min_version:"6.6.6001.22000", dir:"\System32", bulletin:bulletin, kb:'975562') ||
    hotfix_is_vulnerable(os:"6.0",                   file:"Quartz.dll",   version:"6.6.6001.18461", min_version:"6.6.0.0",        dir:"\System32", bulletin:bulletin, kb:'975562') ||

    # Windows 2003 / XP x64
    hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Quartz.dll",   version:"6.5.3790.4660",                                dir:"\System32", bulletin:bulletin, kb:'975562') ||

    # Windows XP x86
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Quartz.dll",   version:"6.5.2600.5933",  min_version:"6.5.0.0",        dir:"\system32", bulletin:bulletin, kb:'975562') ||
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Quartz.dll",   version:"6.5.2600.3665",  min_version:"6.5.0.0",        dir:"\system32", bulletin:bulletin, kb:'975562') ||

    # Windows 2000
    # - Quartz.dll (DirectShow)
    hotfix_is_vulnerable(os:"5.0",                   file:"Quartz.dll",   version:"6.5.1.914",      min_version:"6.5.0.0",        dir:"\system32", bulletin:bulletin, kb:'975562')
  ) vuln = TRUE;
}

# - Media Format Runtime 9, 9.5, and 11.
if (
  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4007",    min_version:"10.0.0.0",       dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvcore.dll",  version:"10.0.0.3821",    min_version:"10.0.0.0",       dir:"\SysWOW64", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvcore.dll",  version:"10.0.0.4007",    min_version:"10.0.0.4000",    dir:"\SysWOW64", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5275", min_version:"11.0.0.0",       dir:"\system32", bulletin:bulletin, kb:'978695') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.3272",     min_version:"9.0.0.0",        dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.3369",     min_version:"9.0.0.3300",     dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.4509",     min_version:"9.0.0.0",        dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4374",    min_version:"10.0.0.4300",    dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4374",    min_version:"10.0.0.4300",    dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.3706",    min_version:"10.0.0.3700",    dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.3706",    min_version:"10.0.0.3700",    dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4078",    min_version:"10.0.0.4000",    dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4078",    min_version:"10.0.0.4000",    dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5275", min_version:"11.0.0.0",       dir:"\system32", bulletin:bulletin, kb:'978695') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5275", min_version:"11.0.0.0",       dir:"\system32", bulletin:bulletin, kb:'978695') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Wmvcore.dll",  version:"9.0.0.3369",                                   dir:"\system32", bulletin:bulletin, kb:'978695')
) vuln = TRUE;

# - Windows Media Encoder.
if (wme_path && hotfix_check_server_core() == 0)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:wme_path);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  if (
    hotfix_check_fversion(file:"Wmenceng.dll", path:wme_path, version:"10.0.0.3821", min_version:"10.0.0.0", bulletin:bulletin, kb:'979332') == HCF_OLDER ||
    hotfix_check_fversion(file:"Wmenceng.dll", path:wme_path, version:"9.0.0.3369",  min_version:"9.0.0.0", bulletin:bulletin, kb:'979332') == HCF_OLDER
  ) vuln = TRUE;
}

# Issue a report if we're vulnerable.
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-033", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
