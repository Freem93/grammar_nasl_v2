#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85884);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2015-2509");
  script_bugtraq_id(76594);
  script_osvdb_id(127202);
  script_xref(name:"MSFT", value:"MS15-100");

  script_name(english:"MS15-100: Vulnerability in Windows Media Center Could Allow Remote Code Execution (3087918)");
  script_summary(english:"Checks the version of ehshell.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability due to a use-after-free error in Microsoft Windows Media
Center when handling specially crafted Media Center link (.mcl) files.
A remote attacker can exploit this vulnerability by convincing a user
to install a malicious link file, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-100");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 7, 8, and
8.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS15-100 Microsoft Windows Media Center MCL Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS15-100';
kb = '3087918';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

vuln = 0;

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
win_media_center_installed = get_registry_value(handle:hklm, item:"SOFTWARE\Clients\Media\Windows Media Center\");
if(win_media_center_installed == "Windows Media Center")
  win_media_center_installed = TRUE;
else win_media_center_installed = FALSE;
RegCloseKey(handle:hklm);
close_registry();

if(!win_media_center_installed)
  audit(AUDIT_NOT_INST, "Windows Media Center");

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

files = list_dir(basedir:winsxs, level:0, dir_pat:"msil_ehshell_31bf3856ad364e35_", file_pat:"^ehshell\.dll$", max_recurse:1);

# Vista
# File Only Exists of Media Center TV Pack is installed (which comes installed by OEM)
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19478','6.0.6002.23788'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99999'),
                            bulletin:bulletin,
                            kb:kb);

# Windows 7
vuln += hotfix_check_winsxs(os:'6.1',
                            sp:1,
                            files:files,
                            versions:make_list('6.1.7600.17545', '6.1.7601.18968', '6.1.7601.23171'),
                            max_versions:make_list('6.1.7600.20000', '6.1.7601.20000', '6.1.7601.99999'),
                            bulletin:bulletin,
                            kb:kb);
# Windows 8
vuln += hotfix_check_winsxs(os:'6.2',
                            sp:0,
                            files:files,
                            versions:make_list('6.2.9200.17486', '6.2.9200.21601'),
                            max_versions:make_list('6.2.9200.20000', '6.2.9200.99999'),
                            bulletin:bulletin,
                            kb:kb);

# Windows 8.1
# Only Vulnerable if Windows Media Center ($10 add-on) is installed
vuln += hotfix_check_winsxs(os:'6.3',
                            sp:0,
                            files:files,
                            versions:make_list('6.3.9600.18015'),
                            max_versions:make_list('6.3.9600.99999'),
                            bulletin:bulletin,
                            kb:kb);

# cleanup
NetUseDel();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
