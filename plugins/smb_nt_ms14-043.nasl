#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77160);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/06 15:05:45 $");

  script_cve_id("CVE-2014-4060");
  script_bugtraq_id(69093);
  script_osvdb_id(109931);
  script_xref(name:"MSFT", value:"MS14-043");
  script_xref(name:"IAVB", value:"2014-B-0110");

  script_name(english:"MS14-043: Vulnerability in Windows Media Center Could Allow Remote Code Execution (2978742)");
  script_summary(english:"Checks the version of msplayer.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability due to a user-after-free flaw in Microsoft Windows Media
Center. An attacker can exploit this vulnerability by convincing a
user to open a file or visit a website containing a specially crafted
Office file, resulting in execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-043");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 7, 8, and
8.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

global_var bulletin, vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS14-043';
kb = 2978742;

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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

files = list_dir(basedir:winsxs, level:0, dir_pat:"_microsoft-windows-ehome-mcplayer_31bf3856ad364e35_", file_pat:"^mcplayer\.dll$", max_recurse:1);

# Vista
# File Only Exists of Media Center TV Pack is installed (which comes installed by OEM)
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.1.1000.18324'),
                            max_versions:make_list('6.1.1000.99999'),
                            bulletin:bulletin,
                            kb:kb);

# Windows 7
vuln += hotfix_check_winsxs(os:'6.1',
                            sp:1,
                            files:files,
                            versions:make_list('6.1.7601.18523', '6.1.7601.22733'),
                            max_versions:make_list('6.1.7601.20000', '6.1.7601.99999'),
                            bulletin:bulletin,
                            kb:kb);
# Windows 8
vuln += hotfix_check_winsxs(os:'6.2',
                            sp:0,
                            files:files,
                            versions:make_list('6.2.9200.17045', '6.2.9200.21162'),
                            max_versions:make_list('6.2.9200.20000', '6.2.9200.99999'),
                            bulletin:bulletin,
                            kb:kb);

# Windows 8.1
# Only Vulnerable if Windows Media Center ($10 add-on) is installed
vuln += hotfix_check_winsxs(os:'6.3',
                            sp:0,
                            files:files,
                            versions:make_list('6.3.9600.17224'),
                            max_versions:make_list('6.3.9600.99999'),
                            bulletin:bulletin,
                            kb:kb);

# cleanup
NetUseDel();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
