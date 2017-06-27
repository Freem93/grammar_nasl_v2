#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91009);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2016-0185");
  script_bugtraq_id(90023);
  script_osvdb_id(138329);
  script_xref(name:"MSFT", value:"MS16-059");
  script_xref(name:"IAVA", value:"2016-A-0129");

  script_name(english:"MS16-059: Security Update for Windows Media Center (3150220)");
  script_summary(english:"Checks the version of ehshell.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a remote code execution vulnerability in
Windows Media Center due to improper handling of Media Center Link
(.mcl) files. An unauthenticated, remote attacker can exploit this
vulnerability by convincing a user to visit a website that hosts a
specially crafted .mcl file or to click a specially crafted link in an
email, resulting in the execution of arbitrary code in the context of
the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-059");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 7, 8, and
8.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
bulletin = 'MS16-059';
kb = '3150220';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Server" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

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
close_registry(close:FALSE);

if(!win_media_center_installed)
{
  close_registry();
  audit(AUDIT_NOT_INST, "Windows Media Center");
}

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

# Avoid the SxS search for Windows 7
if ("Windows 7" >!< productname)
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3150220~31bf3856ad364e35~amd64~~6.2.1.0";

  files = list_dir(basedir:winsxs, level:0, dir_pat:"msil_ehshell_31bf3856ad364e35_", file_pat:"^ehshell\.dll$", max_recurse:1);

  # File Only Exists of Media Center TV Pack is installed (which comes installed by OEM)
  vuln += hotfix_check_winsxs(os:'6.0',
                              sp:2,
                              files:files,
                              versions:make_list('6.0.6002.19634','6.0.6002.23948'),
                              max_versions:make_list('6.0.6002.20000','6.0.6002.99999'),
                              bulletin:bulletin,
                              kb:kb,
                              key:key);

  # Windows 8.1
  # Only Vulnerable if Windows Media Center ($10 add-on) is installed
  vuln += hotfix_check_winsxs(os:'6.3',
                              sp:0,
                              files:files,
                              versions:make_list('6.3.9600.18299'),
                              max_versions:make_list('6.3.9600.99999'),
                              bulletin:bulletin,
                              kb:kb,
                              key:key);
}

hcf_init = TRUE;

# Windows 7
vuln += hotfix_check_winsxs(os:"6.1", 
                             sp:1, 
                             files:files,
                             versions: make_list('6.1.7600.17545', '6.1.7601.23434'), 
                             max_versions:make_list('6.1.7600.20000', '6.1.7601.99999'),
                             bulletin:bulletin, 
                             kb:kb,
                             key:key);

# cleanup
hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
