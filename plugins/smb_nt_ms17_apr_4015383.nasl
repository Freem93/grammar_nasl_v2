#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99309);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id("CVE-2013-6629");
  script_bugtraq_id(63676);
  script_osvdb_id(99711);
  script_xref(name:"MSKB", value:"4015383");

  script_name(english:"KB4015383: Security Update for the libjpeg Information Disclosure Vulnerability (April 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4015383. It is,
therefore, affected by an information disclosure vulnerability in the
open-source libjpeg image processing library due to improper handling
of objects in memory. An unauthenticated, remote attacker can exploit
this to disclose sensitive information that can be utilized to bypass
ASLR security protections.");
  # https://support.microsoft.com/en-us/help/4015383/security-update-for-the-libjpeg-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18ad2286");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2013-6629
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5f07ab5");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015383.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-04';
kbs = make_list("4015383");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (hotfix_check_fversion_init() == HCF_CONNECT) exit(0, "Unable to create SMB session.");

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$", max_recurse:1);

vuln = 0;

function windows_os_is_vuln()
{
  # hotfix_check_winsxs opens another share
  # we need to save state so our session can be restored
  local_var smb_session = make_array(
    'login',    login,
    'password', pass,
    'domain',   domain,
    'share',    winsxs_share
  );

  local_var kb = "4015383";

  vuln += hotfix_check_winsxs(
    os:'6.0',
    sp:2,
    files:files,
    versions:make_list('5.2.6002.19749', '5.2.6002.24072', '6.0.6002.19749', '6.0.6002.24072'),
    max_versions:make_list('5.2.6002.21000', '5.2.6002.99999', '6.0.6002.21000', '6.0.6002.99999'),
    bulletin:bulletin,
    kb:kb,
    session:smb_session
  );
}

windows_os_is_vuln();

if (vuln > 0)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
