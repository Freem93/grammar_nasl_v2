#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58331);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2012-0156");
  script_bugtraq_id(52332);
  script_osvdb_id(80003);
  script_xref(name:"MSFT", value:"MS12-019");

  script_name(english:"MS12-019: Vulnerability in DirectWrite Could Allow Denial of Service (2665364)");
  script_summary(english:"Checks version of Dwrite.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in the implementation of
DirectWrite installed on the remote Windows host.

In an Instant Messenger-based attack scenario, an attacker sending a
specially crafted sequence of Unicode characters directly to an
Instant Messenger client could cause the application to become
unresponsive.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-019");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

bulletin = "MS12-019";
kb = "2665364";
kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
path  = ereg_replace(pattern:"^[A-Za-z](.*)", replace:"\1", string:rootfile);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft-windows-directwrite", file_pat:"^Dwrite\.dll$", max_recurse:1);

# Windows Vista / Windows Server 2008
vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:make_list('7.0.6002.18582', '7.0.6002.22797'), max_versions:make_list('7.0.6002.20000', '7.0.6002.29999'), bulletin:bulletin, kb:kb);

# Windows 7 / Windows Server 2008 R2
vuln += hotfix_check_winsxs(os:'6.1.', sp:0, files:files, versions:make_list('6.1.7600.16961', '6.1.7600.21148'), max_versions:make_list('6.1.7600.20000', '6.1.7600.29999'), bulletin:bulletin, kb:kb);
vuln += hotfix_check_winsxs(os:'6.1.', sp:1, files:files, versions:make_list('6.1.7601.17776', '6.1.7601.21920', '6.2.9200.0'), max_versions:make_list('6.1.7601.20000', '6.1.7601.29999', ''), bulletin:bulletin, kb:kb);

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
