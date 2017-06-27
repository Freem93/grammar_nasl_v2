#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58332);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2012-0002", "CVE-2012-0152");
  script_bugtraq_id(52353, 52354);
  script_osvdb_id(80000, 80004);
  script_xref(name:"CERT", value:"624051");
  script_xref(name:"EDB-ID", value:"18606");
  script_xref(name:"IAVA", value:"2012-A-0039");
  script_xref(name:"MSFT", value:"MS12-020");

  script_name(english:"MS12-020: Vulnerabilities in Remote Desktop Could Allow Remote Code Execution (2671387)");
  script_summary(english:"Checks version of Rdpwd.sys / Rdpwsx.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host could allow arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"An arbitrary remote code vulnerability exists in the implementation of
the Remote Desktop Protocol (RDP) on the remote Windows host. The
vulnerability is due to the way that RDP accesses an object in memory
that has been improperly initialized or has been deleted.

If RDP has been enabled on the affected system, an unauthenticated,
remote attacker could leverage this vulnerability to cause the system
to execute arbitrary code by sending a sequence of specially crafted
RDP packets to it.

Note that the Remote Desktop Protocol is not enabled by default.

This plugin also checks for a denial of service vulnerability in
Microsoft Terminal Server.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.org/adv/termdd_1-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-044/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-020");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_protocol");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = "MS12-020";
kbs = make_list("2621440", "2667402");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

vuln = 0;

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);

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

# KB2667402 (only for win7 and 2008 r2)
if (hotfix_check_sp(win7:2) > 0)
{
  # The directory path contains two literal periods in the middle, as do all nearby directories.
  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
  files = list_dir(basedir:winsxs, level:0, dir_pat:"instationextensions", file_pat:"^rdpwsx\.dll$");

  vuln += hotfix_check_winsxs(os:'6.1', sp:0, files:files, versions:make_list('6.1.7600.17009', '6.1.7600.21200'), max_versions:make_list('6.1.7600.17999', '6.1.7600.21999'), bulletin:bulletin, kb:'2667402');
  vuln += hotfix_check_winsxs(os:'6.1', sp:1, files:files, versions:make_list('6.1.7600.17828', '6.1.7600.21980'), max_versions:make_list('6.1.7601.17999', '6.1.7601.21999'), bulletin:bulletin, kb:'2667402');
}

kb = "2621440";
if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rdpwd.sys", version:"6.1.7601.21924", min_version:"6.1.7601.21000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rdpwd.sys", version:"6.1.7601.17779", min_version:"6.1.7601.17000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Rdpwd.sys", version:"6.1.7600.21151", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Rdpwd.sys", version:"6.1.7600.16963", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rdpwd.sys", version:"6.0.6002.22774", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rdpwd.sys", version:"6.0.6002.18568", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Rdpwd.sys", version:"5.2.3790.4952", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Rdpwd.sys", version:"5.1.2600.6187", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
) vuln++;

hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
