#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53386);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-0041");
  script_bugtraq_id(47250);
  script_osvdb_id(71779);
  script_xref(name:"MSFT", value:"MS11-029");

  script_name(english:"MS11-029: Vulnerability in GDI+ Could Allow Remote Code Execution (2489979)");
  script_summary(english:"Checks the version of gdiplus.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through
Microsoft's GDI+ subsystem.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft's GDI+ subsystem installed on the remote
Windows host contains an integer overflow due to the way that GDI+
handles integer calculations.

If an attacker can trick a user on the affected system into opening a
specially crafted EMF image file, this issue could be exploited to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-029");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-029';
kbs = make_list("2412687", "2509461");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

vuln = 0;
office_versions = hotfix_check_office_version ();
progfiles = hotfix_get_programfilesdir();
cdir = hotfix_get_commonfilesdir();
msoxp_path = cdir + '\\Microsoft Shared\\Office10';

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

# The fixes for Office XP SP3 and Visual Studio.NET SP1 both update the same
# exact file.  The Office fix supersedes the VS .NET fix.
if (office_versions["10.0"])
{
  office_sp = get_kb_item("SMB/Office/XP/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    # Office XP SP3 (KB974811)
    if(hotfix_is_vulnerable(file:"mso.dll", version:"10.0.6870.0", path:msoxp_path))
    {
      vuln++;
    }
  }
}

# If any of the above applications are vulnerable, there's no need to check
# the WinSxS dir (for the OS-specific patches
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_add_report(bulletin:bulletin, kb:'2509461');
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

# KB958869.  Checks the SxS directory.  The bulletin says 2k, vista/2k8 SP2,
# and win7 aren't affected
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

vuln = 0;
kb = '2412687';
winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$");

# Windows XP / 2003
vuln += hotfix_check_winsxs(os:'5.1', sp:3, files:files, versions:make_list('5.2.6002.22509'), bulletin:bulletin, kb:kb);
vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.6002.22507'), bulletin:bulletin, kb:kb);

# Windows Vista / Server 2008
versions = make_list(
  '5.2.6001.18551',
  '5.2.6001.22791',
  '5.2.6002.18342',
  '5.2.6002.22519',
  '6.0.6001.18551',
  '6.0.6001.22791',
  '6.0.6002.18342',
  '6.0.6002.22518'
);
max_versions = make_list(
  '5.2.6001.20000',
  '5.2.6001.99999',
  '5.2.6002.20000',
  '5.2.6002.99999',
  '6.0.6001.20000',
  '6.0.6001.99999',
  '6.0.6002.20000',
  '6.0.6002.99999'
);
vuln += hotfix_check_winsxs(os:'6.0', files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
