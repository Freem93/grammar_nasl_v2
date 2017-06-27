#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48287);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2010-2564");
  script_bugtraq_id(42268);
  script_osvdb_id(66986);
  script_xref(name:"MSFT", value:"MS10-050");

  script_name(english:"MS10-050: Vulnerability in Windows Movie Maker Could Allow Remote Code Execution (981997)");
  script_summary(english:"Checks version of Moviemk.exe / Moviemk.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Windows
Movie Maker.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Windows Movie Maker that
is affected by a memory corruption vulnerability due to the way the
application parses project file formats.

If an attacker can trick a user on the affected system into opening a
specially crafted Movie Maker project file using the affected
application, this issue could be leveraged to execute arbitrary code
subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-050");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and Vista.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-050';
kbs = make_list("981997");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if("Vista" >!< productname && "XP" >!< productname)
  exit(0, "The host is running "+productname+" and hence is not affected.");

# Figure out where Movie Maker's installed.
path = NULL;
progfiles = hotfix_get_programfilesdir();

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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

if ( !isnull(progfiles) )
{
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\moviemk.exe";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item) && strlen(item[1]) > 0 )
  {
    path = item[1];
    path = ereg_replace(
      pattern:"^(.+)\\moviemk\.exe$",
      replace:"\1",
      string:path,
      icase:TRUE
    );
    path = ereg_replace(
      pattern:"%ProgramFiles%",
      replace:progfiles,
      string:path,
      icase:TRUE
    );
  }
  RegCloseKey(handle:key_h);
 }
}

if (isnull(path))
{
  key = "SOFTWARE\Classes\Windows.Movie.Maker\Shell\Open\Command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item) && strlen(item[1]) > 0)
    {
      path = item[1];
      path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:path);
      if (ereg(pattern:"moviemk\.exe ?", string:path, icase:TRUE))
        path = ereg_replace(pattern:"^(.+)\\\moviemk\.exe( .+)?$", replace:"\1", string:path);
      else path = NULL;
    }
    RegCloseKey(handle:key_h);
  }
}
if (isnull(path)) path = hotfix_get_programfilesdir() + "\Movie Maker";

RegCloseKey(handle:hklm);
NetUseDel();

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '981997';
if (
  # Vista
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Moviemk.dll", version:"6.0.6002.22426", min_version:"6.0.6002.22000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Moviemk.dll", version:"6.0.6002.18273", min_version:"6.0.6002.18000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Moviemk.dll", version:"6.0.6001.22714", min_version:"6.0.6001.22000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Moviemk.dll", version:"6.0.6001.18494", min_version:"6.0.6001.18000", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Moviemk.exe", version:"2.6.4039.0",     min_version:"2.6.0.0",        path:path, bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Moviemk.exe", version:"2.1.4031.0",                                   path:path, bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Moviemk.exe", version:"2.1.4028.0",                                   path:path, bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-050", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
