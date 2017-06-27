#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51168);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3147");
  script_bugtraq_id(42648);
  script_osvdb_id(67553);
  script_xref(name:"EDB-ID", value:"14745");
  script_xref(name:"IAVA", value:"2010-A-0173");
  script_xref(name:"MSFT", value:"MS10-096");

  script_name(english:"MS10-096: Vulnerability in Windows Address Book Could Allow Remote Code Execution (2423089)");
  script_summary(english:"Checks version of wab.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Windows
Address Book.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Windows Address Book
that incorrectly restricts the path used for loading external
libraries.

If an attacker can trick a user on the affected system into opening a
specially crafted Windows Address Book file located in the same
network directory as a specially crafted dynamic link library (DLL)
file, this issue could be leveraged to execute arbitrary code subject
to the user's privileges.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-096");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

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

bulletin = 'MS10-096';
kbs = make_list("2423089");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
win_ver = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hcf_init == TRUE ) NetUseDel(close:TRUE);

# Locate the Outlook Express / Windows Mail installation dirs.
progfiles = hotfix_get_programfilesdir();
if ( isnull(progfiles) ) exit(1, "Could not find the value of %ProgramFiles%");

oe_path = "";
wm_path = "";

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

if (win_ver == "6.0" || win_ver == "6.1")
{
  key = "Software\Microsoft\Windows Mail";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"InstallRoot");
    if (!isnull(value))
    {
      path = value[1];
      wm_path = ereg_replace(
        pattern:"%ProgramFiles%",
        replace:progfiles,
        string:path,
        icase:TRUE
      );
    }
    RegCloseKey(handle:key_h);
  }
  if (isnull(wm_path)) wm_path = hotfix_get_programfilesdir() + "\Windows Mail";
}
else if (win_ver == "5.1" || win_ver == "5.2")
{
  key = "Software\Microsoft\Outlook Express";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"InstallRoot");
    if (!isnull(value))
    {
      path = value[1];
      oe_path = ereg_replace(
        pattern:"%ProgramFiles%",
        replace:progfiles,
        string:path,
        icase:TRUE
      );
    }
    RegCloseKey(handle:key_h);
  }
  if (isnull(oe_path)) oe_path = hotfix_get_programfilesdir() + "\Outlook Express";
}


RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Test installs.
vuln = FALSE;

kb = "2423089";
if (wm_path)
{
  share = hotfix_path2share(path:wm_path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
    # Windows 7 / Server 2008 R2
    hotfix_is_vulnerable(os:"6.1",       file:"Wab.exe", version:"6.1.7600.20814", min_version:"6.1.7600.20000", path:wm_path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1",       file:"Wab.exe", version:"6.1.7600.16684", min_version:"6.1.0.0",        path:wm_path, bulletin:bulletin, kb:kb) ||

    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wab.exe", version:"6.0.6002.22503", min_version:"6.0.6002.22000", path:wm_path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wab.exe", version:"6.0.6002.18324", min_version:"6.0.0.0",        path:wm_path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wab.exe", version:"6.0.6001.22774", min_version:"6.0.6001.22000", path:wm_path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wab.exe", version:"6.0.6001.18535", min_version:"6.0.0.0",        path:wm_path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
}
else if (oe_path)
{
  share = hotfix_path2share(path:oe_path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  # For Windows XP and 2k3 check in Program Files\Outlook Express
  if (
    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", file:"Wab.exe", version:"6.0.3790.4785", path:oe_path, bulletin:bulletin, kb:kb) ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", file:"Wab.exe", version:"6.0.2900.6040", path:oe_path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
}


# Issue a report if we're vulnerable.
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-096", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
