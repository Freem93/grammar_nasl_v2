#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55797);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2011-1976");
  script_bugtraq_id(49033);
  script_osvdb_id(74396);
  script_xref(name:"MSFT", value:"MS11-067");

  script_name(english:"MS11-067: Vulnerability in Microsoft Report Viewer Could Allow Information Disclosure (2578230)");
  script_summary(english:"Checks version of Microsoft.ReportViewer.WebForms.dll / ReportViewer.exe / Install.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web control that could allow
information disclosure.");
  script_set_attribute(attribute:"description", value:
"The installed version of the Microsoft Report Viewer control fails to
properly validate parameters within a data source, which results in a
reflected (or non-persistent) cross-site scripting vulnerability.

If an attacker can trick a user into clicking on a link to a malicious
server, he could inject a client-side script in the user's browser
that in turn could be used to spoof content or disclose sensitive
information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-067");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visual Studio
2005 SP1 and the Microsoft Report Viewer 2005 SP1 Redistributable
Package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:report_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-067';
kbs = make_list("2548826", "2579115");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

winroot = hotfix_get_systemroot();
if (!winroot) exit(1, "Can't get the system root.");


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");
hcf_init = TRUE;

# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Detect Visual Studio 2005 installs
key = "SOFTWARE\Microsoft\VisualStudio\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2005_path = item[1];
    vs2005_root = ereg_replace(
      pattern:"^(.+)\\Common7\\IDE\\$", replace:"\1", string:vs2005_path,
      icase:TRUE
    );
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


# Determine if we should look for the redistributable.
#
# nb: other than potentially slowing down a scan because we're trying
#     to check for a couple of files, there's no downside to flagging
#     it as installed.
redistributable_installed = FALSE;
if (report_paranoia < 2)
{
  get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated");

  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (!isnull(list))
  {
    foreach name (keys(list))
    {
      prod = list[name];
      if (prod && ereg(pattern:"^Microsoft Report Viewer Redistributable 2005", string:prod, icase:TRUE))
      {
        redistributable_installed = TRUE;
      }
    }
  }
}
else redistributable_installed = TRUE;




# Check files.

vuln = 0;

# - Visual Studio 2005 SP1
if (vs2005_root)
{
  path = vs2005_root + '\\SDK\\v2.0\\BootStrapper\\Packages\\ReportViewer';
  if (
    hotfix_is_vulnerable(file:"Microsoft.ReportViewer.WebForms.dll", version:"8.0.50727.5677", path:path, bulletin:bulletin, kb:'2548826') ||
    hotfix_is_vulnerable(file:"ReportViewer.exe",                    version:"2.0.50727.5677", path:path, bulletin:bulletin, kb:'2548826')
  ) vuln++;
}

# - Microsoft Report Viewer 2005 SP1 Redistributable Package
if (redistributable_installed)
{
  path = winroot + "\Microsoft.NET\Framework\v2.0.50727\Microsoft Report Viewer Redistributable 2005";
  if (
    hotfix_is_vulnerable(file:"Install.exe",                         version:"8.0.50727.5677", path:path, bulletin:bulletin, kb:'2579115') ||
    hotfix_is_vulnerable(file:"Microsoft.ReportViewer.WebForms.dll", version:"8.0.50727.5677", path:path, bulletin:bulletin, kb:'2579115')
  ) vuln++;
}


# Report a problem if a vulnerable instance was found.
if (vuln)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
