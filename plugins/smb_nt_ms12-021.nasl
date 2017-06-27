#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58333);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2012-0008");
  script_bugtraq_id(52329);
  script_osvdb_id(80006);
  script_xref(name:"MSFT", value:"MS12-021");
  script_xref(name:"IAVA", value:"2012-A-0042");

  script_name(english:"MS12-021: Vulnerability in Visual Studio Could Allow Elevation of Privilege (2651019)");
  script_summary(english:"Checks version of Visual Studio Environment Loader");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a development application that is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Microsoft Visual Studio does not properly
validate add-ins in the path before loading them into the application.

An attacker can elevate his privileges by placing a specially crafted
add-in in the path used by Visual Studio and convincing a user with
higher privileges to start Visual Studio.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-021");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visual Studio
2008 SP1, 2010, and 2010 SP1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-021';
kbs = make_list('2669970', '2644980', '2645410');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, 'Can\'t get system root.');

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
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Make sure Visual Studio 2008 is installed
vs2008_path = NULL;
key = "SOFTWARE\Microsoft\VisualStudio\9.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2008_path = item[1];
  }
  else
  {
    key2 = "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\9.0";
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      item = RegQueryValue(handle:key2_h, item:"InstallDir");
      if (!isnull(item))
      {
        vs2008_path = item[1];
      }
      RegCloseKey(handle:key2_h);
    }
  }
  RegCloseKey(handle:key_h);
}

# Detect Visual Studio 2010 path
vs2010_path = NULL;
key = "SOFTWARE\Microsoft\VisualStudio\10.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2010_path = item[1];
  }
  else
  {
    key2 = "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\10.0";
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      item = RegQueryValue(handle:key2_h, item:"InstallDir");
      if (!isnull(item))
      {
        vs2010_path = item[1];
      }
      RegCloseKey(handle:key2_h);
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(vs2008_path) && isnull(vs2010_path))
{
  NetUseDel();
  exit(0, 'No Visual Studio 2008 or 2010 installs were detected on the remote host.');
}

vuln = 0;
# Visual Studio 2008 SP1
if (vs2008_path)
{
  programfilesdir = hotfix_get_programfilesdirx86();
  if (isnull(programfilesdir)) programfilesdir = hotfix_get_programfilesdir();
  path = programfilesdir + '\\Common Files\\Microsoft Shared\\VSA\\9.0\\VsaEnv';
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:vs2008_path);
  if (!is_accessible_share(share:share))
  {
    NetUseDel();
    exit(1, 'is_accessible_share() failed.');
  }

  if (hotfix_is_vulnerable(file:'vsaenv.exe', version:'9.0.30729.5797', min_version:'9.0.30729.0', path:path, bulletin:bulletin, kb:'2669970'))
  {
    vuln++;
  }
}
# Visual Studio 2010
if (vs2010_path)
{
  path = vs2010_path + '\\ShellExtensions\\Platform';
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  if (!is_accessible_share(share:share))
  {
    NetUseDel();
    exit(1, 'is_accessible_share() failed.');
  }

  if (
    hotfix_is_vulnerable(file:'AppenvStub.dll', version:'10.0.40219.377', min_version:'10.0.40219.0', path:path, bulletin:bulletin, kb:'2645410') ||
    hotfix_is_vulnerable(file:'AppenvStub.dll', version:'10.0.30319.552',                             path:path, bulletin:bulletin, kb:'2644980')
  )
  {
    vuln++;
  }
}

hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else exit(0, 'The host is not affected.');
