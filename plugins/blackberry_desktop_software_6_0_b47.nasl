#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49674);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2010-2600");
  script_bugtraq_id(43139);
  script_osvdb_id(67992);
  script_xref(name:"Secunia", value:"41346");

  script_name(english:"BlackBerry Desktop Software < 6.0 B47 Path Subversion Arbitrary DLL Injection Code Execution");
  script_summary(english:"Checks the version of DesktopMgr.exe or Rim.Desktop.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a DLL
loading vulnerability.");

  script_set_attribute(attribute:"description", value:
"BlackBerry Desktop Software has a DLL loading vulnerability that
occurs when the program searches for a DLL file in the current working
directory. Attackers may exploit the issue by placing a specially
crafted DLL file and another file associated with the application in
an location controlled by the attacker. When the associated file is
launched, the attacker's arbitrary code can be executed.");

  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB24242");
  script_set_attribute(attribute:"solution", value:"Upgrade to BlackBerry Desktop Software 6.0 B47 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
# From "About Blackberry Desktop Software"

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25"); 
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


# Check whether it's installed.
path = NULL;
bins = make_list("DesktopMgr.exe","Rim.Desktop.exe");
bundle = NULL;

key = "SOFTWARE\Research in Motion\Common\Installations\Desktop";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Directory");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  value = RegQueryValue(handle:key_h, item:"BundleNumber");
  if (!isnull(value))
  {
    bundle = value[1];
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "BlackBerry Desktop Software is not installed.");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

versionfail = TRUE;

foreach bin (bins)
{
  # Check the version of the main exe.
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+bin, string:path);

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
    versionfail = FALSE;
    break;
  }
}

NetUseDel();

# Check the version number.
if (!isnull(ver))
{

  vers = ver;
  report_version = NULL;

  for (i=0; i<max_index(vers); i++)
    vers[i] = int(vers[i]);

  if (vers[0] == 6 && vers[1] == 0) report_version = "6.0";

  version = join(ver,sep:".");
  fixed_version = "6.0.0.43";
  fixed_bundle  = 47;
  report_fixed = "6.0";

  if (isnull(bundle)) bundle = 0;

  if (
    (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1) ||
    (version == fixed_version && (bundle < fixed_bundle))
  )
  {
    if (report_verbosity > 0)
    {
        report = '\n  Path              : ' + path;
        if(vers[0] == 6) report += '\n  Installed version : ' + report_version +  ' B' + bundle;
        else             report += '\n  Installed version : ' + version;
        report +=                  '\n  Fixed version     : ' + report_fixed + ' B' + fixed_bundle + '\n';
        security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }

  if(!isnull(report_version)) exit(0, "BlackBerry Desktop Software version "+report_version+" B"+bundle+" is installed and not vulnerable.");
  else exit(0, "BlackBerry Desktop Software version "+version+" is installed and not vulnerable.");
}

if (versionfail == TRUE) exit(0, "Couldn't find "+bins[0]+" or "+bins[1]+" in '"+path+"'.");
else exit(1, "Couldn't get version of "+bins[0]+" or "+bins[1]+" in '"+path+"'.");
