#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45017);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Symantec IM Manager Detection");
  script_summary(english:"Looks for Symantec IM Manager");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging security application is installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"Symantec IM Manager, used to manage instant messaging traffic, is
installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/im-manager");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:im_manager");
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
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

name    =  kb_smb_name();
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

dir = NULL;

key = "SOFTWARE\IMLogic\IM Linkage";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  dir = RegQueryValue(handle:key_h, item:"TargetFolder");
  if (!isnull(dir)) dir = dir[1] - "\IMLinkage";

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(dir))
{
  NetUseDel();
  exit(0, "No evidence of IM Manager was found in the registry.");
}
NetUseDel(close:FALSE);

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:dir);
exe = ereg_replace(
  pattern:'^[A-Za-z]:(.*)',
  replace:"\1\IMLogService.exe",
  string:dir
);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (fh)
{
  ver = GetFileVersion(handle:fh);
  if (ver)
  {
    build = join(ver, sep:'.');
    set_kb_item(name:'SMB/Symantec/im_mgr/Build', value:build);
    set_kb_item(name:'SMB/Symantec/im_mgr/Path', value:dir);

    register_install(
      app_name:"Symantec IM Manager",
      path:dir,
      version:build,
      cpe:"cpe:/a:symantec:im_manager");
  }
  CloseFile(handle:fh);
}
else
{
  NetUseDel();
  exit(1, 'Unable to access IM Manager file: '+share-'$'+':'+exe);
}
NetUseDel();

if (isnull(ver)) exit(1, 'Unable to extract IM Manager build version number.');

if (report_verbosity > 0)
{
  report = '\n  Build version : '+build +
           '\n  Path          : '+dir + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
