#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40926);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Total Commander Detection");
  script_summary(english:"Checks if Total Commander is installed");

  script_set_attribute(attribute:"synopsis", value:"A Windows file explorer utility is installed on the remote system.");

  script_set_attribute(attribute:"description", value:
"Total Commander, a shareware file explorer for Windows, is installed
on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.ghisler.com/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies.");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

if(!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1,"The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName' KB items are missing.");

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod &&  "Total Commander" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   break;
  }
}

if (isnull(installstring)) exit(0, "No evidence of Total Commander is found in the Uninstaller's registry hive.");

# Get the install path

name   =  kb_smb_name();
port   =  kb_smb_transport();
login  =  kb_smb_login();
pass   =  kb_smb_password();
domain =  kb_smb_domain();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share with the supplied credentials.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1,"Can't connect to remote registry.");
}

key = installstring;
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If Total Commander is installed...
  item = RegQueryValue(handle:key_h, item:"UninstallString");
  if (!isnull(item))
    path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
 NetUseDel();
 exit(1,"Can't get path.");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   =  ereg_replace(pattern:"^[A-Za-z]:(.+)\\tcuninst.exe", replace:"\1\TOTALCMD.EXE", string:path);
path  =  ereg_replace(pattern:"^([A-Za-z]:.+)\\tcuninst.exe", replace:"\1\TOTALCMD.EXE", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1,"Can't connect to " + share + " share with supplied credentials.");
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
);


ver = NULL;
prod_ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  prod_ver = GetProductVersion(handle:fh);

  CloseFile(handle:fh);
}

NetUseDel();

if(!isnull(ver))
{
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
  set_kb_item(name:"SMB/Totalcommander/Path", value:path);
  set_kb_item(name:"SMB/Totalcommander/Version", value:version);

  register_install(
    app_name:"Total Commander",
    path:path,
    version:version,
    display_version:prod_ver);

  if(!isnull(prod_ver))
  {
    set_kb_item(name:"SMB/Totalcommander/Version_UI", value:prod_ver);
    version_ui = prod_ver;
  }
  else version_ui = version;

   report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version_ui + '\n';
  security_note(port:port, extra:report);
}
