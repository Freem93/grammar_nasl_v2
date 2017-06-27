#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56412);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Symantec Enterprise Vault Detection");
  script_summary(english:"Checks if Enterprise Vault is installed");

  script_set_attribute(attribute:"synopsis", value:"An archiving application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Symantec Enterprise Vault, an archiving application, is installed on
the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/enterprise-vault");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:symantec:enterprise_vault");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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
  exit(1, "Can't connect to the remote registry.");
}

path = NULL;
key = "SOFTWARE\KVS\Enterprise Vault\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "No evidence of Symantec Enterprise Vault was found in the registry.");
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = "\EVConverterSandbox.exe";
file =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1" + exe, string:path);

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Check a different file for versions < 8.0 SP5
if (isnull(fh))
{
  exe = "\EVservice.exe";
  file =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1" + exe, string:path);
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
}

# If the file can't be opened, it's likely because it's been uninstalled
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Symantec Enterprise Vault is not actually installed.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, "Couldn't get file version information from '"+(share-'$')+":"+file+"'.");

display_ver = strcat(join(make_list(ver[0], ver[1], ver[2]), sep:'.'), ' build ', ver[3]);
set_kb_item(name:'SMB/enterprise_vault/path', value:path);
set_kb_item(name:'SMB/enterprise_vault/ver', value:join(ver, sep:'.'));

register_install(
  app_name:"Symantec Enterprise Vault",
  path:path,
  version:join(ver, sep:'.'),
  display_version:display_ver,
  cpe:"x-cpe:/a:symantec:enterprise_vault");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + display_ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
