#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40619);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/10/06 23:50:20 $");

  script_name(english:"Subversion Client/Server Detection (Windows)");
  script_summary(english:"Checks if Subversion Client/Server is installed.");

  script_set_attribute(attribute:"synopsis", value:"Version control software is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Subversion, an open source version control system, is installed on the
remote system. Subversion can be installed on Windows using
CollabNet-certified binaries or through third-party packages such as
VisualSVN, TortoiseSVN, and SlikSVN. Third-party packages typically
include CollabNet binaries in their respective packages, and it is not
uncommon to have more than one Subversion package installed on a given
system.

This plugin attempts to identify the versions of Subversion client or
server included with popular Subversion packages.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

installed = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Figure out if Subversion is installed.
# We use this later to make a guess if subversion
# is installed.
subversion_installed = 0;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Subversion" >< prod)
    {
      subversion_installed = 1;
      break;
    }
  }
}

paths = make_array();

# Search for CollabNet
key = "SOFTWARE\CollabNet\Subversion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    # Try to be locale independent.
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey + "\Server";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Install Location");
        if (!isnull(value)) paths["CollabNet"]= value[1];
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

# Search for VisualSVN
key = "SOFTWARE\VisualSVN\VisualSVN Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value))
  {
    path = value[1];
    if (!ereg(pattern:"\\$",string:path))
      paths["VisualSVN"] = path + "\bin";
    else
      paths["VisualSVN"] = path + "bin";
  }
  RegCloseKey(handle:key_h);
}

# Search for SlikSVN
key = "SOFTWARE\SlikSvn\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Location");
  if (!isnull(value)) paths["SlikSVN"] = value[1];
  RegCloseKey(handle:key_h);
}

# Search for TortoiseSVN client
key = "SOFTWARE\TortoiseSVN";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ProcPath");
  if (!isnull(value)) paths["TortoiseSVN"] = value[1];
  RegCloseKey(handle:key_h);
}

# Search for WANDisk
key = "SYSTEM\CurrentControlSet\services\WANdiscoSubversionServer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  match = eregmatch(string:value[1], pattern:"([A-Za-z]:\\.*\\)[^\\]+\.exe");
  if (!isnull(match)) paths["WANdisco"] = match[1]- "\Apache2\bin\";
  RegCloseKey(handle:key_h);
}

# Search for CollabNetServer
key = "SYSTEM\CurrentControlSet\services\CollabNetSubversionServer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  match = eregmatch(string:value[1], pattern:"([A-Za-z]:\\.*\\)[^\\]+\.exe");
  if (!isnull(match)) paths["CollabNetEdge"] = match[1]- "\Apache2\bin\";
  RegCloseKey(handle:key_h);
}

# Make a guess for Apache installs
if (subversion_installed)
{
  path = hotfix_get_programfilesdir() + "\Subversion\bin";
  paths["Apache"] = path;
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!empty_or_null(paths))
{
  foreach prod (keys(paths))
  {
    exe_client = NULL;
    exe_svr    = NULL;

    # Don't look for SVN Server for TortoiseSVN
    if ("TortoiseSVN" >< prod)
    {
      exe_client  = paths[prod];
      paths[prod] = str_replace(find:"\TortoiseProc.exe",replace:"",string:paths[prod]);
    }
    else
    {
      exe_client = paths[prod] + "\svn.exe";
      exe_svr    = paths[prod] + "\svnserve.exe";
    }

    # Handle svn client installs
    if (!isnull(exe_client))
    {
      client_ver = hotfix_get_fversion(path:exe_client);

      if (client_ver['error'] != HCF_OK && prod == 'Apache')
      {
        paths["Apache"] = hotfix_get_programfilesdirx86() + "\Subversion\bin";
        exe_client = ereg_replace(pattern:"(Program Files)", replace:"\1 (x86)", string:exe_client);
        client_ver = hotfix_get_fversion(path:exe_client);
      };

      if (client_ver['error'] == HCF_OK && !empty_or_null(client_ver['value']))
      {
        version = string(client_ver['value'][0], ".", client_ver['value'][1], ".", client_ver['value'][2]);
        register_install(
          app_name : "Subversion Client",
          version  : version,
          path     : paths[prod],
          extra    : make_array('Packaged with', prod),
          cpe      : "cpe:/a:apache:subversion"
        );

        installed = TRUE;
      }
    }

    # Handle svn server installs
    if (!isnull(exe_svr))
    {
      server_ver = hotfix_get_fversion(path:exe_svr);

      if(server_ver['error'] != HCF_OK && prod == 'Apache')
      {
        paths["Apache"] = hotfix_get_programfilesdirx86() + "\Subversion\bin";
        exe_svr = ereg_replace(pattern:"(Program Files)", replace:"\1 (x86)", string:exe_svr);
        server_ver = hotfix_get_fversion(path:exe_svr);
      };

      if (server_ver['error'] == HCF_OK && !empty_or_null(server_ver['value']))
      {
        version = string(server_ver['value'][0], ".", server_ver['value'][1], ".", server_ver['value'][2]);
        register_install(
          app_name : "Subversion Server",
          version  : version,
          path     : paths[prod],
          extra    : make_array('Packaged with', prod),
          cpe      : "cpe:/a:apache:subversion"
        );

        installed = TRUE;
      }
    }
  }
}

close_registry();

if (installed) report_installs(port:port);
else audit(AUDIT_NOT_INST, "Subversion Client/Server");
