#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46238);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"HP Virtual Machine Manager Detection");
  script_summary(english:"Checks for bin/product.version in a VMM installation");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management product is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"HP Virtual Machine Manager (VMM) is installed on the remote host. VMM
provides centralized management for multiple virtualization platforms.");
  script_set_attribute(attribute:"see_also", value:"http://www.hp.com/go/vmmanage");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_virtual_machine_management");
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
  exit(1, "Cannot connect to remote registry.");
}

prods = make_list(
  'SOFTWARE\\HP\\Insight Control virtual machine management',  # 6.0
  'SOFTWARE\\HP\\Virtual Machine Management Pack'              # pre-6.0
);
paths = make_list();

# Figure out the installation path and product version
foreach key (prods)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    path = RegQueryValue(handle:key_h, item:'ExtensionBase');
    if (path) paths = make_list(paths, path[1]);
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  NetUseDel();
  exit(0, "HP Virtual Machine Manager does not appear to be installed.");
}

# Research indicates only one version of VMM can be installed at a time,
# but it's possible multiple versions will be in the registry due to an
# improper uninstallation.  We'll stop on the first evidence of a valid
# installation
ver = NULL;

foreach path (paths)
{
  NetUseDel(close:FALSE);

  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  txt = ereg_replace(
    pattern:'^[A-Za-z]:(.*)',
    replace:"\1\bin\product.version",
    string:path
  );

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    debug_print("Unable to access share: " + share);
    continue;
  }

  fh = CreateFile(
    file:txt,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (fh)
  {
    # This file was ~200 bytes in a 3.7.2 install - the 1k check is just a
    # sanity check to ensure we don't try to read a very large amount
    len = GetFileSize(handle:fh);
    if (len > 1024) len = 1024;
    data = ReadFile(handle:fh, length:len, offset:0);

    if (strlen(data) == len)
    {
      match = eregmatch(string:data, pattern:'productVersion = ([0-9.]+)');
      if (match)
      {
        ver = match[1];
        set_kb_item(name:'SMB/hpvmm/version', value:ver);
        set_kb_item(name:'SMB/hpvmm/path', value:path);
      }
    }
    else debug_print('Unable to read ' + len + ' bytes from ' + path);

    CloseFile(handle:fh);

    if (ver) break;
    else debug_print("Error getting version from "+share+':'-'$'+txt);
  }
}

NetUseDel();

if (isnull(ver)) exit(1, "Unable to extract the version of HP VMM.");

register_install(
  app_name:"HP Virtual Machine Manager",
  path:path,
  version:ver,
  cpe:"cpe:/a:hp:insight_virtual_machine_management");

if (report_verbosity > 0)
{
  report =
    '\n  Path      : '+path+
    '\n  Version   : '+ver+'\n';
  security_note(port:port, extra:report);
}
else security_note(port);
