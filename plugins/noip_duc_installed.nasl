#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47827);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"No-IP Windows Dynamic Update Client Detection");
  script_summary(english:"Checks for DUC executable");

  script_set_attribute(attribute:"synopsis", value:"A dynamic DNS client is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"The No-IP Windows dynamic update client is installed on the remote
Windows host. This software is intended to map a dynamic IP address,
such as those found on a residential broadband or dialup connection,
to a static host name, such as www.example.com. It can also be abused
to host unsanctioned services within a business, university, or other
organization.");
  script_set_attribute(attribute:"see_also", value:"http://www.no-ip.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");

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
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated KB item is not set to TRUE.");


# Check for Uninstall key.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
keys = make_list();

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (
      prod &&
      (
        "No-IP.com DUC" >< prod ||
        "No-IP DUC" >< prod
      )
    )
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);
      keys = make_list(keys, key);
    }
  }
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Locate any EXEs.
exes = make_list();

foreach key (keys)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"DisplayIcon");
    if (!isnull(value) && ereg(pattern:"DUC[0-9]+\.exe", string:value[1], icase:TRUE))
    {
      exe = value[1];
      exes = make_list(exes, exe);
    }

    value = RegQueryValue(handle:key_h, item:"UninstallString");
    if (!isnull(value) && ereg(pattern:"DUC[0-9]+\.exe", string:value[1], icase:TRUE))
    {
      exe = value[1];
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:exe);
      exes = make_list(exes, exe);
    }

    RegCloseKey(handle:key_h);
  }
}
# - Look in alternate locations.
key = "SYSTEM\CurrentControlSet\Services\NoIPDUCService";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!isnull(value))
  {
    exe = value[1];
    exe = ereg_replace(pattern:'^([^ ]+).*', replace:"\1", string:exe);
    exes = make_list(exes, exe);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


info = "";
installs = 0;
kb_base = "SMB/NoIP_DUC/";

foreach exe (list_uniq(exes))
{
  # Check the version of the main exe.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
  }

  fh = CreateFile(
    file               : exe2,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );

  if (isnull(fh)) continue;

  version = "";
  ver = GetFileVersion(handle:fh);
  if (isnull(ver))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize < 100000) ofs = 0;
    else ofs = int((fsize / 4) * 3);

    while (fsize > 0 && ofs <= fsize && !version)
    {
      data = ReadFile(handle:fh, length:16384, offset:ofs);
      if (strlen(data) == 0) break;
      data = str_replace(find:raw_string(0), replace:"", string:data);

      while (strlen(data)  && "No-IP DUC v" >< data)
      {
        data = strstr(data, "No-IP DUC v") - "No-IP DUC v";
        blob = data - strstr(data, '\r\n');
        pat = "^([0-9\.]+).*";
        if (ereg(pattern:pat, string:blob))
        {
          version = ereg_replace(pattern:pat, replace:"\1", string:blob);
        }
        if (version) break;
      }
      ofs += 16383;
    }
  }
  else
  {
    if (ver[3] == 0) version = join(make_list(ver[0], ver[1], ver[2]), sep:".");
    else version = join(ver, sep:".");
  }
  CloseFile(handle:fh);

  if (!version) exit(1, "Couldn't get file version of '"+exe+"'.");

  file = ereg_replace(pattern:"^.+\\([^\\]+)$", replace:"\1", string:exe);
  path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:exe);

  set_kb_item(name:kb_base+"/"+version+"/File", value:file);
  set_kb_item(name:kb_base+"/"+version+"/Path", value:path);
  set_kb_item(name:kb_base+"Version", value:version);

  register_install(
    app_name:"The No-IP Dynamic Update Client",
    path:path,
    extra:make_array('File', file),
    version:version);

  installs++;
  info +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}
NetUseDel();

if (installs == 0) exit(0, "The No-IP Dynamic Update Client is not installed.");
else
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);

  if (report_verbosity > 0) security_note(port:port, extra:info);
  else security_note(port);
}
