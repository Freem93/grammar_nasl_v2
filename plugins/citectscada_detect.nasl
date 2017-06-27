#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33169);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"CitectSCADA Detection");
  script_summary(english:"Gets version of CitectSCADA");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is running CitectSCADA.");
  script_set_attribute(attribute:"description", value:
"The remote host is running CitectSCADA, which is used to gather data
from PLC's, RTU's and present it within an Human Machine Interface
(HMI) for control and monitoring of physical processes. CitectSCADA is
commonly found in power, electric, water, and other SCADA systems.");
  script_set_attribute(attribute:"see_also", value:"http://www.citect.com/index.php?option=com_content&view=article&id=1457&Itemid=1314" );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Find where it's installed.
path = NULL;

key = "SOFTWARE\Citect\Citect HMI/SCADA";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9]+\.")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"InstallDir");
        if (!isnull(item))
        {
          path = item[1];
          path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Determine its version.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
xml   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\CtVersion.xml", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:xml,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
version = NULL;
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  data = ReadFile(handle:fh, length:fsize, offset:0);
  if ("<BUILD" >< data)
  {
    build = strstr(data, "<BUILD") - "<BUILD";
    build = build - strstr(build, "</BUILD>");

    if ("<LABEL>" >< build)
    {
      version = strstr(data, "<LABEL>") - "<LABEL>";
      version = version - strstr(version, "<");
      if (version !~ "^[0-9][0-9.]+") version = NULL;
    }
  }

  CloseFile(handle:fh);
}
NetUseDel();


if (version)
{
  kb_key = "SCADA/CitectSCADA";
  set_kb_item(name:kb_key, value:TRUE);
  set_kb_item(name:kb_key+"/Version", value:version);
  set_kb_item(name:kb_key+"/Path", value:path);
  register_install(
    app_name:"CitectSCADA",
    path:path,
    version:version);

  if (report_verbosity)
  {
    report = string(
      "\n",
      "  Version : ", version, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
