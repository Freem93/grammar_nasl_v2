#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55573);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/11/17 16:38:32 $");

  script_name(english:"LibreOffice Detection");
  script_summary(english:"Checks for LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an alternative office suite.");
  script_set_attribute(attribute:"description", value:
"LibreOffice is installed on the remote Windows host. LibreOffice is a
free software office suite developed as a fork of OpenOffice.org.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

ver_ui_arr =
make_array(
  "3.3.6.500", "3.3.0",
  "3.3.8.500", "3.3.1",
  "3.3.201.500", "3.3.2 RC1",
  "3.3.202.500", "3.3.2",
  "3.3.301.500", "3.3.3",
  "3.3.401.500", "3.3.4",
  "3.4.11.500", "3.4.0 RC1",
  "3.4.12.500", "3.4.0",
  "3.4.101.500", "3.4.1 RC1",
  "3.4.102.500", "3.4.1 RC2",
  "3.4.103.500", "3.4.1",
  "3.4.201.500", "3.4.2",
  "3.4.301.500", "3.4.3 RC1",
  "3.4.302.500", "3.4.3",
  "3.4.401.500", "3.4.4 RC1",
  "3.4.402.500", "3.4.4",
  "3.4.501.500", "3.5.1 RC1",
  "3.4.502.500", "3.4.5",
  "3.4.601.500", "3.4.6 RC1",
  "3.4.602.500", "3.4.6",
  "3.5.0.11", "3.5.0 RC1",
  "3.5.0.12", "3.5.0 RC2",
  "3.5.0.13", "3.5.0",
  "3.5.0.101", "3.5.1 RC1",
  "3.5.0.102", "3.5.1",
  "3.5.0.101", "3.5.1 RC1",
  "3.5.0.202", "3.5.2",
  "3.5.3.1", "3.5.3 RC1",
  "3.5.3.2", "3.5.3",
  "3.5.4.2", "3.5.4",
  "3.5.5.3", "3.5.5",
  "3.5.7.2", "3.5.7",
  "3.6.0.101", "3.6.0 RC1",
  "3.6.0.102", "3.6.0 RC2",
  "3.6.0.104", "3.6.0",
  "3.6.1.1", "3.6.1 RC1",
  "3.6.1.2", "3.6.1",
  "3.6.2.1", "3.6.2 RC1",
  "3.6.2.2", "3.6.2",
  "3.6.3.1", "3.6.3 RC1",
  "3.6.3.2", "3.6.3",
  "3.6.4.1", "3.6.4 RC1",
  "3.6.4.3", "3.6.4 RC3",
  "3.6.5.2", "3.6.5 Final",
  "3.6.6.1", "3.6.6 RC1",
  "3.6.6.2", "3.6.6 RC2",
  "3.6.7.1", "3.6.7 RC1",
  "3.6.7.2", "3.6.7 RC2",
  "4.0.1.2", "4.0.1 Final",
  "4.0.4.1", "4.0.4 RC1",
  "4.0.4.2", "4.0.4 RC2",
  "4.0.5.1", "4.0.5 RC1",
  "4.0.5.2", "4.0.5 RC2",
  "4.0.6.1", "4.0.6 RC1",
  "4.0.6.2", "4.0.6 RC2",
  "4.1.0.0", "4.1.0 Beta",
  "4.1.0.1", "4.1.0 RC1",
  "4.1.0.2", "4.1.0 RC2",
  "4.1.0.3", "4.1.0 RC3",
  "4.1.0.4", "4.1.0 RC4",
  "4.1.1.1", "4.1.1 RC1",
  "4.1.1.2", "4.1.1 RC2",
  "4.1.2.1", "4.1.2 RC1",
  "4.1.2.2", "4.1.2 RC2",
  "4.1.2.3", "4.1.2 RC3",
  "4.1.3.1", "4.1.3 RC1",
  "4.1.3.2", "4.1.3 RC2",
  "4.1.4.1", "4.1.4 RC1",
  "4.1.4.2", "4.1.4 RC2",
  "4.1.5.1", "4.1.5 RC1",
  "4.1.5.2", "4.1.5 RC2",
  "4.1.5.3", "4.1.5 RC3",
  "4.2.0.0", "4.2.0 Beta",
  "4.2.0.1", "4.2.0 RC1",
  "4.2.0.2", "4.2.0 RC2",
  "4.2.0.3", "4.2.0 RC3",
  "4.2.0.4", "4.2.0 RC4",
  "4.2.1.1", "4.2.1",
  "4.2.2.1", "4.2.2",
  "4.2.3.1", "4.2.3",
  "4.2.6.2", "4.2.6",
  "4.2.6.3", "4.2.6-secfix",
  "4.2.7.2", "4.2.7",
  "4.2.8.2", "4.2.8",
  "4.3.1.2", "4.3.1",
  "4.3.2.2", "4.3.2",
  "4.3.3.2", "4.3.3",
  "4.4.5.2", "4.4.5",
  "4.4.6.3", "4.4.6",
  "5.0.0.5", "5.0.0",
  "5.0.1.2", "5.0.1"
);

get_kb_item_or_exit("SMB/Registry/Enumerated");

kb_base = "SMB/LibreOffice";

# Connect to the appropriate share.
name    =  kb_smb_name();
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
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Find where it's installed.
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\soffice.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SOFTWARE\LibreOffice.org";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey) && subkey =~ "^LibreOffice")
      {
        key2 = key + "\" + subkey;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          info2 = RegQueryInfoKey(handle:key2_h);
          for (i2=0; i2<info2[1]; ++i2)
          {
            subkey2 = RegEnumKey(handle:key2_h, index:i2);
            if (strlen(subkey2) && subkey2 =~ "^[0-9]+\.[0-9]+")
            {
              key3 = key + "\" + subkey + "\" + subkey2;
              key3_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
              if (!isnull(key3_h))
              {
                info3 = RegQueryInfoKey(handle:key3_h);
                for (i3=0; i3<info3[1]; ++i3)
                {
                  subkey3 = RegEnumKey(handle:key3_h, index:i3);
                  if (strlen(subkey3) && subkey3 =~ "^\{[0-9A-Fa-f-]+\}")
                  {
                    key4 = key + "\" + subkey + "\" + subkey2 + "\" + subkey3;
                    key4_h = RegOpenKey(handle:hklm, key:key4, mode:MAXIMUM_ALLOWED);
                    if (!isnull(key4_h))
                    {
                      value = RegQueryValue(handle:key4_h, item:"INSTALLLOCATION");
                      if (isnull(value)) value = RegQueryValue(handle:key4_h, item:"OFFICEINSTALL");
                      if (!isnull(value))
                      {
                        path = value[1];
                        path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
                        paths = make_list(paths, path);
                      }
                      RegCloseKey(handle:key4_h);
                    }
                  }
                }
                RegCloseKey(handle:key3_h);
              }
            }
          }
          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "LibreOffice");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\program\soffice.exe", string:path);
ini =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\program\version.ini", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:ini,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+(share-'$')+":"+ini+"'.");
}

length = GetFileSize(handle:fh);
ini_content = ReadFile(handle:fh, offset:0, length:length);
if("LibreOffice" >!< ini_content || "libreoffice" >!< ini_content)
  exit(0, "Unable to verify LibreOffice install.");
CloseFile(handle:fh);

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+(share-'$')+":"+exe+"'.");
}

version = NULL;

version = GetFileVersion(handle:fh);
if(version != NULL)
{
  version = join(version, sep: '.');
}
else
{
  NetUseDel();
  audit(AUDIT_VER_FAIL, (share-'$')+":"+exe);
}
CloseFile(handle:fh);

NetUseDel();

set_kb_item(name:kb_base+"/Path", value:path);
set_kb_item(name:kb_base+"/Version", value:version);

ver_ui = version;
if(!isnull(ver_ui_arr[version]))
  ver_ui = ver_ui_arr[version] + ' (' + version + ')';

set_kb_item(name:kb_base+"/Version_UI", value:ver_ui);

register_install(
  app_name:"LibreOffice",
  path:path,
  version:version,
  display_version:ver_ui,
  cpe:"cpe:/a:libreoffice:libreoffice");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver_ui + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
