#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40770);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_name(english:"Ipswitch WS_FTP Server Version Detection (credentialed check)");
  script_summary(english:"Check the version of WS_FTP");

   script_set_attribute(attribute:"synopsis", value:"The remote Windows host is running WS_FTP Server.");
   script_set_attribute(attribute:"description", value:
"Ipswitch WS_FTP Server, a commercial FTP server for Windows, is
installed on the remote host.");
   script_set_attribute(attribute:"see_also", value:"http://www.ipswitchft.com/products/ws_ftp_server/");
   script_set_attribute(attribute:"solution", value:
"Make sure that use of this software conforms to your organization's
acceptable use and security policies.");
   script_set_attribute(attribute:"risk_factor", value:"None");

   script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:ws_ftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

#Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

name    = kb_smb_name();
port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

#Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

#Determine the install path
path = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1, "Couldn't find required registry keys.");
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Ipswitch WS_FTP")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  NetUseDel();
  exit(0, "Ipswitch WS_FTP Server is not installed.");
}
#Determine if the install is earlier than 6.0
ver_item = NULL;
key = "SOFTWARE\Ipswitch\iFtpSvc";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Version");
  ver_item = item[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(item))
{
  NetUseDel();
  exit(1, "Could not determine version from the registry.");
}

#If the Version is earlier than 6.0, determine the version from iFtpSvc.exe
if (ver_item =~ "^([0-5]\.+)")
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\iFtpSvc.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  #Grab the version number if the file was opened successfully.
  ver = NULL;
  if (fh)
  {
    ver = split(GetProductVersion(handle:fh), sep:", ", keep:FALSE);
    version = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];
    CloseFile(handle:fh);
    NetUseDel();
  }
  else
  {
    NetUseDel();
    exit(1, "Unable to access WS_FTP file: " + exe);
  }
}
#If the Version is 6.0 or later, determine the version by reading SSHServerApi.dll
else
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SSHServerApi.dll", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  version = NULL;
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize < 250000) off = 0;
    else off = fsize - 250000;

    while (fsize > 0 && off <= fsize && isnull(version))
    {
      data = ReadFile(handle:fh, length:16384, offset:off);
      if (strlen(data) == 0) break;
      data = str_replace(find:raw_string(0), replace:"", string:data);

      while (strlen(data)  && "220{0}{1} {2}2 WS_FTP Server " >< data)
      {
        data = strstr(data, "220{0}{1} {2}2 WS_FTP Server ") - "220{0}{1} {2}2 WS_FTP Server ";
        blob = data - strstr(data, '\r\n');
        pat = "^([0-9\.]+).*";
        if (ereg(pattern:pat, string:blob))
        {
          version = ereg_replace(pattern:pat, replace:"\1", string:blob);
        }
        if (version) break;
      }
      off += 16383;
    }
    CloseFile(handle:fh);
  }
  NetUseDel();
}

if (!isnull(version))
{
  kb_base = "SMB/WS_FTP_Server";
  set_kb_item(name:kb_base+"/Path", value:path);
  set_kb_item(name:kb_base+"/Version", value:version);

  register_install(
    app_name:"Ipswitch WS_FTP Server",
    path:path,
    version:version,
    cpe:"cpe:/a:ipswitch:ws_ftp");

  if(report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Version        : ", version, "\n",
      "  Path           : ", path, "\n",
      "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
