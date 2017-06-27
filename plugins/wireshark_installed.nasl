#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34112);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_name(english:"Wireshark / Ethereal Detection (Windows)");
  script_summary(english:"Determines if Wireshark/Ethereal is installed");

 script_set_attribute(attribute:"synopsis", value:"A network protocol analyzer is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Wireshark (formerly known as Ethereal) is installed on the remote
Windows host.

Wireshark is a popular open source network protocol analyzer (sniffer)
typically used for network troubleshooting and protocol analysis.");
 script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/about.html");
 script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/news/20060607.html" );
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/09");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

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

# Get the install path

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
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

exes = make_array();
paths = make_array();
foreach sniffer (make_list("Wireshark", "Ethereal"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + tolower(sniffer) + '.exe';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item)) exes[sniffer] = item[1];

    item = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(item)) paths[sniffer] = item[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

info = "";
foreach sniffer (keys(paths))
{
  exe = exes[sniffer];
  path = paths[sniffer];

  share = ereg_replace(pattern:"^([A-Za-z]):.+", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1);
  }

  fh = CreateFile(file:exe2,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    if (!isnull(ver))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2]);
      set_kb_item(name:"SMB/Wireshark/"+version, value:path);

      register_install(
        app_name:sniffer,
        path:path,
        version:version,
        cpe:"cpe:/a:wireshark:wireshark");

      info += '  Application : ' + sniffer + '\n' +
              '  Path        : ' + path + '\n' +
              '  Version     : ' + version + '\n' +
              '\n';

      CloseFile(handle:fh);
    }
  }
}
NetUseDel();


if (info)
{
  set_kb_item(name:"SMB/Wireshark/Installed", value:TRUE);
  if (report_verbosity) security_note(port:port,extra:'\n'+info);
  else security_note(port);
}
