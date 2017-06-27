#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50525);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"Microsoft Forefront Unified Access Gateway Installed");
  script_summary(english:"Checks if UAG / IAG is installed");

  script_set_attribute(attribute:"synopsis", value:"A VPN solution is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Forefront Unified Access Gateway (formerly known as
Microsoft Intelligent Application Gateway, or IAG) is installed on the
remote host. This software provides secure remote access to corporate
networks for remote employees and business partners.");
  script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/forefront/uag");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

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


name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

path = NULL;
key = "SOFTWARE\WhaleCom\e-Gap\Configuration";
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
  exit(0, "No evidence of Forefront UAG found in the registry.");
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = "\common\bin\SessionMgrCom.exe";
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

# If the file can't be open, it's likely because it's been uninstalled
if (fh)
{
  set_kb_item(name:'SMB/forefront_uag/path', value:path);
  installed = TRUE;
  CloseFile(handle:fh);
}
else installed = FALSE;

NetUseDel();

if (!installed) exit(1, exe + ' was not found at '+path);

register_install(
  app_name:"Microsoft Forefront Unified Access Gateway",
  path:path);

if (report_verbosity > 0)
{
  report = '\nForefront UAG was detected at the following location :\n\n' + path + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);

