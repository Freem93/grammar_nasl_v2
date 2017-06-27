#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38971);
  script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"Novell GroupWise Internet Agent Detection");
  script_summary(english:"Checks to see if GWIA is installed");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an SMTP server.");
  script_set_attribute(attribute:"description", value:
"Novell GroupWise Internet Agent (GWIA) is installed on the remote
host. GWIA is part of the GroupWise suite, and is used for sending and
receiving messages over the Internet.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/groupwise/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_require_ports(139, 445);
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
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

gwia_path = NULL;
gwia_key = "SYSTEM\CurrentControlSet\Services\GWIA";
gwia_key_h = RegOpenKey(handle:hklm, key:gwia_key, mode:MAXIMUM_ALLOWED);

if (!isnull(gwia_key_h))
{
  item = RegQueryValue(handle:gwia_key_h, item:"ImagePath");

  # Removes the enclosing quotes from the pathname
  if (!isnull(item))
    gwia_path = ereg_replace(pattern:'^"(.*)"$', replace:"\1", string:item[1]);

  RegCloseKey (handle:gwia_key_h);
}

RegCloseKey(handle:hklm);

if (isnull(gwia_path))
{
  NetUseDel();
  exit(0);
}


# Determine its version from the executable itself.
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:gwia_path);
exe =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:gwia_path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

filever = NULL;
if (!isnull(fh))
{
  filever = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (isnull(filever)) exit(0);

version = string(filever[0], ".", filever[1], ".", filever[2], ".", filever[3]);
set_kb_item(name:"SMB/GWIA/Version", value:version);
set_kb_item(name:"SMB/GWIA/Path", value:gwia_path);

register_install(
  app_name:"Novell GroupWise Internet Agent",
  path:gwia_path,
  version:version);

if (report_verbosity > 0)
{
  report = string(
    "\n",
    "Nessus found the following install of GroupWise Internet Agent :\n\n",
    "  Path    : ", gwia_path, "\n",
    "  Version : ", version, "\n"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
