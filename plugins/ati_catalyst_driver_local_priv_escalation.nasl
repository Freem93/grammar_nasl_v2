#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25931);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2007-4315");
  script_bugtraq_id(25265);
  script_osvdb_id(39562);

  script_name(english:"ATI Catalyst Dynamic Driver (atidsmxx.sys) Local Privilege Escalation");
  script_summary(english:"Checks version of atidcmxx.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
local privilege escalation attack.");
  script_set_attribute(attribute:"description", value:
"The version of the ATI Catalyst Software Suite installed on the remote
Windows Vista host reportedly allows a local user to load unsigned
drivers into the kernel and thereby gain administrative control of the
affected host.");
  script_set_attribute(attribute:"see_also", value:"http://bluepillproject.org/stuff/IsGameOver.ppt");
  script_set_attribute(attribute:"see_also", value:"http://blogs.zdnet.com/security/?p=438" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197bebdf" );
  script_set_attribute(attribute:"see_also", value:"http://ati.amd.com/support/drivers/vista32/common-vista32.html" );
  script_set_attribute(attribute:"solution", value:"Upgrade to ATI's Catalyst Software Suite 7.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_nativelanman.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Host/OS/smb");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure we're only looking at Vista.
os = get_kb_item("Host/OS/smb");
if ("Windows Vista" >!< os && "Windows 6.0" >!< os)  exit (0);


# Connect to the appropriate share.
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


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\ATI Technologies\Install\ATI Catalyst Install Manager";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of atidcmxx.sys.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Bin\atidcmxx.sys", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  # nb: 3.0.641.0 is the file version from version 7.8 of the Catalyst Software Suite.
  fix = split("3.0.641.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
