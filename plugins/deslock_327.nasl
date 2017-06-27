#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31130);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2017/05/16 21:08:26 $");

  script_cve_id("CVE-2008-1141", "CVE-2008-1140", "CVE-2008-1139", "CVE-2008-1138");
  script_bugtraq_id(27862);
  script_osvdb_id(42923, 42924, 42925, 42926);
  script_xref(name:"EDB-ID", value:"5141");
  script_xref(name:"EDB-ID", value:"5142");
  script_xref(name:"EDB-ID", value:"5143");
  script_xref(name:"EDB-ID", value:"5144");
  script_xref(name:"Secunia", value:"29005");

  script_name(english:"DESlock+ < 3.2.7 Multiple Local Vulnerabilities");
  script_summary(english:"Reads version from setup.xml");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"DESlock+ is installed on the remote host. It is used for encrypting
files, folders, and emails on Windows machines.

The version of DESlock+ installed on the remote host reportedly
contains several buffer overflows in its 'DLMFDISK.sys' and
'DLMFENC.sys' kernel drivers. Using specially crafted arguments to
associated IOCTL handlers, a local user may be able to leverage these
issues to crash the affected system or to execute arbitrary code with
kernel privileges.");
 script_set_attribute(attribute:"see_also", value:"https://www.deslock.com/");
 script_set_attribute(attribute:"solution", value:"Upgrade to DESlock+ version 3.2.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/20");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Data Encryption Systems Limited\DESlock+\Client";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"strInstallDir");
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


# Read the version from setup.xml.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
xml = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\setup.xml", string:path);
NetUseDel(close:FALSE);

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
  # Read up to 10K.
  chunk = 10240;
  size = GetFileSize(handle:fh);
  if (size > 0)
  {
    if (chunk > size) chunk = size;
    data = ReadFile(handle:fh, length:chunk, offset:0);

    if (data && 'install version="v' >< data)
    {
      version = strstr(data, 'install version="v') - 'install version="v';
      version = version - strstr(version, '"/>');
      if (version !~ "^[0-9][0-9.]+[0-9]$") version = NULL;
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("3.2.7", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version v", version, " of DESlock+ is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
