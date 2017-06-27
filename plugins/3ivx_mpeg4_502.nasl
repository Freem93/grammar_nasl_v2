#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29749);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:42 $");

  script_cve_id("CVE-2007-6401", "CVE-2007-6402");
  script_bugtraq_id(26773);
  script_osvdb_id(42579, 42580);

  script_name(english:"3ivx MPEG-4 < 5.0.2 Buffer Overflow");
  script_summary(english:"Checks version of 3ivxConfig.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The 3ivx MPEG-4 compression suite is installed on the remote host. It
contains an MP4 codec for use with media players such as Windows Media
Player for creating and playing back MPEG-4 / MP4 files.

The version of this codec on the remote host is affected by a buffer
overflow vulnerability. If an attacker can trick a user on the
affected host into opening a specially crafted MP4 file with a media
player that uses this codec, this issue could be leveraged to execute
arbitrary code on the affected host subject to the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484781/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484779/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.3ivx.com/pr/pr20071213_502.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to 3ivx MPEG-4 compression suite version 5.0.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

if (!smb_session_init()) exit(0);

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
current_version = NULL;
path = NULL;

key = "SOFTWARE\3ivx\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) current_version = value[1];
  RegCloseKey(handle:key_h);
}
if (!isnull(current_version))
{
  key = "SOFTWARE\3ivx\" + current_version;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Install_Dir");
    if (!isnull(value)) path = value[1] + "\" + current_version;
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the file version of 3ivxConfig.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\3ivxConfig.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("5.0.2.280", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2]);
      report = string(
        "Version ", version, " of the 3ivx MPEG-4 compression suite is installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
