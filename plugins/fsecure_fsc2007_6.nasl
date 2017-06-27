#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26193);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id("CVE-2007-5143");
  script_bugtraq_id(25824);
  script_osvdb_id(41377);

  script_name(english:"F-Secure Anti-Virus for Windows system32 Directory Crafted File Detection Bypass");
  script_summary(english:"Checks version of F-Secure Anti-Virus for Windows Servers");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application that may fail to
scan selected files.");
 script_set_attribute(attribute:"description", value:
"The remote host is running F-Secure Anti-Virus for Windows Servers.

According to its version, the installation of this software on the
remote host may allow an attacker by bypass antivirus scanning by
placing a specially crafted archive or packed executable into the
'system32' folder.

Note that this issue only affects 64-bit server platforms, which
Nessus has determined the remote host to be.");
 script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/security/fsc-2007-6.shtml");
 script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/28");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:f-secure_anti-virus");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");

# Make sure the remote is running Windows 2003.
win = get_kb_item("SMB/WindowsVersion");
if (!win || win != "5.2") exit(0);

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
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure proc architecture is amd64.
arch = NULL;

key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"PROCESSOR_ARCHITECTURE");
  if (!isnull(value)) arch = value[1];

  RegCloseKey(handle:key_h);
}
if (!arch || arch != "AMD64")
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Make sure F-Secure Anti-Virus for Windows Servers 7.00 is installed.
prod_name = NULL;
ver = NULL;

key = "SOFTWARE\Wow6432Node\Data Fellows\F-Secure\TNB\Products";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    prod = RegEnumKey(handle:key_h, index:i);
    if (strlen(prod))
    {
      key2 = key + "\" + prod;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"ProductName");
        if (!isnull(value)) prod_name = value[1];

        if (!isnull(prod_name) && "for Windows Servers" >< prod_name)
        {
          value = RegQueryValue(handle:key2_h, item:"Version");
          if (!isnull(value)) ver = value[1];
        }

        RegCloseKey(handle:key2_h);
      }
    }
    if (!isnull(prod_name) && "for Windows Servers" >< prod_name) break;
  }
  RegCloseKey(handle:key_h);
}
if (
  !prod_name || "for Windows Servers" >!< prod_name ||
  !ver || ver != "7.00"
)
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}



# Determine the installation location.
path = NULL;

key = "SOFTWARE\Wow6432Node\Data Fellows\F-Secure\Anti-Virus";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of fsgk32.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\fsgk32.exe", string:path);
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
  fix = split("7.50.13360.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_note(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
