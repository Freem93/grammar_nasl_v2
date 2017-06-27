#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33218);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/05/04 14:21:27 $");

  script_cve_id("CVE-2008-2822");
  script_bugtraq_id(29749);
  script_osvdb_id(46155);
  script_xref(name:"Secunia", value:"30651");

  script_name(english:"3D-FTP Multiple Directory Traversal Vulnerabilities");
  script_summary(english:"Checks for vulnerable version of 3D-FTP");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
directory traversal vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host has the 3D-FTP FTP client installed.

The installed version of 3D-FTP is affected by multiple directory
traversal vulnerabilities. By prefixing '../' to filenames in response
to 'LIST' and 'MLSD' commands, it may be possible for an attacker to
write arbitrary files outside the client's directory, subject to the
privileges of the user. An attacker can leverage this issue to write
arbitrary files (potentially containing malicious code) to client
startup directory which would then be executed when the user logs on.
In order to successfully exploit this issue, an attacker must trick a
user into downloading a specially-named file from a malicious ftp
server.");
 script_set_attribute(attribute:"see_also", value:"http://vuln.sg/3dftp801-en.html");
 script_set_attribute(attribute:"see_also", value:"http://www.3dftp.com/3dftp_versions.htm" );
 script_set_attribute(attribute:"solution", value:"Upgrade to 3D-FTP version 8.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/18");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "3D-FTP" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   break;
  }
}

if(isnull(installstring)) exit(0);

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#if (!get_port_state(port)) exit(0);

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);

if (!smb_session_init()) exit(0);


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

key = installstring;
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If 3D-FTP is installed..
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
  {
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\3dftp.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

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
  # Version of 3dftp that is not vulnerable
  fix = split("8.0.0.2", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1],".", ver[3]);
        report = string(
          "\n",
          "Version ", version, " of 3D-FTP is installed under :\n",
          "\n",
          "  ", path, "\\3dftp.exe\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
