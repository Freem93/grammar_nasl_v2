#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44046);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_cve_id("CVE-2009-4775");
  script_bugtraq_id(36297);
  script_osvdb_id(64036);

  script_name(english:"WS_FTP Pro HTTP Server Response Format String");
  script_summary(english:"Checks version of wsftpgui.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is prone to a remote
format string attack.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Ipswitch's WS_FTP
Professional that is earlier than 12.2. Such versions are prone to a
format-string vulnerability because they fail to properly sanitize
user-supplied input before passing it as the format specifier to a
formatted-printing function.

If an attacker can trick a user into connecting to a malicious web
server using the affected application, this issue could be exploited
to execute arbitrary code subject to the user's privileges.");
   # http://docs.ipswitch.com/WS_FTP%20122/ReleaseNotes/English/index.htm?k_id=ipswitch_com_ftp_documents_worldwide_ws_ftp122releasenotesenglish
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22c765aa");
  script_set_attribute(attribute:"solution", value:"Upgrade to WS_FTP Pro for Windows version 12.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:ws_ftp");
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
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The registry wasn't enumerated.");

# Connect to the appropriate share.
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
  exit(1, "Can't connect to IPC$ share.");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Ipswitch\WS_FTP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Dir");
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
  exit(0, "WS_FTP Pro is not installed.");
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\wsftpgui.exe", string:path);
NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
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
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

  if (
    (ver[0] > 1900 && ver[0] <= 2007) ||
    ver[0] < 12 ||
    (ver[0] == 12 && ver[1] < 2)
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        '  Version : ' + version + '\n' +
        '  Path    : ' + path + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }

  exit(0, "WS_FTP Pro version "+version+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+exe+"'.");
