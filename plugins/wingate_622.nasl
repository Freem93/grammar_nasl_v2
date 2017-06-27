#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25879);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/05/04 18:02:23 $");

  script_cve_id("CVE-2007-4335");
  script_bugtraq_id(25272, 25303);
  script_osvdb_id(39535);

  script_name(english:"WinGate Invalid SMTP State Format String DoS");
  script_summary(english:"Checks version of WinGate");

 script_set_attribute(attribute:"synopsis", value:"The remote proxy is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running WinGate, a Windows application
for managing and securing Internet access.

The version of WinGate installed on the remote host fails to sanitize
user-supplied input to its SMTP server component of format strings
before using it to log a problem. By connecting to the service and
issuing commands the server was not expecting, a remote attacker may
be able to force the service to an invalid state and crash the WinGate
service itself, thereby denying service to legitimate users.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/476011/30/0/threaded");
  # http://web.archive.org/web/20080209102128/http://www.wingate.com/news.php?id=50
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?133c709d" );
 script_set_attribute(attribute:"solution", value:"Upgrade to WinGate 6.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:qbik:wingate");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Qbik Software\Key Management\Products\Wingate";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Key Folder");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinGate.exe", string:path);
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
  if (
    ver[0] == 5 ||
    (
      ver[0] == 6 &&
      (
        ver[1] < 2 ||
        (ver[1] == 2 && ver[2] < 2)
      )
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2]);
    report = string(
      "\n",
      "Version ", version, " of WinGate is installed under :\n",
      "\n",
      "  ", path
    );
    security_warning(port:port, extra:report);
  }
}
