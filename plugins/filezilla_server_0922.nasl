#
#  (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(23831);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/14 15:43:27 $");

  script_cve_id("CVE-2006-6564", "CVE-2006-6565");
  script_bugtraq_id(21542, 21549);
  script_osvdb_id(34435);
  script_xref(name:"EDB-ID", value:"2914");

  script_name(english:"FileZilla FTP Server < 0.9.22 Wildcard Handling Remote DoS");
  script_summary(english:"Checks version of FileZilla Server Interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that suffers from multiple
denial of service vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its version, the FileZilla Server Interface installed on
the remote host is affected by several denial of service flaws, which
could be leveraged by an authenticated attacker to crash the server
and deny service to legitimate users.");
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/filezilla_0921_dos.html");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85be86cd" );
 script_set_attribute(attribute:"solution", value:"Upgrade to FileZilla Server version 0.9.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/12");
script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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


# Get some info about the install.
key = "SOFTWARE\FileZilla Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\FileZilla Server Interface.exe", string:path);
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

  # There's a problem if the version is < 0.9.22.
  if (!isnull(ver))
  {
    if (
      ver[0] == 0 &&
      (
        ver[1] < 9 ||
        (ver[1] == 9 && ver[2] < 22)
      )
    )
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of FileZilla is installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_warning(port:port, extra:report);
    }
  }
}


# Clean up.
NetUseDel();
