#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54956);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_bugtraq_id(47998);
  script_osvdb_id(73260);
  script_xref(name:"Secunia", value:"44718");

  script_name(english:"Wing FTP Server LDAP Authentication Bypass");
  script_summary(english:"Checks version of Wing FTP and whether LDAP authentication is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is vulnerable to an authentication bypass
attack.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is running a version of Wing FTP Server earlier
than 3.8.7. As such, it reportedly is affected by an authentication
bypass vulnerability when LDAP or Active Directory authentication is
used.

An attacker can exploit this issue by logging into the FTP server with
an empty password. Successfully exploiting this issue requires that
the LDAP server allows anonymous binds as well as knowledge of a valid
account.");
  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/serverhistory.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.8.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:wftpserver:wing_ftp_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("wing_ftp_server_detect.nasl");
  script_require_keys("SMB/Wing_FTP/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

global_var base;

function ldap_enabled(domain, path)
{
  local_var blob, fh, length, line;

  # Read the file.
  blob = NULL;
  fh = CreateFile(
    file:path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    length = GetFileSize(handle:fh);
    blob = ReadFile(handle:fh, offset:0, length:length);
    CloseFile(handle:fh);
  }

  if (isnull(blob))
  {
    NetUseDel();
    exit(1, "Failed to open " + base + "\Data\" + domain + "\settings.xml.");
  }

  # Parse the list of port listeners.
  foreach line (split(blob))
  {
    # Check if AD is enabled.
    if (line =~ "<ADUser_Enable>1</ADUser_Enable>")
      return "Active Directory";

    # Check if LDAP is enabled.
    if (line =~ "<LDAP_Enable>1</LDAP_Enable>")
      return "LDAP";
  }

  return NULL;
}

# Check if the version is vulnerable.
ldap = "3.7.2";
fixed = "3.8.7";
version = get_kb_item_or_exit("SMB/Wing_FTP/Version");
if (ver_compare(ver:version, fix:ldap, strict:FALSE) < 0)
  exit(0, "Wing FTP " + version + " is not affected because it does not support Active Directory or LDAP authentication.");
if (ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0)
  exit(0, "Wing FTP " + version + " is not affected.");

# Split the software's location into components.
base = get_kb_item_or_exit("SMB/Wing_FTP/Path");
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");

report = NULL;
if (report_paranoia < 2)
{
  # Connect to the appropriate share.
  name    =  kb_smb_name();
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  # Try to connect to server.
  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  # Connect to the share software is installed on.
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Failed to connect to " + share + " share.");
  }

  # Check if any domain has AD/LDAP enabled.
  auth = NULL;
  dh = FindFirstFile(pattern:dir + "\Data\*");
  while (!isnull(dh[1]))
  {
    # Skip non-directories.
    if (dh[2] & FILE_ATTRIBUTE_DIRECTORY != 0)
    {
      # Ignore non-domain directories.
      if (dh[1] != "." && dh[1] != ".." && dh[1] != "_ADMINISTRATOR")
      {
        auth = ldap_enabled(domain:dh[1], path:dir + "\Data\" + dh[1] + "\settings.xml");
        if (!isnull(auth))
        {
          report = auth + " authentication is enabled for domain " +  dh[1] + ".";
          break;
        }
      }
    }

    dh = FindNextFile(handle:dh);
  }

  # Clean up.
  NetUseDel();
}
else
{
  report =
    'Note that Nessus did not check whether Active Directory or LDAP\n' +
    'authentication was enabled because of the Report Paranoia setting in\n' +
    'effect when this scan was run.';
}

if (isnull(report))
  exit(0, "Wing FTP " + version + " on the remote host does not have LDAP authentication enabled and thus is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n' +
    '\n' + report +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
