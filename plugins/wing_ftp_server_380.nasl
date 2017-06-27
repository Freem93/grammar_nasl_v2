#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( description )
{
  script_id(53373);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_bugtraq_id(46754);
  script_osvdb_id(71007);
  script_xref(name:"Secunia", value:"43634");

  script_name(english:"Wing FTP Server SFTP Connection Unspecified DoS");
  script_summary(english:"Checks build date of Wing FTP and whether SFTP is enabled.");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP service is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is running a version of Wing FTP Server earlier
than 3.8.0. Such versions reportedly are affected by a denial of
service vulnerability that can be triggered when handling SFTP
connections.

A remote, unauthenticated attacker may be able to leverage this issue
to crash the service and deny access to legitimate users.");

  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/serverhistory.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/12");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:wftpserver:wing_ftp_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("wing_ftp_server_detect.nasl");
  script_require_keys("SMB/Wing_FTP/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

global_var base;

function sftp_enabled(domain, path)
{
  local_var blob, fh, length, line, matches, type;

  # Read the file.
  blob = NULL;
  fh = CreateFile(
    file:path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if ( ! isnull(fh) )
  {
    length = GetFileSize(handle:fh);
    blob = ReadFile(handle:fh, offset:0, length:length);
    CloseFile(handle:fh);
  }

  if ( isnull(blob) )
  {
    NetUseDel();
    exit(1, "Failed to open " + base + "\Data\" + domain + "\portlistener.xml.");
  }

  # Parse the list of port listeners.
  type = NULL;
  foreach line ( split(blob) )
  {
    # Start new listener.
    if ( line =~ "^\s*<Port_Listener_List>\s*$" )
    {
      type = NULL;
      continue;
    }

    # Find SFTP type.
    if ( line =~ "^\s*<Type>5</Type>\s*$" )
    {
      type = "sftp";
      continue;
    }

    # Don't parse unless we're in an SFTP listener.
    if ( isnull(type) ) continue;

    # Parse port
    matches = eregmatch(string:line, pattern:"^\s*<Port>([0-9]+)</Port>\s*$");
    if ( ! isnull(matches) ) return matches[1];
  }

  return NULL;
}

# Check if the version is vulnerable.
fixed = "3.8.0";
version = get_kb_item_or_exit("SMB/Wing_FTP/Version");
if (ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0)
  exit(0, "Wing FTP " + version + " is not affected.");

# Split the software's location into components.
base = get_kb_item_or_exit("SMB/Wing_FTP/Path");
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");

report = NULL;
if ( report_paranoia < 2 )
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
  if ( rc != 1 )
  {
    NetUseDel();
    exit(1, "Failed to connect to " + share + " share.");
  }

  # Check if any domain has SFTP enabled.
  sftp = NULL;
  dh = FindFirstFile(pattern:dir + "\Data\*");
  while ( ! isnull(dh[1]) )
  {
    # Skip non-directories.
    if ( dh[2] & FILE_ATTRIBUTE_DIRECTORY != 0 )
    {
      # Ignore non-domain directories.
      if ( dh[1] != "." && dh[1] != ".." && dh[1] != "_ADMINISTRATOR" )
      {
        sftp = sftp_enabled(domain:dh[1], path:dir + "\Data\" + dh[1] + "\portlistener.xml");
        if ( ! isnull(sftp) )
        {
          report = 'SFTP is enabled for domain ' +  dh[1] + ' on port ' + sftp + '.';
          break;
        }
      }
    }

    dh = FindNextFile(handle:dh);
  }

  # Clean up.
  NetUseDel();
}
else report = "This plugin did not check whether SFTP was enabled due to 'Report paranoia' being set to 'Paranoid'.";

if ( isnull(report) )
  exit(0, "Wing FTP version " + version + " on the remote host does not have SFTP enabled and thus is not affected.");

if ( report_verbosity > 0 )
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n' +
    '\n  ' + report +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
