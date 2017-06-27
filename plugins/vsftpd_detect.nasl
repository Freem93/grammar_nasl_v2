#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52703);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/21 00:22:37 $");

  script_name(english:"vsftpd Detection");
  script_summary(english:"Determines the presence of vsftpd");

  script_set_attribute(attribute:"synopsis", value:
"An FTP server is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"The remote host is running vsftpd, an FTP server for UNIX-like
systems written in C.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"see_also", value:"http://vsftpd.beasts.org/");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/17");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/vsftpd");
  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1, "Failed to receive a banner from the FTP server on port "+port+".");
if ("vsFTPd " >!< banner) exit(0, "The FTP service on port "+port+" does not appear to be vsFTPd.");

version_pattern = "^[0-9][0-9][0-9] \(vsFTPd ([0-9][0-9.]+).*\)";
match = eregmatch(pattern:version_pattern, string:banner);
if (isnull(match)) exit(1, "Failed to extract a version from the FTP banner from port "+port+".");

source  = match[0];
version = match[1];

set_kb_item(name:"ftp/"+port+"/vsftpd/version_source", value:source);
set_kb_item(name:"ftp/"+port+"/vsftpd/version", value:version);

if (report_verbosity > 0)
{
  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port:port);
