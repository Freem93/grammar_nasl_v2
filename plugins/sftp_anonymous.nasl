#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72664);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/24 17:53:58 $");

  script_name(english:"Anonymous SFTP Enabled");
  script_summary(english:"Checks if the device supports anonymous SFTP");

  script_set_attribute(attribute:"synopsis", value:"The remote SSH service supports anonymous SFTP logins.");
  script_set_attribute(attribute:"description", value:
"The remote SSH service supports anonymous SFTP logins.  A remote user
may connect and authenticate without providing unique credentials.");
  script_set_attribute(attribute:"solution", value:
"Disable anonymous SFTP if it is not required.  Routinely check the
server to ensure sensitive content is not available.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("sftp_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

logins = get_kb_list_or_exit("SSH/"+port+"/sftp/login");

report = "";
foreach login (make_list(logins))
{
  if (login == "anonymous" || login == "guest")
  {
    report += '\n  User : ' + login + '\n';
  }
}

if (report)
{
  if (report_verbosity > 0) security_note(port:port, extra:report);
  else security_note(port);
}
else exit(0, "The SSH service listening on port "+port+" does not support anonymous SFTP.");
