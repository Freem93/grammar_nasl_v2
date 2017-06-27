#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57333);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/12/19 19:03:57 $");

  script_name(english:"NNTP Authentication Methods");
  script_summary(english:"Checks which authentication methods are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NNTP supports authentication.");
  script_set_attribute(attribute:"description", value:
"The remote NNTP server advertises that it supports authentication.");

  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3977");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4643");

  script_set_attribute(attribute:"solution", value:
"Review the list of methods and whether they're available over an
encrypted channel.");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("nntp_info.nasl", "nntp_starttls.nasl");
  script_require_ports("Services/nntp", 119);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("nntp_func.inc");

global_var methods;

function get_methods(port, starttls)
{
  local_var auth, auths, enc, encaps, i, lines, method, res, soc;

  # Connect to the NNTP server. In some implementations (e.g. Cyrus),
  # the initial banner is delayed several seconds before sending, so
  # we'll up the timeout.
  soc = open_sock_tcp(port, timeout:get_read_timeout() + 5);
  if (!soc) exit(1, "Failed to open a socket on port "+port+".");

  # Receive the banner.
  res = nntp_recv(socket:soc, code:200, exit_on_fail:TRUE);

  # Negotiate a StartTLS connection if supported.
  if (starttls)
  {
    soc = nntp_starttls(socket:soc, encaps:ENCAPS_TLSv1);
    if (!soc) return;
  }

  # Get the service's supported authentication methods.
  res = nntp_cmd(socket:soc, cmd:"AUTHINFO GENERIC", code:281, exit_on_fail:TRUE);
  close(soc);

  # Parse out the authentication methods supported, skipping the first
  # (status) and last (terminator) lines.
  auths = make_list();
  lines = split(res["body"], sep:'\r\n', keep:FALSE);
  for (i = 1; i < max_index(lines) - 1; i++)
  {
    auths = make_list(auths, lines[i]);
  }

  # Decide whether this is an encrypted connection.
  encaps = get_kb_item("Transports/TCP/" + port);
  enc = starttls || encaps != ENCAPS_IP;

  # Save the authentication methods to the KB.
  foreach auth (auths)
  {
    if (enc) set_kb_item(name:"nntp/" + port + "/auth_tls", value:auth);
    else set_kb_item(name:"nntp/" + port + "/auth", value:auth);
    methods[enc] = make_list(methods[enc], auth);
  }
}

port = get_service(svc:"nntp", default:119, exit_on_fail:TRUE);

# Create data structure to store all the authentication methods that
# this port supports.
methods = make_array();
methods[FALSE] = make_list();
methods[TRUE] = make_list();

# Enumerate all the authentication methods that the port supports,
# both before and after StartTLS.
get_methods(port:port, starttls:FALSE);
get_methods(port:port, starttls:TRUE);

report = "";
foreach key (make_list(FALSE, TRUE))
{
  if (max_index(methods[key]) == 0) continue;

  if (key) with = "with";
  else with = "without";

  report +=
    '\nThe following authentication methods are advertised by the NNTP' +
    '\nserver ' + with + ' encryption : ' +
    '\n';

  foreach method (methods[key])
    report += '  ' + method + '\n';
}

if (report == "")
  exit(1, "The NNTP server listening on port " + port + " doesn't appear to support the AUTH command.");

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
