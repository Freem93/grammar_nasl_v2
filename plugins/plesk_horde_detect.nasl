#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66175);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/22 19:02:18 $");

  script_name(english:"Plesk Horde Detection");
  script_summary(english:"Looks for Horde on Plesk");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts an application framework written in PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is running Horde, an open source, PHP-based
application framework from The Horde Project.  This installation was
detected on a web server configured with Parallels Plesk Panel, a web
hosting control panel.  Plesk pre-configures the Horde install with a
virtual host such as 'horde.webmail.' or 'webmail.', depending on the
host operating system Plesk is installed on.  This virtual host
configuration can cause the Horde install to not be scanned by Nessus
unless the specific named host is scanned (for example,
'horde.webmail.example.com').  By not scanning the 'horde.webmail' or
'webmail.' named host, vulnerabilities within the installed version of
Horde may go undetected."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Conduct a review of the Plesk administrative panel to ensure all
applications are updated to the most up-to-date versions."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:parallels:parallels_plesk_panel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) test_hosts = make_list("webmail.");
  else test_hosts = make_list("horde.webmail.");
}
else test_hosts = make_list("horde.webmail.", "webmail.");

pat1 = 'name="imp_login"';
pat2 = 'alt="Powered by Horde"';
url = "/login.php";

report_req = NULL;
foreach test_host (test_hosts)
{
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    host   : test_host + get_host_name(),
    exit_on_fail    : TRUE,
    follow_redirect : 3
  );

  if (pat1 >< res[2] && pat2 >< res[2])
  {
    report_req = http_last_sent_request();
    break;
  }
}
if (isnull(report_req)) audit(AUDIT_WEB_APP_NOT_INST, "Plesk's default Horde install", port);


# Check if we're scanning the name-based virtual host.
res2 = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail    : TRUE,
  follow_redirect : 3
);
if (pat1 >< res2[2] && pat2 >< res2[2]) exit(0, "The Horde install configured by Plesk on port "+port+" is not affected.");

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to verify that Horde is installed with the following'+
    '\nrequest :' +
    '\n' +
    '\n' + report_req +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
