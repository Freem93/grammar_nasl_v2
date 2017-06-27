#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42823);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2014/09/19 20:19:00 $");

 script_name(english:"Non-compliant Strict Transport Security (STS)");
 script_summary(english:"Checks if the web server supports STS correctly.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server implements Strict Transport Security
incorrectly.");
 script_set_attribute(attribute:"description", value:
"The remote web server implements Strict Transport Security. However,
it does not respect all the requirements of the STS draft standard.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fb3aca6");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("http_version.nasl", "sts_detect.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);

sts = get_kb_item("www/"+port+"/STS");
if (!sts) exit(0, "The web server on port "+port+" does not implement STS.");

t = get_port_transport(port);
nc = "";
if (t == ENCAPS_IP)
{
  security_note(port: port, extra:'\n' + 'The Strict-Transport-Security header must not be sent over an' + '\n' + 'unencrypted channel.');
}
else if (port == 443)
{
  report = "";

  if (ereg(pattern:"max-age *= *0($|[^0-9])", string:sts))
  {
    report += 
      '\n' +
      '\n' + 'The web server listening on port '+port+' returns an STS header line' +
      '\n' + "with a value of 0 for the 'max-age' directive :" +
      '\n' +
      '\n' + snip +
      '\n' + sts +
      '\n' + snip +
      '\n';
  }

  port2 = 80;
  if (get_port_state(port2))
  {
    r2 = http_get_cache(port:port2, item: "/", exit_on_fail: 1);
    h2 = r2 - strstr(r2, '\r\n\r\n');

    info = '';
    if (!egrep(string:h2, pattern:"^HTTP/1\.[01] 301 "))
      info += '\n' + '  - does not contain a Status-Code of 301.';
    if (!egrep(string:h2, pattern:"^Location: *https://", icase:TRUE))
      info += '\n' + '  - does not contain a Location header field.';

    if (info)
    {
      report += 
        '\n' + 'The response from the web server listening on port '+port2+' :' +
        '\n' +
        info;
      if (report_verbosity > 1)
      {
        report += 
          '\n' +
          '\n' + 'The following are the headers received :' +
          '\n' +
          '\n' + snip +
          '\n' + h2 +
          '\n' + snip +
          '\n';
      }
    }
  }

  if (report)
  {
    if (report_verbosity > 0) security_note(port:port, extra:report);
    else security_note(port);
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "web server", port);
