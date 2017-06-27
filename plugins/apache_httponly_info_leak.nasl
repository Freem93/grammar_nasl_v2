#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57792);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_cve_id("CVE-2012-0053");
  script_bugtraq_id(51706);
  script_osvdb_id(78556);
  script_xref(name:"EDB-ID", value:"18442");

  script_name(english:"Apache HTTP Server httpOnly Cookie Information Disclosure");
  script_summary(english:"Checks for default error message");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web server running on the remote host is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache HTTP Server running on the remote host is
affected by an information disclosure vulnerability. Sending a request
with HTTP headers long enough to exceed the server limit causes the
web server to respond with an HTTP 400. By default, the offending HTTP
header and value are displayed on the 400 error page. When used in
conjunction with other attacks (e.g., cross-site scripting), this
could result in the compromise of httpOnly cookies."
  );
  script_set_attribute(attribute:"see_also", value:"http://fd.the-wildcat.de/apache_e36a9cf46c.php");
  # http://web.archive.org/web/20130801230537/http://httpd.apache.org/security/vulnerabilities_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e005199a");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1235454");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache version 2.0.65 / 2.2.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this looks like Apache unless paranoid
if (report_paranoia < 2)
{
  server = http_server_header(port:port);

  if ( 'ibm_http_server' >!< tolower(server) && 'apache' >!< tolower(server) && 'oracle http server' >!< tolower(server) && 'oracle-http-server' >!< tolower(server) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like an Apache-based httpd.');

  # looks like Apache _httpd_
  if ('apache' >< tolower(server) && ( 'coyote' >< tolower(server) || 'tomcat' >< tolower(server)) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like Apache httpd.');
}


function beautify()
{
 local_var buf;
 local_var array, line;
 local_var ret;


 buf = _FCT_ANON_ARGS[0];
 array = split(buf);
 foreach line ( array )
 {
  if ( strlen(line) < 80 )
    ret = strcat(ret, line);
  else
    ret = strcat(ret, substr(line, 0, 77), '...\n');
 }
 return ret;
}

enable_cookiejar();
junk = crap(data:'A', length:1000);

for (i = 0; i < 10; i++)
  set_http_cookie(name:strcat('z', i), value:junk);

res = http_send_recv3(method:'GET', port:port, item:'/', exit_on_fail:TRUE);

if (
  'Size of a request header field exceeds server limit' >< res[2] &&
  'Cookie: ' >< res[2] &&
  junk >< res[2]
)
{
  if (report_verbosity > 0)
  {
    # cut down the size of the response
    semicolon_idx = stridx(res[2], ';');
    if (semicolon_idx == -1)
      error = res[2];
    else
      error = substr(res[2], 0, semicolon_idx);

    report =
      '\nNessus verified this by sending a request with a long Cookie header :\n\n' +
      chomp(beautify(http_last_sent_request())) +
      '\n\nWhich caused the Cookie header to be displayed in the default error page\n' +
      '(the response shown below has been truncated) :\n\n' +
      beautify(error) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The server on port ' + port + ' is not affected.');
