#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22055);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2006-3775");
  script_bugtraq_id(18997);
  script_osvdb_id(27335);
  script_xref(name:"EDB-ID", value:"3653");

  script_name(english:"MyBB HTTP Header 'CLIENT-IP' Field SQLi");
  script_summary(english:"Checks for the CLIENT-IP SQL injection vulnerability in MyBB.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by a SQL
injection vulnerability due to improper sanitization of user-supplied
input to the 'CLIENT-IP' request header before using it in a database
query when initiating a session in the inc/class_session.php script. A
remote attacker can exploit this issue to manipulate SQL queries,
resulting in the disclosure of sensitive information and modification
of data.

Note that successful exploitation is possible regardless of PHP's
settings.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/mybb_115_sql.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/440163/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=10555" );
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB version 1.1.6 or later" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/MyBB");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Try to exploit the flaw to generate a SQL syntax error.
magic = "'" + SCRIPT_NAME + "--";

w = http_send_recv3(
  method : "GET",
  item   : dir + "/",
  port   : port,
  add_headers  : make_array("CLIENT-IP", magic),
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if we see a syntax error with our script name.
if (
  "SQL error: 1064" >< res &&
  "near " + magic + "'' at line" >< res &&
  (
    "SELECT sid,uid" >< res ||
    "WHERE ip='" >< res
  )
)
{
  output = strstr(res, "SQL error: 1064");
  if (empty_or_null(output)) output = res;

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
