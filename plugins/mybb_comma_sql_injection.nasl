#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21053);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2006-0959");
  script_bugtraq_id(16631);
  script_osvdb_id(23554);

  script_name(english:"MyBB 'comma' Cookie SQLi");
  script_summary(english:"Tries to generate a SQL syntax error");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by a SQL
injection vulnerability due to improper sanitization of user-supplied
input to the 'comma' cookie used by several scripts. A remote attacker
can exploit this issue to manipulate SQL queries, resulting in the
disclosure of sensitive information and modification of data.

Note that successful exploitation requires that PHP's
'register_globals' setting be enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426653/30/30/threaded");
  script_set_attribute(attribute:"solution", value:"Disable PHP's 'register_globals' setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");

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
script = SCRIPT_NAME;

# Try to exploit the flaw to generate a SQL syntax error.
r = http_send_recv3(
  method : "GET",
  item   : dir + "/showteam.php",
  port   : port,
  add_headers  : make_array("Cookie", "comma='"+script),
  exit_on_fail : TRUE
);

# There's a problem if we see a syntax error with our script name.
if (egrep(pattern:"mySQL error: 1064.+near.+" +script+ "'.+Query: SELECT u\\.\\*", string: r[2]))
{
  output = strstr(r[2], "mySQL error: 1064");
  if (empty_or_null(output)) output = r[2];

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
