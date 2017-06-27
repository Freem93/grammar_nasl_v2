#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20342);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/01/19 15:40:44 $");

  script_cve_id("CVE-2005-4199", "CVE-2005-4200");
  script_bugtraq_id(15793);
  script_osvdb_id(
    19031,
    21600,
    21601,
    22157,
    22158,
    59396,
    59397,
    59398
  );

  script_name(english:"MyBB calendar.php 'month' Parameter SQLi");
  script_summary(english:"Checks for a SQL injection vulnerability.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by a SQL
injection vulnerability due to improper sanitization of user-supplied
input to the 'month' parameter of the calendar.php script. A remote,
unauthenticated attacker can exploit this issue to manipulate SQL
queries, resulting in the disclosure of sensitive information and
modification of data.

Note that the application is also reportedly affected by several
additional SQL injection vulnerabilities, many of which can be
exploited even if PHP's 'register_globals' setting is disabled and the
'magic_quotes_gpc' setting is enabled. However, Nessus has not tested
for these additional issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.trapkit.de/advisories/TKADV2005-12-001.txt");
  # http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040584.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab61d0c");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=5184");
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB 1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

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

# Make sure one of the affected scripts exists.
w = http_send_recv3(
  method : "GET",
  item   : dir + "/calendar.php",
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# If it does...
if ('<form action="calendar.php" method=' >< res)
{
  postdata =
    "month=11'" + script + "&" +
    "day=11&" +
    "year=2005&" +
    "subject=NESSUS&" +
    "description=Plugin+Check&" +
    "action=do_addevent";

  w = http_send_recv3(
    method : "POST",
    item   : dir + "/calendar.php",
    port   : port,
    data   : postdata,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );
  res = w[2];

  # There's a problem if we get a syntax error involving our script name.
  if (egrep(pattern:"an error in your SQL syntax.+ near '"+script, string:res))
  {
    output = strstr(res, "an error in your SQL syntax");
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
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
