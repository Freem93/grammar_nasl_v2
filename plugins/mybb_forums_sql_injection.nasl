#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21052);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/06/23 19:40:22 $");

  script_cve_id("CVE-2006-1065");
  script_osvdb_id(23784);

  script_name(english:"MyBB search.php 'forums' Parameter SQLi");
  script_summary(english:"Checks for the forums parameter SQL injection vulnerability in MyBB.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
SQL injection vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of MyBB running on the remote host is affected by a SQL
injection vulnerability due to improper sanitization of user-supplied
input to the 'forums' parameter of the search.php script. A remote
attacker can exploit this issue to manipulate SQL queries, resulting
in the disclosure of sensitive information and modification of data.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426631/30/30/threaded");
  script_set_attribute(attribute:"solution", value:
"Edit search.php and ensure 'forum' takes on only integer values as
described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/02");
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

# First we need a username.
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/index.php",
  exit_on_fail : TRUE
);
user = NULL;

pat = '<a href="member.php\\?action=profile&amp;uid=[^>]+>([^<]+)</a>';
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    user = eregmatch(pattern:pat, string:match);
    if (!empty_or_null(user))
    {
      user = user[1];
      break;
    }
  }
}

# If we have a username...
if (!empty_or_null(user))
{
  script = SCRIPT_NAME;
  url = "/search.php?action=do_search&postthread=1&author=" + user+
    "&matchusername=1&forums[]=-1'" + script;

  # Try to exploit the flaw to generate a SQL syntax error.
  w = http_send_recv3(
    method : "GET", 
    item   : dir + url,
    port   : port, 
    exit_on_fail : TRUE
  );
  res = w[2];

  # There's a problem if we see a syntax error with our script name.
  if (egrep(
    pattern:"mySQL error: 1064.+near '" + script + ",'.+Query: SELECT f\\.fid",     string:res)
  )
  {
    output = strstr(res, "mySQL error: 1064");
    if (empty_or_null(output)) output = res;

    security_report_v4(
      port       : port,
      severity   : SECURITY_WARNING,
      generic    : TRUE,
      sqli       : TRUE,  # Sets SQLInjection KB key
      request    : make_list(http_last_sent_request()),
      output     : chomp(output)
    );
    exit(0);

  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else exit(0, "Could not identify a username on the " + app + " install located at " + install_url);
