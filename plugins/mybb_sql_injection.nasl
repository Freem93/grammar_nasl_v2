#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(16143);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/02/23 16:41:17 $");

  script_cve_id("CVE-2005-0282");
  script_bugtraq_id(12161);
  script_osvdb_id(12798);

  script_name(english:"MyBB member.php 'uid' Parameter SQLi");
  script_summary(english:"Checks for SQL injection vulnerability in member.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by
a SQL injection vulnerability due to improper sanitization of
user-supplied input to the avatar upload system via the 'uid'
parameter of the member.php script. If PHP's 'magic_quotes_gpc'
setting is disabled, can exploit this issue to manipulate SQL queries,
resulting in the disclosure of sensitive information and modification
of data..");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110486566600980&w=2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MyBBPreview Release 2 or later. Alternatively, enable PHP's
'magic_quotes_gpc' setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

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

# Try to exploit one of the flaws.
#
# nb: use an randomly-named table so we can generate a MySQL error.
rnd_table = "nessus" + rand_str(length:3);
postdata =
  "uid=1'%20UNION%20SELECT%2010000,200,1%20AS%20type%20FROM%20" +rnd_table+ "%20WHERE%20uid=1%20ORDER%20BY%20uid%20DESC--";

w = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/member.php?action=avatar",
  data   : postdata,
  content_type : "application/x-www-form-urlencoded",
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if we see our table name.
if (egrep(string:res, pattern:"mySQL error: 1146<br>Table '.*\\." + rnd_table))
{
  output = strstr(res, "mySQL error: 1146");
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
