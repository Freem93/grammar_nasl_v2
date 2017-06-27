#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32505);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_bugtraq_id(29466);
  script_xref(name:"EDB-ID", value:"5721");

  script_name(english:"AEC Subscription Manager Component for Mambo / Joomla! 'usage' Parameter SQLi");
  script_summary(english:"Attempts to generate a SQL error.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the AEC Subscription Manager component for Joomla! and
Mambo running on the remote host is affected by a SQL injection
vulnerability in the acctexp.class.php script due to improper
sanitization of user-supplied input to the 'usage' parameter before
using it to construct database queries. Regardless of the PHP
'magic_quotes_gpc' setting, an unauthenticated, remote attacker can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Mambo / Joomla!";

# Generate a list of paths to check.
dirs = make_list();

# - Joomla
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    dirs = make_list(dirs, dir);
  }
}

# - Mambo Open Source.
install = get_kb_item("www/" +port+ "/mambo_mos");
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs = make_list(dirs, dir);
  }
}

if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Make sure component is installed first
plugin = "AEC Subscription Manager";
new_dirs = make_list();

foreach dir (dirs)
{
  # Check KB first
  installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

  if (!installed)
  {
    checks = make_array();
    regexes = make_list();
    regexes[0] = make_list('== Subscription Plans Page ==');
    checks["/components/com_acctexp/style.css"] = regexes;

    # Ensure plugin is installed
    installed = check_webapp_ext(
      checks : checks,
      dir    : dir,
      port   : port,
      ext    : plugin
    );
    if (installed) new_dirs = make_list(new_dirs, dir);
  }
}

# Loop through each directory.
info = "";
non_affect = make_list();
vuln = FALSE;
exploit = unixtime() + " OR " + SCRIPT_NAME - ".nasl";

foreach dir (new_dirs)
{
  url = dir + "/index.php?option=com_acctexp&task=subscribe&usage=" + urlencode(str:exploit);

  r = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );
  res = r[2];

  # There's a problem if we see a SQL error involving the acctexp_plans table.
  if (
    "DB function failed" >< res &&
    "acctexp_plans WHERE active = '1' AND id=" + exploit >< res
  )
  {
    info += build_url(qs:url, port:port) + '\n';
    output = strstr(res, "acctexp_plans WHERE active");
    if (empty_or_null(output)) output = res;
    vuln = TRUE;
  }
  non_affect = make_list(non_affect, dir);
  if (!thorough_tests) break;
}

if (vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    line_limit  : 5,
    sqli        : TRUE,
    generic     : TRUE,
    request     : split(info),
    output      : chomp(output)
  );
  exit(0);
}
else
{
  installs = max_index(non_affect);
  if (installs == 0)
    exit(0, "None of the "+app+ " installs (" + join(dirs, sep:" & ") + ") on port " + port+ " contain the " + plugin+ " component.");

  else if (installs == 1)
    audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, build_url(qs:dir, port:port), plugin + " component");

  else exit(0, "None of the "+app+ " installs with the " + plugin+ " component (" + join(non_affect, sep:" & ") + ") on port " + port + " are affected.");
}
