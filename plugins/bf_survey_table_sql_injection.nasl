#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40988);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2009-4625");
  script_bugtraq_id(42969);
  script_osvdb_id(57883);
  script_xref(name:"EDB-ID", value:"9601");
  script_xref(name:"Secunia", value:"36657");

  script_name(english:"BF Survey Pro Component for Joomla! 'table' Parameter SQLi");
  script_summary(english:"Attempts to generate a SQL error.");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of BF Survey Pro or BF Survey Pro Free for Joomla! running
on the remote host is affected by a SQL injection vulnerability due to
improper sanitization of user-supplied input to the 'table' parameter
in a POST request (when 'task' is set to 'updateOnePage') before using
it to construct database queries. An unauthenticated, remote attacker
can exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, modification of data, or other
attacks against the underlying database.");
  # Information received from the author on 2009-09-17
  script_set_attribute(attribute:"see_also", value:"http://www.tamlynsoftware.com/forum/index.php?topic=357.0");
  script_set_attribute(attribute:"solution", value:
"Update to BF Survey Pro version 1.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");

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
plugin = "BF Survey Pro";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('.bfsurvey_([P|p]ro([F|f]ree)?|BasicTrial)?');
#  regexes[0] = make_list('<name>BFSurvey_([P|p]ro([F|f]ree)?|BasicTrial)?<');
  checks["/components/com_bfsurvey_profree/css/style.css"]=regexes;
  checks["/components/com_bfsurvey_pro/css/style.css"]=regexes;
  checks["/components/com_bfsurvey_basictrial/css/style.css"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

components = make_list(
  "com_bfsurvey_profree",
  "com_bfsurvey_pro",
  "com_bfsurvey_basictrial"
);

exploit = SCRIPT_NAME - ".nasl" + " SET NESSUS=" + unixtime() + " -- ";

foreach component (components)
{
  url = "/index.php?option=" + component;
  postdata = "task=updateOnePage&table=" + urlencode(str:exploit);

  res = http_send_recv3(
    method : "POST",
    port   : port,
    item   : dir + url,
    data   : postdata,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  # There's a problem if we see a SQL syntax error.
  if ("SQL=INSERT INTO " +exploit+ "( `id`" >< res[2])
  {
    output = strstr(res[2], exploit);
    if (empty_or_null(output)) output = res[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      sqli        : TRUE,
      line_limit  : 2,
      generic     : TRUE,
      request     : make_list(http_last_sent_request()),
      output      : chomp(output)
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
