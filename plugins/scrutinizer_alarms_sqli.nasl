#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58993);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/07 10:43:59 $");

  script_cve_id("CVE-2012-1259");
  script_bugtraq_id(52989);
  script_osvdb_id(81119);

  script_name(english:"Scrutinizer < 9.0.1 d4d/alarms.php Multiple Parameters SQLi");
  script_summary(english:"Tries to trigger a SQL error");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Scrutinizer installed on the remote web server is
affected by a SQL injection vulnerability in multiple parameters of
the 'd4d/alarms.php' script. 

An unauthenticated remote attacker can leverage this issue to
manipulate database queries, leading to disclosure of sensitive
information, attacks against the underlying database, and the like. 

Note that this install is also likely to be affected by multiple other
vulnerabilities, though Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2012-008.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Scrutinizer 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"SonicWALL Scrutinizer 9.0.1 alarms.php SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("scrutinizer_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/scrutinizer_netflow_sflow_analyzer");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'scrutinizer_netflow_sflow_analyzer', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue to generate a SQL error.
magic = SCRIPT_NAME + '-' + unixtime();
url = dir + '/d4d/alarms.php?loadAlarms=1&user_id=1&step=10\''+magic+'&page=0&search_str=test&column=msg&fa_algorithm=all&order=modified_ts';

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  'Message:</td><td><b>MySQL Query fail:</b>' >< res[2] &&
  'LIMIT 0,10\''+magic+'</td></tr>' >< res[2] &&
  '{"results":[],"totrows":"0","alarm_types":' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Scrutinizer Netflow & sFlow Analyzer', build_url(port:port, qs:install['dir']));
