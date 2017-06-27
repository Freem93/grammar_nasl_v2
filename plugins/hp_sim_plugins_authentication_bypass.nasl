#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50563);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id("CVE-2010-3986", "CVE-2010-4100", "CVE-2010-4103");
  script_bugtraq_id(44326, 44532, 44583);
  script_osvdb_id(68825, 68945, 69180);
  script_xref(name:"TRA", value:"TRA-2010-03");
  script_xref(name:"Secunia", value:"41926");
  script_xref(name:"Secunia", value:"42000");
  script_xref(name:"Secunia", value:"42038");

  script_name(english:"HP Systems Insight Manager Multiple Products Authentication Bypass");
  script_summary(english:"Attempts to bypass authentication using HEAD requests");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that is affected by an
authentication bypass vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote host contains an HP Systems Insight Manager plugin that is
affected by an authentication bypass vulnerability.  It is possible to
access restricted pages by using a HEAD request.  A remote attacker,
exploiting this flaw, could gain unauthorized access to the affected
application.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2010-03");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02550412
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f1a6c6b");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02574359
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bb9ab2d");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02573176
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da7cfcb3");
  script_set_attribute(attribute:"solution", value:"Apply the solution from the appropriate vendor reference.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:virtual_connect_enterprise_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("hp_systems_insight_control_detect.nasl", "hp_systems_insight_dynamics_detect.nasl", "hp_systems_insight_manager_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("www/hp_insight_control", "www/hp_insight_dynamics", "www/hp_insight_manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:50000);

vuln = FALSE;
vulnerable_apps = make_list();

# First check for HP Systems Insight Manager
install = get_install_from_kb(appname:'hp_insight_manager', port:port);
if (isnull(install))
{
  # Next check for HP Insight Control
  install = get_install_from_kb(appname:'hp_insight_control', port:port);
  if (isnull(install))
  {
    # Finally, check for HP Insight Dynamics
    install = get_install_from_kb(appname:'hp_insight_dynamics', port:port);
  }
  if (isnull(install)) exit(0, "Nessus did not detect HP Systems Insight Manager, HP Insight Control, or HP Insight Dynamics on port "+port+".");
}

dir = install['dir'];

exploits = make_array(
  'HP Insight Control Performance Management', '/pmpweb/DisplayReport.jsp',
  'HP Insight Managed System Setup Wizard', '/mssw/taskresults.jsp',
  'HP Virtual Connect Enterprise Manager', '/mvcd/jsp/jobList.jsp'
);

expected_res = make_array(
  'HP Insight Control Performance Management', '23: out.println(request.getAttribute(&quot;Content&quot;).toString());',
  'HP Insight Managed System Setup Wizard', '43:     MxBean.jspInit(request, response);',
  'HP Virtual Connect Enterprise Manager', '<title>HP Virtual Connect Enterprise Manager</title>'
);

foreach app (keys(exploits))
{
  url = dir + exploits[app];
  res = http_send_recv3(method:"HEAD", item:url, version:9, port:port, exit_on_fail:TRUE);

  if (expected_res[app] >< res[2])
  {
    if (report_paranoia < 2)
    {
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
      if (expected_res[app] >< res[2]) continue;
    }

    vuln = TRUE;
    vulnerable_apps = make_list(vulnerable_apps, app);
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (max_index(vulnerable_apps) > 1) s = 's';
    else s = '';

    report =
      '\nNessus found the following vulnerable app'+s+' :\n';
    foreach app (vulnerable_apps)
    {
      report = report + '\n  - ' + app;
    }
    report += '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "No vulnerable HP applications were detected on port "+port+".");
